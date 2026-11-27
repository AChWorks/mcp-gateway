<?php

namespace App\Application\Targets;

use App\Application\Files\VerifiedTransferSpool;
use Closure;
use Throwable;

/**
 * Explicit synchronous script delivery, not native exec splitting or a Job.
 * The caller owns one admitted exact SSH binding and overall deadline.
 */
final class SshStagedScriptExecution
{
    public const DIRECTORY_PREFIX = '/var/tmp/.mcp-gateway-script-';

    public static function validInterpreter(string $path): bool
    {
        return str_starts_with($path, '/') && strlen($path) <= 1024
            && mb_check_encoding($path, 'UTF-8')
            && preg_match('/[\x00-\x1f\x7f]/', $path) !== 1;
    }

    /**
     * @param  Closure(string, ?Closure):array<string,mixed>  $execute  Exact pinned native exec, marking only the send attempt.
     * @param  Closure(string, resource, int, string, Closure):array<string,mixed>  $upload  Verified private SFTP stream.
     * @return array<string,mixed>
     */
    public function run(string $script, string $interpreter, SshCommandExecutionDeadline $deadline, Closure $execute, Closure $upload): array
    {
        $started = hrtime(true);
        $directory = self::DIRECTORY_PREFIX.bin2hex(random_bytes(16));
        $witness = bin2hex(random_bytes(32));
        $dir = SshPrivateArtifactWitness::quote($directory);
        $file = SshPrivateArtifactWitness::quote($directory.'/script');
        $marker = SshPrivateArtifactWitness::quote($directory.'/identity');
        $program = SshPrivateArtifactWitness::quote($interpreter);
        $bytes = strlen($script);
        $sha256 = hash('sha256', $script);
        $artifact = new SshPrivateArtifactWitness($directory, 'identity', $witness, 'script_staging_identity_unverified');
        $privateDirectory = $artifact->directoryCheck();
        $identity = $artifact->shellCheck();

        $prepareAttempted = false;
        $created = false;
        $verified = false;
        $launchAttempted = false;
        $stage = 'prepare';
        $diagnostics = [];
        $cleanupError = null;
        $source = null;
        try {
            // Stage local bytes before making any remote directory. Do not
            // put script contents in exec argv, a command log or a shell pipe.
            $source = VerifiedTransferSpool::empty();
            if (fwrite($source, $script) !== $bytes || fseek($source, 0) !== 0) {
                throw new SshTargetConnectionException('input_unavailable');
            }
            $deadline->assertAvailable();
            $prepared = $execute(
                'umask 077; test -f '.$program.' && test -x '.$program
                .' && command -v sha256sum >/dev/null 2>&1'
                .' && mkdir -m 700 -- '.$dir.' && '.$privateDirectory
                .' && printf %s '.SshPrivateArtifactWitness::quote($witness).' > '.$marker.' && '.$identity,
                static function () use (&$prepareAttempted): void {
                    $prepareAttempted = true;
                },
            );
            if (! self::successful($prepared)) {
                throw new SshTargetConnectionException('script_preparation_failed', self::observation($prepared));
            }
            $created = true;
            $stage = 'upload';
            $deadline->assertAvailable();
            $staged = $upload($directory, $source, $bytes, $sha256, $artifact->sftpVerifier());
            if (($staged['status'] ?? null) !== 'completed'
                || ($staged['bytes_written'] ?? null) !== $bytes
                || ($staged['sha256'] ?? null) !== $sha256
                || ($staged['integrity_check'] ?? null) !== 'remote_readback_sha256') {
                $details = $staged['__diagnostic_context'] ?? [];
                throw new SshTargetConnectionException('script_staging_failed', is_array($details) ? $details : []);
            }
            $verified = true;
            $stage = 'launch';
            $deadline->assertAvailable();
            // Readback was verified by SFTP. Check the exact bytes again in
            // the exec filesystem namespace immediately before interpreter
            // invocation (SFTP chroots/aliases need not share that view).
            // The native exit belongs to this guarded launcher; a nonzero
            // validation/exec failure is not proof of interpreter execution.
            $check = $identity.' && test -f '.$file.' && test ! -L '.$file
                .' && test "$(stat -c %a -- '.$file.')" = 600'
                .' && test "$(stat -c %u -- '.$file.')" = "$(id -u)"'
                .' && test "$(stat -c %s -- '.$file.')" = '.SshPrivateArtifactWitness::quote((string) $bytes)
                .' && test "$(sha256sum -- '.$file.')" = '.SshPrivateArtifactWitness::quote($sha256.'  '.$directory.'/script');
            $result = $execute(
                'if '.$check.'; then exec '.$program.' '.$file
                .'; else printf "%s\n" "Gateway staged script integrity check failed; interpreter not invoked." >&2; exit 125; fi',
                static function () use (&$launchAttempted): void {
                    $launchAttempted = true;
                },
            );
        } catch (Throwable $exception) {
            // Preserve the real typed refusal. An unexpected local exception
            // is not remote evidence; after the send boundary it is unknown.
            $code = $exception instanceof SshTargetConnectionException ? $exception->reason : 'operation_unconfirmed';
            $diagnostics = $exception instanceof SshTargetConnectionException
                ? $exception->diagnostics : ['exception_class' => $exception::class, 'provider_cause_unknown' => true];
            $result = [
                'status' => $launchAttempted ? 'outcome_unknown' : 'failed',
                'complete' => false,
                'exit_code' => null,
                'error_code' => $launchAttempted ? 'outcome_unknown' : $code,
            ];
        } finally {
            if (is_resource($source)) {
                fclose($source);
            }
        }

        $clean = ! $prepareAttempted;
        if ($created && (! $launchAttempted || ($result['status'] ?? null) === 'completed')) {
            try {
                $deadline->assertAvailable();
                // Only exact known files; no recursive delete, glob, fresh
                // authority or cleanup of a possibly running interpreter.
                $cleanup = $execute($identity.' && rm -f -- '.$file.' '.$marker
                    .' && rmdir -- '.$dir, null);
                $clean = self::successful($cleanup);
                if (! $clean) {
                    $cleanupError = 'script_cleanup_unconfirmed';
                }
            } catch (Throwable $exception) {
                $cleanupError = $exception instanceof SshTargetConnectionException ? $exception->reason : 'script_cleanup_unconfirmed';
            }
        }
        if (! $clean && $cleanupError === null) {
            $cleanupError = 'script_cleanup_unconfirmed';
        }

        // Underlying SFTP/transport diagnostics can describe one unsent
        // stage, never the entire compound operation after mkdir.
        unset($diagnostics['pre_dispatch'], $diagnostics['request_not_sent'], $diagnostics['retry_safe'], $diagnostics['effect_unconfirmed']);
        if (! $prepareAttempted) {
            $diagnostics['request_not_sent'] = true;
        }
        $evidence = [
            'script_stage' => $stage,
            'script_launch_attempted' => $launchAttempted,
            'script_staging_verified' => $verified,
            'temporary_cleanup_confirmed' => $clean,
            ...($clean ? [] : [
                'script_staging_path' => $directory,
                'script_cleanup_error_code' => $cleanupError,
            ]),
        ];

        return [
            ...$result,
            ...$evidence,
            'script_bytes' => $bytes,
            'duration_ms' => (int) round((hrtime(true) - $started) / 1_000_000),
            '__diagnostic_context' => [
                ...$diagnostics, ...$evidence,
                'retry_safe' => false,
                'effect_unconfirmed' => ($result['status'] ?? null) === 'outcome_unknown' || ! $clean,
            ],
        ];
    }

    /** @param array<string,mixed> $result */
    private static function successful(array $result): bool
    {
        return ($result['status'] ?? null) === 'completed' && ($result['exit_code'] ?? null) === 0;
    }

    /** @param array<string,mixed> $result
     * @return array<string,mixed>
     */
    private static function observation(array $result): array
    {
        return [
            'failure_origin' => 'unknown',
            'failure_stage' => 'operation',
            ...is_int($result['exit_code'] ?? null) ? ['remote_exit_code' => $result['exit_code']] : ['provider_cause_unknown' => true],
        ];
    }
}
