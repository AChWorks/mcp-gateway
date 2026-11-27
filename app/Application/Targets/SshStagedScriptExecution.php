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

    // Exit codes belong only to our small preparation/cleanup programs,
    // never to the user script or its guarded launcher.
    private const CONTROL_FAILURES = [
        'umask_failed' => 40,
        'interpreter_unavailable' => 41,
        'hash_unavailable' => 42,
        'directory_create_failed' => 43,
        'directory_identity_unverified' => 44,
        'witness_write_failed' => 45,
        'witness_identity_unverified' => 46,
        'cleanup_identity_unverified' => 47,
        'payload_remove_failed' => 48,
        'directory_remove_failed' => 49,
    ];

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
        $cleanupDiagnostics = [];
        $source = null;
        try {
            // Stage local bytes before making any remote directory. Do not
            // put script contents in exec argv, a command log or a shell pipe.
            $source = VerifiedTransferSpool::empty();
            if (fwrite($source, $script) !== $bytes || fseek($source, 0) !== 0) {
                throw new SshTargetConnectionException('input_unavailable');
            }
            $deadline->assertAvailable();
            $prepareSteps = [
                'umask_failed' => 'umask 077',
                'interpreter_unavailable' => 'test -f '.$program.' && test -x '.$program,
                'hash_unavailable' => 'command -v sha256sum >/dev/null 2>&1',
                'directory_create_failed' => 'mkdir -m 700 -- '.$dir,
                'directory_identity_unverified' => $privateDirectory,
                'witness_write_failed' => 'printf %s '.SshPrivateArtifactWitness::quote($witness).' > '.$marker,
                'witness_identity_unverified' => $identity,
            ];
            $prepared = $execute(
                self::controlCommand($prepareSteps),
                static function () use (&$prepareAttempted): void {
                    $prepareAttempted = true;
                },
            );
            if (! self::successful($prepared)) {
                throw new SshTargetConnectionException('script_preparation_failed', self::observation($prepared, $prepareSteps, $directory, $witness));
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
                $cleanupSteps = [
                    'cleanup_identity_unverified' => $identity,
                    'payload_remove_failed' => 'rm -f -- '.$file.' '.$marker,
                    'directory_remove_failed' => 'rmdir -- '.$dir,
                ];
                $cleanup = $execute(self::controlCommand($cleanupSteps), null);
                $clean = self::successful($cleanup);
                if (! $clean) {
                    $cleanupError = 'script_cleanup_unconfirmed';
                    $cleanupDiagnostics = self::observation($cleanup, $cleanupSteps, $directory, $witness);
                }
            } catch (Throwable $exception) {
                $cleanupError = $exception instanceof SshTargetConnectionException ? $exception->reason : 'script_cleanup_unconfirmed';
                $cleanupDiagnostics = $exception instanceof SshTargetConnectionException
                    ? $exception->diagnostics : ['exception_class' => $exception::class, 'provider_cause_unknown' => true];
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
                ...($cleanupDiagnostics === [] ? [] : ['script_cleanup_diagnostics' => $cleanupDiagnostics]),
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

    /** @param array<string,string> $steps */
    private static function controlCommand(array $steps): string
    {
        // These are Gateway-owned commands, not the user script. Disable
        // shell tracing before the private witness and use stable native
        // utility diagnostics; the user's launch environment is unchanged.
        $command = 'set +x; LC_ALL=C; export LC_ALL';
        foreach ($steps as $reason => $step) {
            $command .= '; { '.$step.'; } || exit '.self::CONTROL_FAILURES[$reason];
        }

        return $command;
    }

    /**
     * Retain actual bounded control-command evidence, never the command
     * string, witness, arbitrary login-shell output or user-script output.
     * Only recognized utility messages about our exact generated paths are
     * useful here. Unrecognized stderr is not invented into a provider cause.
     *
     * @param  array<string,mixed>  $result
     * @param  array<string,string>  $steps
     * @return array<string,mixed>
     */
    private static function observation(array $result, array $steps, string $directory, string $witness): array
    {
        $details = ['failure_origin' => 'unknown', 'failure_stage' => 'operation'];
        $exit = $result['exit_code'] ?? null;
        if (($result['status'] ?? null) !== 'completed' || ! is_int($exit)) {
            return [...$details, 'provider_cause_unknown' => true];
        }
        $details['remote_exit_code'] = $exit;
        if (($result['stderr_truncated'] ?? false) === true) {
            $details['script_control_stderr_truncated'] = true;
        }
        $reason = array_search($exit, self::CONTROL_FAILURES, true);
        if (! is_string($reason) || ! isset($steps[$reason])) {
            return [...$details, 'provider_cause_unknown' => true];
        }
        $details['script_control_failure'] = $reason;
        // Native stdout/stderr have independent capture limits. Keep only
        // relevant utility evidence whose path is owned by this operation.
        $prefixes = match ($reason) {
            'directory_create_failed' => ["mkdir: cannot create directory '".$directory."': "],
            'directory_remove_failed' => ["rmdir: failed to remove '".$directory."': "],
            'payload_remove_failed' => [
                "rm: cannot remove '".$directory."/script': ",
                "rm: cannot remove '".$directory."/identity': ",
            ],
            'directory_identity_unverified', 'witness_identity_unverified', 'cleanup_identity_unverified' => [
                "stat: cannot stat '".$directory."': ",
                "stat: cannot stat '".$directory."/identity': ",
                'cat: '.$directory.'/identity: ',
            ],
            default => [],
        };
        $stderr = $result['stderr'] ?? null;
        if ($prefixes !== [] && is_string($stderr) && ($result['stderr_encoding'] ?? null) === 'utf-8') {
            $messages = [];
            foreach (explode("\n", $stderr) as $line) {
                foreach ($prefixes as $prefix) {
                    if (str_starts_with($line, $prefix)) {
                        // A trace or shell startup line is not a native
                        // utility diagnostic. Explicitly mask our witness
                        // even in a recognized line before common redaction.
                        $messages[] = str_replace($witness, '[REDACTED]', $line);
                        break;
                    }
                }
            }
            if ($messages !== []) {
                $details['source_error_message'] = implode("\n", $messages);
                $details['source_error_message_truncated'] = ($result['stderr_truncated'] ?? false) === true;
            }
        }

        return $details;
    }
}
