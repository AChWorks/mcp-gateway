<?php

namespace Tests\Unit\Targets;

use App\Application\Targets\SshCommandExecutionDeadline;
use App\Application\Targets\SshStagedScriptExecution;
use App\Application\Targets\SshTargetConnectionException;
use App\Support\OperationDiagnostics;
use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Process\Process;
use Tests\TestCase;

final class SshStagedScriptExecutionTest extends TestCase
{
    /** @return array<string,array{string, string, bool, bool, int}> */
    public static function outcomes(): array
    {
        return [
            'complete' => ['complete', 'completed', true, true, 3],
            'lost preparation' => ['prepare_unknown', 'failed', false, false, 1],
            'unverified upload' => ['upload_unknown', 'failed', false, true, 2],
            'wrong digest' => ['wrong_hash', 'failed', false, true, 2],
            'revoked before launch' => ['revoked', 'failed', false, false, 3],
            'expired after staging' => ['expired', 'failed', false, false, 1],
            'expired after launch' => ['expired_cleanup', 'completed', true, false, 2],
            'lost launch' => ['launch_unknown', 'outcome_unknown', true, false, 2],
            'cleanup failure preserves completed result' => ['cleanup_unknown', 'completed', true, false, 3],
        ];
    }

    #[DataProvider('outcomes')]
    public function test_exact_stage_order_and_outcome_certainty(string $mode, string $status, bool $attempted, bool $clean, int $execs): void
    {
        $script = "printf 'private-".str_repeat('x', 524288)."'";
        $clock = 1_000_000_000;
        $deadline = new SshCommandExecutionDeadline(10, static function () use (&$clock): int {
            return $clock;
        });
        $calls = [];
        $uploaded = false;
        $uploadObserved = null;
        $markCallbacks = [];
        $result = (new SshStagedScriptExecution)->run($script, "/opt/Unicode's interpreter", $deadline,
            static function (string $command, ?Closure $mark) use (&$calls, &$markCallbacks, $mode, &$clock): array {
                $calls[] = $command;
                $markCallbacks[] = $mark !== null;
                if (count($calls) === 1) {
                    $mark?->__invoke();

                    return $mode === 'prepare_unknown' ? ['status' => 'outcome_unknown', 'exit_code' => null] : ['status' => 'completed', 'exit_code' => 0];
                }
                if (str_contains($command, 'then exec')) {
                    if ($mode === 'revoked') {
                        throw new SshTargetConnectionException('target_changed');
                    }
                    $mark?->__invoke();
                    if ($mode === 'expired_cleanup') {
                        $clock += 10_000_000_000;
                    }

                    return $mode === 'launch_unknown'
                        ? ['status' => 'outcome_unknown', 'exit_code' => null, 'complete' => false]
                        : ['status' => 'completed', 'exit_code' => 7, 'stdout' => 'exact', 'stderr' => 'err', 'complete' => true];
                }
                if ($mode === 'revoked') {
                    throw new SshTargetConnectionException('target_changed', [
                        'failure_origin' => 'gateway_admission', 'failure_stage' => 'admission',
                        'pre_dispatch' => true, 'source_error_code' => 'fixture_binding_changed',
                        'source_error_message' => 'Exact fixture binding changed.',
                        'password' => 'must-not-be-retained',
                    ]);
                }

                return $mode === 'cleanup_unknown' ? ['status' => 'outcome_unknown', 'exit_code' => null] : ['status' => 'completed', 'exit_code' => 0];
            },
            static function (string $directory, mixed $source, int $bytes, string $sha256, Closure $verify) use ($mode, &$uploaded, &$clock, &$uploadObserved): array {
                $uploadObserved = [$directory, is_resource($source), stream_get_contents($source), $bytes, $sha256];
                $uploaded = true;
                if ($mode === 'expired') {
                    $clock += 10_000_000_000;
                }
                if ($mode === 'upload_unknown') {
                    return ['status' => 'outcome_unknown', '__diagnostic_context' => [
                        'pre_dispatch' => true, 'provider_error_code' => 'file_unavailable',
                    ]];
                }

                return ['status' => 'completed', 'bytes_written' => $bytes,
                    'sha256' => $mode === 'wrong_hash' ? str_repeat('0', 64) : $sha256,
                    'integrity_check' => 'remote_readback_sha256'];
            },
        );

        self::assertSame($status, $result['status']);
        self::assertSame($attempted, $result['script_launch_attempted']);
        self::assertSame($clean, $result['temporary_cleanup_confirmed']);
        self::assertSame($execs, count($calls));
        self::assertSame($mode !== 'prepare_unknown', $uploaded);
        self::assertStringContainsString('mkdir -m 700', $calls[0]);
        self::assertTrue($markCallbacks[0]);
        foreach ($calls as $index => $command) {
            self::assertLessThan(8192, strlen($command), 'The script must never enter native exec argv.');
            if ($index === 0) {
                continue;
            }
            if (str_contains($command, 'then exec')) {
                self::assertStringContainsString('sha256sum', $command);
                self::assertTrue($markCallbacks[$index]);
            } else {
                self::assertFalse($markCallbacks[$index]);
                self::assertStringContainsString('rmdir --', $command);
                self::assertStringNotContainsString('rm -rf', $command);
            }
        }
        if ($uploaded) {
            self::assertMatchesRegularExpression('~\\A/var/tmp/\\.mcp-gateway-script-[a-f0-9]{32}\\z~', $uploadObserved[0]);
            self::assertSame([true, $script, strlen($script), hash('sha256', $script)], array_slice($uploadObserved, 1));
        }

        if ($status === 'completed') {
            self::assertSame(7, $result['exit_code']);
            self::assertSame('exact', $result['stdout']);
            self::assertSame('err', $result['stderr']);
        } else {
            self::assertNull($result['exit_code']);
        }
        if ($clean) {
            self::assertArrayNotHasKey('script_staging_path', $result);
        } else {
            self::assertStringStartsWith(SshStagedScriptExecution::DIRECTORY_PREFIX, $result['script_staging_path']);
        }
        $safe = OperationDiagnostics::safeContext($result['__diagnostic_context']);
        self::assertSame($attempted, $safe['script_launch_attempted']);
        self::assertSame($clean, $safe['temporary_cleanup_confirmed']);
        self::assertArrayNotHasKey('request_not_sent', $safe, 'A preparation attempt may already have had filesystem effects.');
        self::assertStringNotContainsString($script, json_encode($safe, JSON_THROW_ON_ERROR));
        if ($mode === 'revoked') {
            $cleanup = $safe['script_cleanup_diagnostics'] ?? [];
            self::assertSame('gateway_admission', $cleanup['failure_origin'] ?? null);
            self::assertSame('fixture_binding_changed', $cleanup['source_error_code'] ?? null);
            self::assertTrue($cleanup['request_not_sent'] ?? false);
            self::assertStringNotContainsString('must-not-be-retained', json_encode($cleanup, JSON_THROW_ON_ERROR));
            self::assertSame($safe, OperationDiagnostics::safeContext($safe));
        }
        if ($mode === 'expired_cleanup') {
            self::assertSame('transfer_timed_out', $result['script_cleanup_error_code']);
        }
    }

    public function test_guarded_launcher_rejects_changed_bytes_before_interpreter_can_run(): void
    {
        $script = "printf 'must-not-run'; exit 7\n";
        $directory = null;
        $calls = [];
        $result = (new SshStagedScriptExecution)->run(
            $script, '/bin/sh', new SshCommandExecutionDeadline(10),
            static function (string $command, ?Closure $mark) use (&$calls): array {
                $calls[] = $command;
                $mark?->__invoke();
                $process = new Process(['/bin/sh', '-c', $command]);
                $process->setTimeout(3);
                $process->run();

                return [
                    'status' => 'completed', 'exit_code' => $process->getExitCode(),
                    'stdout' => $process->getOutput(), 'stderr' => $process->getErrorOutput(),
                ];
            },
            static function (string $path, mixed $source, int $bytes, string $sha256, Closure $verify) use (&$directory): array {
                $directory = $path;
                $content = stream_get_contents($source);
                // Simulate an exact-size change after verified SFTP readback.
                file_put_contents($path.'/script', 'X'.substr($content, 1));
                chmod($path.'/script', 0600);

                return ['status' => 'completed', 'bytes_written' => $bytes,
                    'sha256' => $sha256, 'integrity_check' => 'remote_readback_sha256'];
            },
        );

        self::assertNotNull($directory);
        self::assertCount(3, $calls);
        self::assertSame('completed', $result['status']);
        self::assertSame(125, $result['exit_code']);
        self::assertSame('', $result['stdout']);
        self::assertStringContainsString('interpreter not invoked', $result['stderr']);
        self::assertTrue($result['script_staging_verified']);
        self::assertTrue($result['script_launch_attempted']);
        self::assertTrue($result['temporary_cleanup_confirmed']);
        self::assertDirectoryDoesNotExist($directory);
    }

    public function test_control_failures_retain_native_evidence_without_replacing_script_result(): void
    {
        $directory = null;
        $execute = static function (string $command, ?Closure $mark) use (&$directory): array {
            $mark?->__invoke();
            if (preg_match('~/var/tmp/\.mcp-gateway-script-[a-f0-9]{32}~', $command, $match) === 1) {
                $directory = $match[0];
            }
            $process = new Process(['/bin/sh', '-c', $command]);
            $process->setTimeout(3);
            $process->run();

            return ['status' => 'completed', 'exit_code' => $process->getExitCode(),
                'stdout' => $process->getOutput(), 'stderr' => $process->getErrorOutput(),
                'stderr_encoding' => 'utf-8', 'stderr_truncated' => false, 'complete' => true];
        };
        $upload = static function (string $path, mixed $source, int $bytes, string $sha256, Closure $verify): array {
            file_put_contents($path.'/script', stream_get_contents($source));
            chmod($path.'/script', 0600);

            return ['status' => 'completed', 'bytes_written' => $bytes, 'sha256' => $sha256, 'integrity_check' => 'remote_readback_sha256'];
        };
        $runner = new SshStagedScriptExecution;
        $missing = $runner->run('printf never', '/nonexistent-mcp-fixture-interpreter', new SshCommandExecutionDeadline(10), $execute, $upload);
        $script = 'touch "$(dirname "$0")/extra"; printf "private-script-output"; exit 7';
        try {
            $result = $runner->run($script, '/bin/sh', new SshCommandExecutionDeadline(10), $execute, $upload);
            self::assertSame('completed', $result['status']);
            self::assertSame(7, $result['exit_code']);
            self::assertSame('private-script-output', $result['stdout']);
            self::assertFalse($result['temporary_cleanup_confirmed']);
            self::assertSame($directory, $result['script_staging_path']);
            $safe = OperationDiagnostics::safeContext($result['__diagnostic_context']);
            self::assertSame('directory_remove_failed', $safe['script_cleanup_diagnostics']['script_control_failure'] ?? null);
            self::assertIsInt($safe['script_cleanup_diagnostics']['remote_exit_code'] ?? null);
            self::assertStringContainsString('Directory not empty', $safe['script_cleanup_diagnostics']['source_error_message'] ?? '');
            self::assertStringNotContainsString('private-script-output', json_encode($safe, JSON_THROW_ON_ERROR));
            $prepare = OperationDiagnostics::safeContext($missing['__diagnostic_context']);
            self::assertFalse($missing['script_launch_attempted']);
            self::assertSame('interpreter_unavailable', $prepare['script_control_failure'] ?? null);
        } finally {
            if (is_string($directory) && is_dir($directory)) {
                foreach (['extra', 'script', 'identity'] as $file) {
                    if (is_file($directory.'/'.$file)) {
                        unlink($directory.'/'.$file);
                    }
                }
                rmdir($directory);
            }
        }
    }

    public function test_preparation_directory_failure_keeps_only_owned_native_cause(): void
    {
        $directory = null;
        $witness = null;
        try {
            $result = (new SshStagedScriptExecution)->run('printf private-body', '/bin/sh', new SshCommandExecutionDeadline(10),
                static function (string $command, ?Closure $mark) use (&$directory, &$witness): array {
                    $mark?->__invoke();
                    self::assertSame(1, preg_match('~/var/tmp/\.mcp-gateway-script-[a-f0-9]{32}~', $command, $match));
                    $directory = $match[0];
                    self::assertSame(1, preg_match("/printf %s '([a-f0-9]{64})'/", $command, $secret));
                    $witness = $secret[1];
                    self::assertTrue(mkdir($directory, 0700), 'Disposable collision directory.');
                    $process = new Process(['/bin/sh', '-c', $command]);
                    $process->setTimeout(3);
                    $process->run();

                    return ['status' => 'completed', 'exit_code' => $process->getExitCode(),
                        'stdout' => 'private-body',
                        'stderr' => '+ printf %s '.$witness."\n".$process->getErrorOutput()."private-body\n",
                        'stderr_encoding' => 'utf-8', 'stderr_truncated' => false];
                },
                static fn () => self::fail('Failed preparation must never upload.'),
            );
            self::assertFalse($result['script_launch_attempted']);
            self::assertFalse($result['temporary_cleanup_confirmed']);
            $safe = OperationDiagnostics::safeContext($result['__diagnostic_context']);
            self::assertSame('directory_create_failed', $safe['script_control_failure'] ?? null);
            self::assertIsInt($safe['remote_exit_code'] ?? null);
            self::assertStringContainsString('File exists', $safe['source_error_message'] ?? '');
            self::assertSame($directory, $safe['script_staging_path']);
            self::assertStringNotContainsString($witness, json_encode($safe, JSON_THROW_ON_ERROR));
            self::assertStringNotContainsString('private-body', json_encode($safe, JSON_THROW_ON_ERROR));
        } finally {
            if (is_string($directory) && is_dir($directory)) {
                rmdir($directory);
            }
        }
    }
}
