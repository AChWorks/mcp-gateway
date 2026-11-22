<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFilePatchService;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshOperatorProbes;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\TargetOperationGate;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use Closure;
use InvalidArgumentException;
use Throwable;

/**
 * Five focused SSH operator capabilities, all using existing command/SFTP
 * trust, Target grants, checked transports and correlated Activity.
 * No second dispatcher, SSH Batch engine or privileged CLI fallback.
 */
final readonly class SshOperatorMcpToolHandlers
{
    public function __construct(
        private AccessControl $access,
        private ActivityRecorder $activity,
        private SshCommandRuntime $commands,
        private SshFileRuntime $files,
        private SshFilePatchService $patches,
        private OperationalSettings $settings,
    ) {}

    /** @param list<string> $sections
     * @return array<string,mixed>
     */
    public function system(
        User $user, string $targetId, array $sections = [], ?string $service = null, int $timeout = 10,
    ): array {
        return $this->dispatch($user, $targetId, 'ssh-system-inspect', GatewayPermission::SshCommandRun,
            function (Target $target) use ($user, $sections, $service, $timeout): array {
                $sections = $sections === [] ? ['system', 'uptime', 'load', 'cpu', 'memory', 'storage'] : $sections;
                $script = SshOperatorProbes::systemScript($sections, $service);
                $raw = $this->command($user, $target, $script, $timeout);

                $parsed = SshOperatorProbes::parseSystem(
                    $raw['stdout_encoding'] === 'utf-8' ? $raw['stdout'] : '',
                    $raw['stdout_truncated'] || $raw['status'] !== 'completed',
                );
                $observed = $raw['status'] === 'completed'
                    && count($parsed['sections']) === count($sections) && $parsed['complete'];

                return [
                    'status' => $observed ? 'observed' : 'unknown',
                    'observed_at' => now('UTC')->toIso8601String(),
                    'target_id' => $target->target_id,
                    'probe_origin' => 'target_ssh_account',
                    ...$parsed,
                    'complete' => $observed,
                    'ssh_exit_code' => $raw['exit_code'],
                    'stderr' => $raw['stderr_encoding'] === 'utf-8' ? $raw['stderr'] : null,
                    'duration_ms' => $raw['duration_ms'],
                ];
            });
    }

    /** @return array<string,mixed> */
    public function network(
        User $user, string $targetId, string $probe, string $host, ?int $port = null,
        string $scheme = 'https', string $path = '/', ?string $dnsName = null, int $timeout = 10,
    ): array {
        return $this->dispatch($user, $targetId, 'ssh-network-diagnose', GatewayPermission::SshCommandRun,
            function (Target $target) use ($user, $probe, $host, $port, $scheme, $path, $dnsName, $timeout): array {
                $script = SshOperatorProbes::networkScript(
                    $probe, $host, $port, $scheme, $path, $dnsName, $timeout,
                );
                $raw = $this->command($user, $target, $script, $timeout);

                return [
                    ...SshOperatorProbes::parseNetwork($probe, $raw),
                    'host' => $host,
                    'port' => $port,
                    'observed_at' => now('UTC')->toIso8601String(),
                    'probe_origin' => 'target_ssh_account',
                    'duration_ms' => $raw['duration_ms'],
                ];
            });
    }

    /** @return array<string,mixed> */
    public function logs(
        User $user, string $targetId, string $source = 'journal',
        ?string $service = null, ?string $path = null,
        ?string $since = null, ?string $until = null, ?string $level = null,
        ?string $cursor = null, int $lines = 50, int $offset = 0, ?int $length = null,
        ?int $expectedSize = null, ?int $expectedMtime = null,
        int $timeout = 10,
    ): array {
        $permission = $source === 'file' ? GatewayPermission::SshFileRead : GatewayPermission::SshCommandRun;

        return $this->dispatch($user, $targetId, 'ssh-logs-query', $permission,
            function (Target $target) use (
                $user, $source, $service, $path, $since, $until, $level, $cursor,
                $lines, $offset, $length, $expectedSize, $expectedMtime, $timeout,
            ): array {
                if ($source === 'file') {
                    if ($path === null || $service !== null || $since !== null || $until !== null
                        || $level !== null || $cursor !== null) {
                        throw new InvalidArgumentException('File log mode supports SFTP path and byte-offset windows, not journal filters.');
                    }
                    $length ??= $this->settings->sshFileLimits()['read_bytes'];
                    $raw = $this->files->read($user, $target, $path, $offset, $length, $expectedSize, $expectedMtime);

                    $fileComplete = ($raw['status'] ?? null) === 'completed';

                    return [
                        'status' => $fileComplete ? 'observed' : 'unknown',
                        'source' => 'sftp_file',
                        'path' => $path,
                        'observed_at' => now('UTC')->toIso8601String(),
                        'source_timestamp_quality' => 'file_mtime_only; individual log lines unparsed',
                        'size' => $raw['size'] ?? null,
                        'mtime' => $raw['mtime'] ?? null,
                        'offset' => $offset,
                        'length' => $raw['length'] ?? null,
                        'encoding' => 'base64',
                        'data' => $raw['data'] ?? null,
                        'next_offset' => ! $fileComplete || ($raw['end_of_file'] ?? false)
                            ? null : $offset + ($raw['length'] ?? 0),
                        'end_of_file' => $raw['end_of_file'] ?? null,
                        'complete' => $raw['complete'] ?? false,
                        'consistency' => 'size_mtime_best_effort',
                    ];
                }
                if ($source !== 'journal' || $path !== null || $offset !== 0
                    || $length !== null || $expectedSize !== null || $expectedMtime !== null) {
                    throw new InvalidArgumentException('Invalid journald source/filter combination.');
                }
                // The Owner-configured SSH stdout capture bounds in-memory
                // response size independently of the requested journal page.
                $script = SshOperatorProbes::journalScript($service, $since, $until, $level, $cursor, $lines);
                $raw = $this->command($user, $target, $script, $timeout);

                return [
                    ...SshOperatorProbes::parseJournal($raw),
                    'observed_at' => now('UTC')->toIso8601String(),
                    'source_timezone' => 'UTC from journald microsecond timestamps',
                    'requested_lines' => $lines,
                    'duration_ms' => $raw['duration_ms'],
                ];
            });
    }

    /** @return array<string,mixed> */
    public function patch(
        User $user, string $targetId, string $path, string $find, string $replace,
        bool $apply = false, ?string $expectedSha256 = null,
    ): array {
        return $this->dispatch($user, $targetId, 'ssh-file-patch', GatewayPermission::SshFileRead,
            function (Target $target) use ($user, $path, $find, $replace, $apply, $expectedSha256): array {
                if ($apply && ! $this->access->allows($user, GatewayPermission::SshFileWrite, $target)) {
                    throw new SshTargetConnectionException('target_not_found');
                }

                return $this->patches->patch($user, $target, $path, $find, $replace, $apply, $expectedSha256);
            });
    }

    /** @return array<string,mixed> */
    public function verify(
        User $user, string $targetId, string $check, string $expected,
        ?string $path = null, ?string $service = null, ?string $host = null,
        ?int $port = null, string $scheme = 'https', int $timeout = 10,
        ?string $before = null,
    ): array {
        return $this->dispatch($user, $targetId, 'ssh-change-verify', GatewayPermission::SshCommandRun,
            function (Target $target) use (
                $user, $check, $expected, $path, $service, $host, $port, $scheme, $timeout, $before,
            ): array {
                if (! in_array($check, ['file_sha256', 'service_state', 'tcp_open', 'http_status'], true)) {
                    throw new InvalidArgumentException('Unsupported independent check.');
                }
                $probe = null;
                if ($check === 'file_sha256') {
                    if ($path === null || $path === '' || ! str_starts_with($path, '/') || strlen($path) > 1024
                        || preg_match('/[\x00-\x1f\x7f]/', $path) === 1
                        || preg_match('/^[a-f0-9]{64}$/D', $expected) !== 1) {
                        throw new InvalidArgumentException('SHA256 check requires an exact path and expected digest.');
                    }
                    $script = 'if ! command -v sha256sum >/dev/null 2>&1; then printf "__GW_UNSUPPORTED__\\n"; exit 127; fi; sha256sum -- '.escapeshellarg($path);
                } elseif ($check === 'service_state') {
                    if ($service === null || ! SshOperatorProbes::serviceNameValid($service)
                        || ! in_array($expected, ['active', 'inactive', 'failed', 'activating', 'deactivating'], true)) {
                        throw new InvalidArgumentException('Service check requires an exact unit and expected state.');
                    }
                    $script = 'if ! command -v systemctl >/dev/null 2>&1; then printf "__GW_UNSUPPORTED__\\n"; exit 127; fi; systemctl is-active -- '.escapeshellarg($service);
                } else {
                    if ($host === null || $port === null || $port < 1 || $port > 65535
                        || $check === 'tcp_open' && $expected !== 'open'
                        || $check === 'http_status' && (
                            preg_match('/^[1-5][0-9]{2}$/D', $expected) !== 1
                            || ! in_array($scheme, ['http', 'https'], true)
                        )) {
                        throw new InvalidArgumentException('Network verification requires an exact destination and expected observation.');
                    }
                    $probe = $check === 'tcp_open' ? 'tcp' : 'http';
                    $script = SshOperatorProbes::networkScript(
                        $probe, $host, $port, $scheme,
                        $probe === 'http' ? ($path ?? '/') : '/', null, $timeout,
                    );
                }
                $raw = $this->command($user, $target, $script, $timeout);
                $complete = $raw['status'] === 'completed' && ! $raw['stdout_truncated']
                    && ! $raw['stderr_truncated'];
                $stdout = $raw['stdout_encoding'] === 'utf-8' ? trim($raw['stdout']) : '';
                $unsupported = $complete && $raw['exit_code'] === 127
                    && str_contains($stdout, '__GW_UNSUPPORTED__');
                $observed = null;
                if ($check === 'file_sha256' && $complete && $raw['exit_code'] === 0
                    && preg_match('/^([0-9a-f]{64})[ \t][ *]/', $stdout, $matches) === 1) {
                    $observed = $matches[1];
                } elseif ($check === 'service_state' && $complete && $raw['exit_code'] !== 127) {
                    $observed = strtok($stdout, "\n");
                } elseif ($probe !== null) {
                    $network = SshOperatorProbes::parseNetwork($probe, $raw);
                    if ($probe === 'tcp' && $network['status'] === 'passed') {
                        $observed = 'open';
                    }
                    if ($probe === 'http' && $network['status'] === 'passed') {
                        $observed = (string) ($network['observed']['http_status'] ?? '');
                    }
                }
                $status = ! $complete ? 'unknown' : ($unsupported ? 'unsupported'
                    : ($observed === null || $observed === '' ? 'failed'
                        : (hash_equals($expected, $observed) ? 'passed' : 'failed')));

                return [
                    'status' => $status,
                    'check' => $check,
                    'expected' => $expected,
                    'observed' => $observed,
                    'before_observed' => $before,
                    'observed_at' => now('UTC')->toIso8601String(),
                    'probe_origin' => 'independent_target_ssh_exec',
                    'source' => match ($check) {
                        'file_sha256' => 'sha256sum', 'service_state' => 'systemctl',
                        'tcp_open' => 'netcat', default => 'curl',
                    },
                    'complete' => $complete,
                    'exit_code' => $raw['exit_code'],
                    'stderr' => $raw['stderr_encoding'] === 'utf-8' ? $raw['stderr'] : null,
                    'duration_ms' => $raw['duration_ms'],
                    'next_step' => $status === 'unknown'
                        ? 'The observation is incomplete; inspect the host before retrying any effectful action.'
                        : ($status === 'failed' ? 'Inspect the reported evidence and service/route state; reload acceptance alone is not health proof.' : null),
                ];
            });
    }

    /** @return array<string,mixed> */
    private function command(User $user, Target $target, string $script, int $timeout): array
    {
        return $this->commands->run($user, $target, $script, $timeout);
    }

    /** @param Closure(Target):array<string,mixed> $operation
     * @return array<string,mixed>
     */
    private function dispatch(
        User $user, string $targetId, string $name, GatewayPermission $permission, Closure $operation,
    ): array {
        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            return $this->failed($name, null, 'target_not_found');
        }
        $target = $this->access->scopeTargets(Target::query(), $user, $permission)
            ->where('target_id', $targetId)->where('connector_type', 'ssh_direct')->first();
        if (! $target instanceof Target) {
            return $this->failed($name, null, 'target_not_found');
        }
        if (TargetOperationGate::isPaused($target)) {
            return $this->failed($name, $target, 'target_paused');
        }
        try {
            $result = $operation($target);
        } catch (InvalidArgumentException $exception) {
            return $this->failed($name, $target, 'invalid_input', [
                'failure_stage' => 'input_validation', 'message' => $exception->getMessage(),
            ]);
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($name, $target, $exception->reason, $exception->diagnostics);
        } catch (Throwable $exception) {
            return $this->failed($name, $target, 'operator_probe_unavailable', [
                'failure_origin' => 'gateway',
                'failure_stage' => 'operation',
                'exception_class' => $exception::class,
            ]);
        }
        $status = $result['status'] ?? 'unknown';
        $unknown = in_array($status, ['unknown', 'outcome_unknown'], true);
        // All Tool envelopes must agree with their source observation:
        // a failed or unsupported journal query is not a successful Tool
        // invocation or successful Activity, even when the remote exec ends.
        $checkFailed = in_array($status, ['failed', 'unsupported'], true);
        $failureCode = $status === 'unsupported' ? 'probe_unsupported'
            : ($name === 'ssh-change-verify' ? 'check_failed' : 'probe_failed');
        $reference = CorrelationId::current();
        $details = is_array($result['__diagnostic_context'] ?? null)
            ? $result['__diagnostic_context'] : [];
        unset($result['__diagnostic_context']);
        $this->activity->record($reference, $name, $unknown ? 'unknown' : ($checkFailed ? 'failure' : 'success'),
            $target, $unknown ? 'outcome_unknown' : ($checkFailed ? $failureCode : null), $unknown ? [
                'failure_origin' => 'remote_observation',
                'failure_stage' => 'operation',
                'effect_unconfirmed' => $name === 'ssh-file-patch',
                'retry_safe' => false,
                ...$details,
            ] : []);

        return [
            'ok' => ! $unknown && ! $checkFailed,
            'target_id' => $target->target_id,
            'diagnostic_reference' => $reference,
            'result' => $result,
            ...($checkFailed ? ['error' => [
                'code' => $failureCode,
                'message' => 'Remote observation failed or is unsupported; inspect the returned source and exit evidence.',
                'diagnostic_reference' => $reference,
            ]] : []),
            ...($unknown ? ['error' => [
                'code' => 'outcome_unknown',
                'message' => 'The remote outcome or observation is not confirmed.',
                'next_step' => OperationDiagnostics::nextStep('outcome_unknown'),
                'diagnostic_reference' => $reference,
            ]] : []),
        ];
    }

    /** @param array<string,mixed> $diagnostics
     * @return array<string,mixed>
     */
    private function failed(string $name, ?Target $target, string $code, array $diagnostics = []): array
    {
        $reference = CorrelationId::current();
        $this->activity->record($reference, $name, 'failure', $target, $code, [
            'failure_stage' => $diagnostics['failure_stage'] ?? 'operator_operation',
            ...$diagnostics,
        ]);

        return [
            'ok' => false,
            'error' => [
                'code' => $code,
                'message' => match ($code) {
                    'target_not_found' => 'SSH Target or required permission is unavailable.',
                    'target_paused' => 'SSH Target operations are paused.',
                    'source_changed' => 'Remote file changed since the approved baseline; preview again.',
                    'patch_match_not_unique' => 'The requested text must occur exactly once in the current file.',
                    'owner_preservation_unsupported' => 'SFTP cannot preserve the original owner/group; the destination was not published.',
                    'mode_preservation_unsupported' => 'SFTP cannot preserve all original file mode bits; the destination was not published.',
                    'invalid_input' => $diagnostics['message'] ?? 'Invalid operator parameters.',
                    default => 'SSH operator operation failed at '.$code.'.',
                },
                'next_step' => OperationDiagnostics::nextStep($code),
                ...(($diagnostics['publication_attempted'] ?? null) === false
                    ? ['publication_attempted' => false] : []),
                ...(is_bool($diagnostics['temporary_cleanup_confirmed'] ?? null)
                    ? ['temporary_cleanup_confirmed' => $diagnostics['temporary_cleanup_confirmed']] : []),
                ...($target instanceof Target ? ['diagnostic_reference' => $reference] : []),
            ],
        ];
    }
}
