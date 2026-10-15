<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/**
 * Minimal agentless retained job over the *existing* verified command/SFTP
 * transports. A launch intent is durable BEFORE any remote side effect.
 * No unknown launch is ever retried; subsequent calls only reconcile by ID.
 */
final readonly class SshJobCoordinator
{
    private const MAX_SCRIPT_BYTES = 16384;

    private const MIN_RUNTIME_SECONDS = 16;

    private const MAX_RUNTIME_SECONDS = 300;

    private const RETENTION_HOURS = 24;

    private const MAX_ACTIVE_PER_USER = 2;

    private const JOB_DIR_PREFIX = '/var/tmp/.mcp-gateway-job-';

    public function __construct(
        private AccessControl $access,
        private SshCommandRuntime $commands,
        private SshFileRuntime $files,
        private ActivityRecorder $activity,
    ) {}

    /** @return array<string,mixed> */
    public function start(
        User $user, string $targetId, string $clientHash, string $requestId,
        string $script, int $runtimeSeconds = 60,
    ): array {
        $target = $this->authorized($user, $targetId, true);
        if (strlen($clientHash) !== 64 || ! ctype_xdigit($clientHash)
            || Str::isUuid($requestId) === false
            || strlen($script) > self::MAX_SCRIPT_BYTES || trim($script) === ''
            || str_contains($script, "\0") || ! mb_check_encoding($script, 'UTF-8')
            || $runtimeSeconds < self::MIN_RUNTIME_SECONDS
            || $runtimeSeconds > self::MAX_RUNTIME_SECONDS) {
            throw new SshTargetConnectionException('invalid_input');
        }

        $binding = $this->binding($target);
        // HMAC avoids retaining a guessable hash of sensitive script contents.
        $digest = hash_hmac('sha256', $script, (string) config('app.key'));
        $identity = [
            'target_record_id' => $target->getKey(),
            'user_id' => $user->getKey(),
            'client_identity_hash' => $clientHash,
            'request_id' => $requestId,
        ];
        [$row, $created] = DB::transaction(function () use ($user, $identity, $digest, $runtimeSeconds, $binding): array {
            // Serialize simultaneous intents from one principal on the same
            // database user row, never while an SSH/network operation runs.
            User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $existing = DB::table('ssh_command_jobs')->where($identity)->first();
            if ($existing !== null) {
                if (! hash_equals((string) $existing->script_digest, $digest)
                    || (int) $existing->runtime_seconds !== $runtimeSeconds
                    || ! hash_equals((string) $existing->target_binding_hash, $binding)) {
                    throw new SshTargetConnectionException('invalid_input');
                }

                return [$existing, false];
            }
            $active = DB::table('ssh_command_jobs')->where('user_id', $user->getKey())
                // An expired unknown launch can still consume remote CPU.
                // Do not forget its admission slot merely because its
                // retention timestamp passed without reconciliation.
                ->whereIn('status', ['preparing', 'launch_unknown', 'running', 'cancel_requested'])
                ->count();
            if ($active >= self::MAX_ACTIVE_PER_USER) {
                throw new SshTargetConnectionException('rate_limited');
            }
            $id = (string) Str::ulid();
            DB::table('ssh_command_jobs')->insert([
                'id' => $id,
                ...$identity,
                'script_digest' => $digest,
                'target_binding_hash' => $binding,
                'status' => 'preparing',
                'runtime_seconds' => $runtimeSeconds,
                'expires_at' => now()->addHours(self::RETENTION_HOURS),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            return [DB::table('ssh_command_jobs')->where('id', $id)->first(), true];
        });

        if (! $created || (string) $row->status !== 'preparing'
            || ! hash_equals((string) $row->target_binding_hash, $binding)) {
            return $this->summary($row);
        }

        $id = (string) $row->id;
        $directory = $this->directory($id);
        $mode = $this->probe($user, $target);
        if ($mode === null) {
            $this->transition($id, 'preparing', 'unsupported');
            $this->record($target, 'ssh-job-start', 'failure', 'job_unsupported');

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }

        $this->transition($id, 'preparing', 'launch_unknown', ['unit_mode' => $mode]);
        // From here on, any lost SSH reply is non-retryable: the directory,
        // script or unit might already exist. Reconcile using stable job ID.
        $prepared = $this->safeCommand($user, $target,
            'umask 077; mkdir -m 700 -- '.escapeshellarg($directory).
            ' && test "$(stat -c %a -- '.escapeshellarg($directory).')" = 700'.
            ' && test "$(stat -c %u -- '.escapeshellarg($directory).')" = "$(id -u)"',
            8);
        if (! $this->successful($prepared)) {
            $this->record($target, 'ssh-job-start', 'unknown', 'outcome_unknown');

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }

        $wrapper = implode("\n", [
            '#!/bin/sh',
            'umask 077',
            '/bin/sh '.escapeshellarg($directory.'/script.sh')
                .' > '.escapeshellarg($directory.'/stdout')
                .' 2> '.escapeshellarg($directory.'/stderr'),
            'exit_status=$?',
            'printf "%s\\n" "$exit_status" > '.escapeshellarg($directory.'/exit-code'),
            'exit "$exit_status"',
            '',
        ]);
        try {
            // Each write uses the existing 16 KiB, atomically-published,
            // owner/mode-verified SFTP single-window file path.
            $scriptFile = $this->files->write($user, $target, $directory.'/script.sh',
                base64_encode($script));
            $wrapperFile = $this->files->write($user, $target, $directory.'/wrapper.sh',
                base64_encode($wrapper));
            if (($scriptFile['status'] ?? '') !== 'completed'
                || ($wrapperFile['status'] ?? '') !== 'completed') {
                throw new SshTargetConnectionException('outcome_unknown');
            }
        } catch (Throwable) {
            $this->record($target, 'ssh-job-start', 'unknown', 'outcome_unknown');

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }

        $unit = $this->unit($id);
        $launch = $this->managerEnvironment($mode).'systemd-run '.($mode === 'user' ? '--user ' : '')
            .'--unit='.escapeshellarg($unit)
            .' --property='.escapeshellarg('RuntimeMaxSec='.$runtimeSeconds)
            .' --property='.escapeshellarg('LimitFSIZE=1048576')
            .' --property='.escapeshellarg('KillMode=control-group')
            .' -- /bin/sh '.escapeshellarg($directory.'/wrapper.sh');

        $result = $this->safeCommand($user, $target, $launch, 8);
        if ($this->successful($result)) {
            $this->transition($id, 'launch_unknown', 'running');
            $this->record($target, 'ssh-job-start', 'success', null);
        } else {
            // No retries: systemd-run may have created the unit even when its
            // response was lost. Status reconciles unit/spool without relaunch.
            $this->record($target, 'ssh-job-start', 'unknown', 'outcome_unknown');
        }

        return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
    }

    /** @return array<string,mixed> */
    public function status(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        [$target, $row] = $this->existing($user, $targetId, $clientHash, $jobId, false);
        if (! in_array($row->status, ['completed', 'failed', 'canceled', 'unsupported'], true)) {
            $exit = $this->exitCode($user, $target, $jobId);
            if ($exit !== null) {
                $this->transition($jobId, (string) $row->status,
                    $exit === 0 ? 'completed' : 'failed',
                    ['exit_code' => $exit, 'terminal_reason' => 'script_exit']);
            } elseif ($row->unit_mode === 'user' || $row->unit_mode === 'system') {
                $running = $this->safeCommand($user, $target,
                    $this->managerEnvironment((string) $row->unit_mode).'systemctl '.($row->unit_mode === 'user' ? '--user ' : '')
                    .'show '.escapeshellarg($this->unit($jobId))
                    .' --property=ActiveState --property=Result --property=ExecMainCode --property=ExecMainStatus --no-pager',
                    8);
                $state = trim((string) ($running['stdout'] ?? ''));
                if ($this->successful($running)
                    && preg_match('/(?:^|\n)ActiveState=(?:active|activating)(?:\n|$)/D', $state) === 1) {
                    if ($row->status === 'launch_unknown') {
                        $this->transition($jobId, 'launch_unknown', 'running');
                    }
                } elseif ($this->successful($running)
                    && preg_match('/(?:^|\n)ActiveState=failed(?:\n|$)/D', $state) === 1
                    && preg_match('/(?:^|\n)Result=(timeout|exit-code|signal|core-dump|resources|watchdog|start-limit-hit)(?:\n|$)/D', $state, $match) === 1) {
                    // No fabricated process exit code: systemd's retained
                    // failed-unit result is authoritative for terminal failure.
                    // Omitting --collect keeps failed units inspectable until
                    // bounded post-retention cleanup, even after disconnect.
                    // The wrapper may have exited before its SFTP-readable
                    // marker became available. systemd's retained main-process
                    // exit status is authoritative only for a normal exit,
                    // never for signals, timeout or inaccessible units.
                    $systemdExit = null;
                    if ($match[1] === 'exit-code'
                        && preg_match('/(?:^|\n)ExecMainCode=1(?:\n|$)/D', $state) === 1
                        && preg_match('/(?:^|\n)ExecMainStatus=([0-9]{1,3})(?:\n|$)/D', $state, $exitMatch) === 1
                        && (int) $exitMatch[1] > 0 && (int) $exitMatch[1] <= 255) {
                        $systemdExit = (int) $exitMatch[1];
                    }
                    $this->transition($jobId, (string) $row->status, 'failed',
                        ['exit_code' => $systemdExit, 'terminal_reason' => 'systemd_'.$match[1]]);
                } elseif ($row->status === 'running') {
                    // An absent/inaccessible unit without exit evidence is
                    // NOT proof of completion or a safe re-launch.
                    $this->transition($jobId, 'running', 'launch_unknown');
                }
            }
        }

        return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first());
    }

    /** @return array<string,mixed> */
    public function output(
        User $user, string $targetId, string $clientHash, string $jobId,
        string $stream, int $offset = 0, int $length = 16384,
    ): array {
        [$target, $row] = $this->existing($user, $targetId, $clientHash, $jobId, true);
        if (! in_array($stream, ['stdout', 'stderr'], true)
            || $offset < 0 || $offset > 1048576 || $length < 1 || $length > 16384) {
            throw new SshTargetConnectionException('invalid_input');
        }
        try {
            $file = $this->files->read($user, $target,
                $this->directory($jobId).'/'.$stream, $offset, $length);
        } catch (SshTargetConnectionException $exception) {
            if ($exception->reason !== 'file_unavailable') {
                throw $exception;
            }

            // Before first output, the file may not exist. Never fabricate
            // an EOF/complete guarantee from absence of the spool.
            return [
                'job_id' => $jobId, 'stream' => $stream, 'available' => false,
                'offset' => $offset, 'encoding' => 'base64', 'data' => '',
                'complete' => false, 'status' => $row->status,
            ];
        }

        return [
            'job_id' => $jobId, 'stream' => $stream, 'available' => true,
            'offset' => $file['offset'], 'size' => $file['size'],
            'length' => $file['length'], 'encoding' => $file['encoding'],
            'data' => $file['data'], 'end_of_file' => $file['end_of_file'],
            'source_check' => $file['source_check'],
            'status' => $row->status,
        ];
    }

    /** @return array<string,mixed> */
    public function cancel(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        [$target, $row] = $this->existing($user, $targetId, $clientHash, $jobId, false);
        if (in_array($row->status, ['completed', 'failed', 'canceled', 'unsupported'], true)) {
            return $this->summary($row);
        }
        // Reconcile an already-finished unit before issuing a stop, avoiding
        // mislabeling a prior systemd failure as a cancellation.
        $reconciled = $this->status($user, $targetId, $clientHash, $jobId);
        if (in_array($reconciled['status'], ['completed', 'failed', 'canceled', 'unsupported'], true)) {
            return $reconciled;
        }
        // Status may change launch_unknown -> running or vice versa.
        // Never apply a stale expected-state condition after reconciliation.
        $row = DB::table('ssh_command_jobs')->where('id', $jobId)->first();
        if (! in_array($row->unit_mode, ['system', 'user'], true)) {
            // A unit was never confirmed available; never pretend its
            // cancellation proves any post-dispatch process was terminated.
            return $this->summary($row);
        }
        if ($row->status !== 'cancel_requested') {
            $this->transition($jobId, (string) $row->status, 'cancel_requested');
        }
        // Stopping the same unique systemd unit is idempotent; a lost stop
        // reply may safely be reconciled without starting new remote work.
        $scope = $row->unit_mode === 'user' ? '--user ' : '';
        $unit = escapeshellarg($this->unit($jobId));
        $response = $this->safeCommand($user, $target,
            $this->managerEnvironment((string) $row->unit_mode).'systemctl '.$scope.'stop '.$unit,
            8);
        if ($this->successful($response)) {
            // A successful stop request is not enough: independently inspect
            // the unit's active state and process identities. Never infer
            // cancellation solely from an absent PID or a failed query.
            $verification = $this->safeCommand($user, $target,
                $this->managerEnvironment((string) $row->unit_mode).'systemctl '.$scope.'show '.$unit
                .' --property=ActiveState --property=MainPID --property=ControlPID --no-pager',
                8);
            $state = (string) ($verification['stdout'] ?? '');
            if ($this->successful($verification)
                && preg_match('/(?:^|\\n)ActiveState=(?:inactive|failed)(?:\\n|$)/D', trim($state)) === 1
                && preg_match('/(?:^|\\n)MainPID=0(?:\\n|$)/D', trim($state)) === 1
                && preg_match('/(?:^|\\n)ControlPID=0(?:\\n|$)/D', trim($state)) === 1) {
                // The script might have exited before the stop request
                // won the race. Its durable exit marker outranks a cancel.
                $exit = $this->exitCode($user, $target, $jobId);
                $final = $exit === null ? 'canceled' : ($exit === 0 ? 'completed' : 'failed');
                $this->transition($jobId, 'cancel_requested', $final,
                    ['exit_code' => $exit, 'terminal_reason' => $exit === null ? 'canceled' : 'script_exit']);
                $this->record($target, 'ssh-job-cancel', 'success', null);

                return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first());
            }
        }
        $this->record($target, 'ssh-job-cancel', 'unknown', 'outcome_unknown');

        return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first());
    }

    /**
     * Expired completed evidence may be safely purged only while the original
     * user still has exact Target access and the remote job directory is
     * independently verified as private to the authenticated OS user.
     * Unknown or active jobs are NEVER purged automatically.
     */
    public function prune(): int
    {
        $done = 0;
        $rows = DB::table('ssh_command_jobs')
            ->where('expires_at', '<=', now())
            ->whereIn('status', ['completed', 'failed', 'canceled', 'unsupported'])
            ->orderBy('expires_at')->limit(25)->get();
        foreach ($rows as $row) {
            if ($row->status === 'unsupported') {
                // The host probe returned before any remote directory or
                // process creation. No SSH mutation is needed to prune it.
                $done += DB::table('ssh_command_jobs')->where('id', $row->id)
                    ->where('status', 'unsupported')->delete();

                continue;
            }
            $target = Target::query()->whereKey($row->target_record_id)->first();
            $user = User::query()->whereKey($row->user_id)->first();
            if (! $target instanceof Target || ! $user instanceof User) {
                continue;
            }
            try {
                $this->authorized($user, $target->target_id, false);
                if (! hash_equals((string) $row->target_binding_hash, $this->binding($target))) {
                    continue;
                }
                $directory = $this->directory((string) $row->id);
                // Remove only known files from our private, non-symlinked
                // directory. Never perform recursive deletion as remote root.
                // Unexpected artifacts prevent pruning and retain evidence.
                $clean = 'if ! test -e '.escapeshellarg($directory).'; then exit 0; fi; '
                    .'test -d '.escapeshellarg($directory)
                    .' && test ! -L '.escapeshellarg($directory)
                    .' && test "$(stat -c %a -- '.escapeshellarg($directory).')" = 700'
                    .' && test "$(stat -c %u -- '.escapeshellarg($directory).')" = "$(id -u)"'
                    .' && rm -f -- '.implode(' ', array_map(
                        static fn (string $file): string => escapeshellarg($directory.'/'.$file),
                        ['script.sh', 'wrapper.sh', 'stdout', 'stderr', 'exit-code'],
                    ))
                    .' && rmdir -- '.escapeshellarg($directory);
                $result = $this->safeCommand($user, $target, $clean, 8);
                if (! $this->successful($result)) {
                    continue;
                }
                DB::table('ssh_command_jobs')->where('id', $row->id)
                    ->where('status', $row->status)->delete();
                $done++;
            } catch (Throwable) {
                // Keep the durable job record for later Owner reconciliation.
            }
        }

        return $done;
    }

    /**
     * @return array{0:Target,1:object}
     */
    private function existing(
        User $user, string $targetId, string $clientHash, string $jobId, bool $requireFileRead,
    ): array {
        $target = $this->authorized($user, $targetId, false);
        if (strlen($jobId) !== 26 || preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/D', $jobId) !== 1
            || strlen($clientHash) !== 64 || ! ctype_xdigit($clientHash)) {
            throw new SshTargetConnectionException('target_not_found');
        }
        $row = DB::table('ssh_command_jobs')
            ->where('id', $jobId)->where('user_id', $user->getKey())
            ->where('target_record_id', $target->getKey())
            ->where('client_identity_hash', $clientHash)->first();
        // TTL only governs pruning completed evidence. Uncertain launches
        // stay inspectable until explicitly reconciled; silently expiring
        // them would discard the only safe no-replay recovery handle.
        if ($row === null || ! hash_equals((string) $row->target_binding_hash, $this->binding($target))
            || ($requireFileRead && ! $this->access->allows($user, GatewayPermission::SshFileRead, $target))) {
            throw new SshTargetConnectionException('target_not_found');
        }

        return [$target, $row];
    }

    private function authorized(User $user, string $targetId, bool $requiresFileWrite): Target
    {
        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            throw new SshTargetConnectionException('target_not_found');
        }
        $target = $this->access->scopeTargets(Target::query(), $user, GatewayPermission::SshCommandRun)
            ->where('target_id', $targetId)->where('connector_type', 'ssh_direct')->first();
        if (! $target instanceof Target || $target->getAttribute('connection_state') !== TargetConnectionState::Connected
            || ($requiresFileWrite && (! $this->access->allows($user, GatewayPermission::SshFileWrite, $target)
                || ! $this->access->allows($user, GatewayPermission::SshFileRead, $target)))) {
            throw new SshTargetConnectionException('target_not_found');
        }

        return $target;
    }

    private function binding(Target $target): string
    {
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
        if (! $config instanceof SshTargetConfig) {
            throw new SshTargetConnectionException('credential_unavailable');
        }

        return hash('sha256', implode("\0", [
            (string) $target->getKey(), $target->target_id,
            $config->host, (string) $config->port, $config->username,
            $config->auth_method, $config->pinned_host_key,
        ]));
    }

    private function probe(User $user, Target $target): ?string
    {
        $command = 'if [ "$(id -u)" = 0 ]; then command -v systemd-run >/dev/null'
            .' && test "$(cat /proc/1/comm)" = systemd && printf system; else '
            .'test "$(loginctl show-user "$(id -u)" -p Linger --value 2>/dev/null)" = yes'
            .' && command -v systemd-run >/dev/null'
            .' && '.$this->managerEnvironment('user').'systemctl --user show-environment >/dev/null 2>&1'
            .' && printf user; fi';
        $result = $this->safeCommand($user, $target, $command, 5);
        if (! $this->successful($result)) {
            return null;
        }
        $mode = trim((string) ($result['stdout'] ?? ''));

        return in_array($mode, ['user', 'system'], true) ? $mode : null;
    }

    /**
     * User managers with linger can outlive the SSH login session. Some SSH
     * servers omit XDG_RUNTIME_DIR on noninteractive exec; bind explicitly to
     * the authenticated remote numeric UID's user bus, never a supplied path.
     */
    private function managerEnvironment(string $mode): string
    {
        return $mode === 'user'
            ? 'XDG_RUNTIME_DIR="/run/user/$(id -u)" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus" '
            : '';
    }

    /** @return array<string,mixed>|null */
    private function safeCommand(User $user, Target $target, string $command, int $seconds): ?array
    {
        try {
            return $this->commands->run($user, $target, $command, $seconds);
        } catch (Throwable) {
            return null;
        }
    }

    /** @param array<string,mixed>|null $result */
    private function successful(?array $result): bool
    {
        return is_array($result)
            && ($result['status'] ?? '') === 'completed'
            && ($result['exit_code'] ?? null) === 0;
    }

    private function exitCode(User $user, Target $target, string $id): ?int
    {
        try {
            $file = $this->files->read($user, $target, $this->directory($id).'/exit-code', 0, 8);
            $value = trim((string) base64_decode((string) $file['data'], true));
            if (preg_match('/^[0-9]{1,3}$/D', $value) === 1 && (int) $value <= 255) {
                return (int) $value;
            }
        } catch (Throwable) {
            // A missing/partially-written marker is not completion evidence.
        }

        return null;
    }

    /** @param array<string,mixed> $extra */
    private function transition(string $id, string $expected, string $next, array $extra = []): void
    {
        DB::table('ssh_command_jobs')->where('id', $id)->where('status', $expected)
            ->update(['status' => $next, 'updated_at' => now(), ...$extra]);
    }

    /** @return array<string,mixed> */
    private function summary(?object $row): array
    {
        if ($row === null) {
            throw new SshTargetConnectionException('target_not_found');
        }

        return [
            'job_id' => $row->id,
            'status' => $row->status,
            'exit_code' => $row->exit_code,
            'terminal_reason' => $row->terminal_reason,
            'max_runtime_seconds' => $row->runtime_seconds,
            'expires_at' => $row->expires_at,
            'complete' => in_array($row->status, ['completed', 'failed', 'canceled'], true),
            'retry_safe' => false,
            'continuation_available' => ! in_array($row->status, ['unsupported'], true),
        ];
    }

    private function directory(string $id): string
    {
        return self::JOB_DIR_PREFIX.$id;
    }

    private function unit(string $id): string
    {
        return 'mgw-'.strtolower($id).'.service';
    }

    private function record(Target $target, string $operation, string $outcome, ?string $code): void
    {
        $this->activity->record(CorrelationId::current(), $operation, $outcome, $target, $code);
    }
}
