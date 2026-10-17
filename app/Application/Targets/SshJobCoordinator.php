<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Application\Files\VerifiedTransferSpool;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use phpseclib4\Exception\FileSystemException;
use Throwable;

/**
 * Minimal agentless retained job over the *existing* verified command/SFTP
 * transports. A launch intent is durable BEFORE any remote side effect.
 * No unknown launch is ever retried; subsequent calls only reconcile by ID.
 */
final readonly class SshJobCoordinator
{
    private const MAX_SCRIPT_BYTES = 65536;

    private const MAX_OUTPUT_BYTES = 1048576;

    private const MAX_INLINE_SCRIPT_BYTES = 16384;

    private const MIN_RUNTIME_SECONDS = 16;

    // The start path can include a bounded SSH command, two independent
    // 55-second SFTP operations and the final systemd-run command. Cover
    // conservative command-admission/transport overhead as well, not just
    // RuntimeMaxSec. A late start whose lease actually expired is NOT sent.
    private const STAGING_RESERVE_SECONDS = 360;

    private const DISPATCH_RESERVE_SECONDS = 90;

    private const LEGACY_PREPARING_GRACE_SECONDS = 600;

    private const LEGACY_RECONCILE_GRACE_SECONDS = 3600;

    private const JOB_DIR_PREFIX = '/var/tmp/.mcp-gateway-job-';

    public function __construct(
        private AccessControl $access,
        private SshCommandRuntime $commands,
        private SshFileRuntime $files,
        private ActivityRecorder $activity,
        private OperationalSettings $settings,
    ) {}

    /** @return array<string,mixed> */
    public function start(
        User $user, string $targetId, string $clientHash, string $requestId,
        string $script, int $runtimeSeconds = 60,
    ): array {
        $target = $this->authorized($user, $targetId, true);
        $policy = $this->settings->sshJobLimits();
        $scriptBytes = strlen($script);
        if (strlen($clientHash) !== 64 || ! ctype_xdigit($clientHash)
            || Str::isUuid($requestId) === false
            || $scriptBytes > self::MAX_SCRIPT_BYTES || trim($script) === ''
            || str_contains($script, "\0") || ! mb_check_encoding($script, 'UTF-8')
            || $runtimeSeconds < self::MIN_RUNTIME_SECONDS || $runtimeSeconds > 604800) {
            throw new SshTargetConnectionException('invalid_input');
        }

        $original = $this->originalIdentity($target);
        $binding = $original['target_binding_hash'];
        $original['original_user_id'] = $user->getKey();
        // HMAC avoids retaining a guessable hash of sensitive script contents.
        $digest = hash_hmac('sha256', $script, (string) config('app.key'));
        $identity = [
            'target_record_id' => $target->getKey(),
            'user_id' => $user->getKey(),
            'client_identity_hash' => $clientHash,
            'request_id' => $requestId,
        ];
        [$row, $created] = DB::transaction(function () use ($user, $identity, $original, $digest, $runtimeSeconds, $binding, $policy, $scriptBytes): array {
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
            if ($scriptBytes > $policy['max_script_bytes']
                || $runtimeSeconds > $policy['max_runtime_seconds']) {
                throw new SshTargetConnectionException('invalid_input');
            }
            // A crash before the durable launch_unknown fence can never have
            // dispatched work. Recover only this pre-side-effect state. The
            // in-flight probe is fenced by a conditional transition below.
            $this->recoverStalePreparing((int) $user->getKey());
            $active = DB::table('ssh_command_jobs')->where('user_id', $user->getKey())
                ->whereIn('status', ['preparing', 'launch_unknown', 'running', 'cancel_requested'])
                ->where(static function ($query): void {
                    $query->where('admission_expires_at', '>', now())
                        ->orWhereNull('admission_expires_at');
                })->count();
            if ($active >= $policy['max_active_per_user']) {
                throw new SshTargetConnectionException('rate_limited');
            }
            $id = (string) Str::ulid();
            $stamp = now();
            DB::table('ssh_command_jobs')->insert([
                'id' => $id,
                ...$identity,
                'script_digest' => $digest,
                ...$original,
                'status' => 'preparing',
                'runtime_seconds' => $runtimeSeconds,
                // Freeze the Owner policy for this individual Job. A later
                // settings update may affect new Jobs, but cannot shorten
                // an already-started Job's predispatch/reconciliation period.
                'preparing_expires_at' => $stamp->copy()->addSeconds($policy['preparing_grace_seconds']),
                'reconcile_grace_seconds' => $policy['reconcile_grace_seconds'],
                // This is an admission lease, NOT confirmation that a remote
                // process stopped or permission to replay/erase evidence.
                'admission_expires_at' => $stamp->copy()->addSeconds(
                    $policy['preparing_grace_seconds'] + $runtimeSeconds + $policy['reconcile_grace_seconds']),
                'expires_at' => $stamp->copy()->addHours($policy['retention_hours']),
                'created_at' => $stamp,
                'updated_at' => $stamp,
            ]);

            return [DB::table('ssh_command_jobs')->where('id', $id)->first(), true];
        });

        if (! $created || (string) $row->status !== 'preparing'
            || ! hash_equals((string) $row->target_binding_hash, $binding)) {
            return $this->summary($row);
        }

        $id = (string) $row->id;
        $directory = $this->directory($id);
        $mode = $this->probe($user, $target, $binding);
        if ($mode === null) {
            if ($this->transition($id, 'preparing', 'unsupported') === false) {
                return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
            }
            $this->record($target, 'ssh-job-start', 'failure', 'job_unsupported');

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }

        if ($this->transition($id, 'preparing', 'launch_unknown', ['unit_mode' => $mode]) === false) {
            // Stale pre-dispatch intent was retired by another request/cron.
            // NEVER dispatch after losing the conditional prelaunch fence.
            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }
        // From here on, any lost SSH reply is non-retryable: the directory,
        // script or unit might already exist. Reconcile using stable job ID.
        $prepared = $this->safeCommand($user, $target,
            'umask 077; mkdir -m 700 -- '.escapeshellarg($directory).
            ' && test "$(stat -c %a -- '.escapeshellarg($directory).')" = 700'.
            ' && test "$(stat -c %u -- '.escapeshellarg($directory).')" = "$(id -u)"',
            8, $binding);
        if (! $this->successful($prepared)) {
            $this->record($target, 'ssh-job-start', 'unknown', 'outcome_unknown');

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }

        // The detached script may legitimately write large files (e.g. package
        // installation). Bound only its stdout/stderr spools: systemd
        // LimitFSIZE would apply to ALL descendants and break those writes.
        $wrapper = implode("\n", [
            '#!/bin/sh',
            'umask 077',
            'limit='.self::MAX_OUTPUT_BYTES,
            'stdout_pipe='.escapeshellarg($directory.'/stdout.pipe'),
            'stderr_pipe='.escapeshellarg($directory.'/stderr.pipe'),
            'stdout_file='.escapeshellarg($directory.'/stdout'),
            'stderr_file='.escapeshellarg($directory.'/stderr'),
            'stdout_marker='.escapeshellarg($directory.'/stdout.truncated'),
            'stderr_marker='.escapeshellarg($directory.'/stderr.truncated'),
            'exit_file='.escapeshellarg($directory.'/exit-code'),
            'if ! mkfifo -m 600 -- "$stdout_pipe" "$stderr_pipe"; then',
            '  printf "125\\n" > "$exit_file"',
            '  exit 125',
            'fi',
            // Keep each FIFO open across head and wc: exceeding the capture
            // ceiling drains, rather than SIGPIPE-ing the installer.
            '(',
            '  head -c "$limit" || exit 125',
            '  overflow=$(wc -c) || exit 125',
            '  if [ "$overflow" -gt 0 ]; then : > "$stdout_marker" || exit 125; fi',
            ') < "$stdout_pipe" > "$stdout_file" &',
            'stdout_reader=$!',
            '(',
            '  head -c "$limit" || exit 125',
            '  overflow=$(wc -c) || exit 125',
            '  if [ "$overflow" -gt 0 ]; then : > "$stderr_marker" || exit 125; fi',
            ') < "$stderr_pipe" > "$stderr_file" &',
            'stderr_reader=$!',
            '/bin/sh '.escapeshellarg($directory.'/script.sh').' > "$stdout_pipe" 2> "$stderr_pipe"',
            'exit_status=$?',
            'wait "$stdout_reader"; stdout_capture=$?',
            'wait "$stderr_reader"; stderr_capture=$?',
            'if [ "$stdout_capture" -ne 0 ] || [ "$stderr_capture" -ne 0 ]; then exit_status=125; fi',
            'rm -f -- "$stdout_pipe" "$stderr_pipe" || exit_status=125',
            'printf "%s\\n" "$exit_status" > "$exit_file"',
            'exit "$exit_status"',
            '',
        ]);
        try {
            if ($scriptBytes <= self::MAX_INLINE_SCRIPT_BYTES) {
                // Preserve the existing 16 KiB safe path for ordinary Jobs.
                $scriptFile = $this->files->write($user, $target, $directory.'/script.sh',
                    base64_encode($script), expectedTargetBinding: $binding);
            } else {
                // Reuse verified whole-file SFTP streaming within the already
                // private 0700 Job directory. Never put a large script into
                // an OS command, weaken per-call file-tool limits, or dispatch
                // until the remote read-back digest and exclusive publication
                // are confirmed under the original pinned Target binding.
                $source = VerifiedTransferSpool::empty();
                try {
                    if (fwrite($source, $script) !== $scriptBytes || fseek($source, 0) !== 0) {
                        throw new SshTargetConnectionException('input_unavailable');
                    }
                    $scriptFile = $this->files->uploadFromStream(
                        $user, $target, $directory.'/script.sh', $source,
                        $scriptBytes, hash('sha256', $script),
                        $policy['max_script_bytes'], 40, $directory,
                        expectedTargetBinding: $binding,
                    );
                } finally {
                    fclose($source);
                }
            }
            if (($scriptFile['status'] ?? '') !== 'completed') {
                // No wrapper/launch after an uncertain file stage. Retain any
                // observed native SFTP evidence from the in-process result.
                throw new SshTargetConnectionException('outcome_unknown',
                    is_array($scriptFile['__diagnostic_context'] ?? null)
                        ? $scriptFile['__diagnostic_context'] : []);
            }
            $wrapperFile = $this->files->write($user, $target, $directory.'/wrapper.sh',
                base64_encode($wrapper), expectedTargetBinding: $binding);
            if (($wrapperFile['status'] ?? '') !== 'completed') {
                throw new SshTargetConnectionException('outcome_unknown',
                    is_array($wrapperFile['__diagnostic_context'] ?? null)
                        ? $wrapperFile['__diagnostic_context'] : []);
            }
        } catch (Throwable $exception) {
            $this->record($target, 'ssh-job-start', 'unknown', 'outcome_unknown',
                $exception instanceof SshTargetConnectionException ? $exception->diagnostics : []);

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }

        $unit = $this->unit($id);
        $launch = $this->managerEnvironment($mode).'systemd-run '.($mode === 'user' ? '--user ' : '')
            .'--unit='.escapeshellarg($unit)
            .' --property='.escapeshellarg('RuntimeMaxSec='.$runtimeSeconds)
            .' --property='.escapeshellarg('KillMode=control-group')
            .' -- /bin/sh '.escapeshellarg($directory.'/wrapper.sh');

        // Extend the protected window immediately before the only operation
        // that can actually launch the systemd Job. If an unexpectedly stalled
        // staging pipeline has already let its prior lease expire, never
        // dispatch late: another Job may have taken that admission slot.
        if (! $this->reserveDispatchLease($id)) {
            $this->record($target, 'ssh-job-start', 'unknown', 'outcome_unknown');

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $id)->first());
        }

        $result = $this->safeCommand($user, $target, $launch, 8, $binding);
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
        if ($row->status === 'preparing') {
            // No remote side effect can precede the launch_unknown CAS.
            // Do not contact the remote host or misreport a pending probe.
            $this->recoverStalePreparing((int) $user->getKey(), $jobId);

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first());
        }
        if ($row->status === 'failed' && $row->exit_code === null
            && $row->terminal_reason === 'systemd_exit-code') {
            // systemd may report the failed exit before the bounded SFTP
            // read is admitted (e.g. transient per-Target SFTP rate limit).
            // Never freeze a null exit code: retry ONLY reading the exact
            // existing marker. This does not redispatch/restart the script.
            $recoveredExit = $this->exitCode($user, $target, $jobId, (string) $row->target_binding_hash);
            if ($recoveredExit !== null) {
                DB::table('ssh_command_jobs')->where('id', $jobId)
                    ->where('status', 'failed')->whereNull('exit_code')
                    ->update(['exit_code' => $recoveredExit,
                        'terminal_reason' => 'script_exit', 'updated_at' => now()]);
            }
        } elseif (! in_array($row->status, ['completed', 'failed', 'canceled', 'unsupported', 'retired'], true)) {
            $exit = $this->exitCode($user, $target, $jobId, (string) $row->target_binding_hash);
            if ($exit !== null) {
                $this->transition($jobId, (string) $row->status,
                    $exit === 0 ? 'completed' : 'failed',
                    ['exit_code' => $exit, 'terminal_reason' => 'script_exit']);
            } elseif ($row->unit_mode === 'user' || $row->unit_mode === 'system') {
                $running = $this->safeCommand($user, $target,
                    $this->managerEnvironment((string) $row->unit_mode).'systemctl '.($row->unit_mode === 'user' ? '--user ' : '')
                    .'show '.escapeshellarg($this->unit($jobId))
                    .' --property=ActiveState --property=Result --property=ExecMainCode --property=ExecMainStatus --no-pager',
                    8, (string) $row->target_binding_hash);
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
        // An operator-attested retired spool was independently destroyed;
        // do not seek files under that retired handle.
        if ($row->status === 'retired') {
            throw new SshTargetConnectionException('job_unavailable');
        }
        if (! in_array($stream, ['stdout', 'stderr'], true)
            || $offset < 0 || $offset > self::MAX_OUTPUT_BYTES || $length < 1 || $length > 16384) {
            throw new SshTargetConnectionException('invalid_input');
        }
        try {
            $file = $this->files->read($user, $target,
                $this->directory($jobId).'/'.$stream, $offset, $length,
                expectedTargetBinding: (string) $row->target_binding_hash);
        } catch (SshTargetConnectionException $exception) {
            if (! $this->isMissingJobOutput($exception)) {
                // A provider permission failure, lost transport, or unknown
                // cause is NOT evidence of a not-yet-created output spool.
                // Retain the observed source status for Activity/AI/Admin.
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

        // The overflow marker proves dropped bytes, even for a canceled Job.
        // A short SFTP spool at EOF does NOT prove both FIFO readers finished.
        // The wrapper writes exit-code only after waiting for both readers,
        // and converts any reader failure to 125. A legitimate overflow
        // always fills the 1 MiB spool: do not make a needless, rate-limited
        // second SFTP call for ordinary small outputs.
        $overflowConfirmed = false;
        if (($file['end_of_file'] ?? false) === true
            && (int) $file['size'] >= self::MAX_OUTPUT_BYTES
            && in_array($row->status, ['completed', 'failed', 'canceled'], true)) {
            try {
                // Keep the marker probe bound to the original Job Target.
                $this->files->read($user, $target,
                    $this->directory($jobId).'/'.$stream.'.truncated',
                    0, 1, expectedTargetBinding: (string) $row->target_binding_hash);
                $overflowConfirmed = true;
            } catch (SshTargetConnectionException $exception) {
                if (! $this->isMissingJobOutput($exception)) {
                    throw $exception;
                }
            }
        }
        $truncated = $this->captureTruncation(
            $row, (int) $file['size'], ($file['end_of_file'] ?? false) === true,
            $overflowConfirmed,
        );

        return [
            'job_id' => $jobId, 'stream' => $stream, 'available' => true,
            'offset' => $file['offset'], 'size' => $file['size'],
            'length' => $file['length'], 'encoding' => $file['encoding'],
            'data' => $file['data'], 'end_of_file' => $file['end_of_file'],
            'truncated' => $truncated,
            'source_check' => $file['source_check'],
            'status' => $row->status,
        ];
    }

    /**
     * Tristate result about capture loss, not whether the script succeeded.
     * A durable script_exit with a non-125 exit code proves the wrapper waited
     * for BOTH readers; 125 is reserved for a collector failure too, so do
     * not infer completeness from it. systemd terminal status or cancellation
     * without this proof remains indeterminate, even for a short spool.
     */
    private function captureTruncation(
        object $row, int $fileSize, bool $endOfFile, bool $overflowConfirmed,
    ): ?bool {
        if (! $endOfFile || ! in_array($row->status, ['completed', 'failed', 'canceled'], true)) {
            return null;
        }
        if ($overflowConfirmed) {
            return true;
        }
        if ($fileSize >= self::MAX_OUTPUT_BYTES
            || ! in_array($row->status, ['completed', 'failed'], true)
            || $row->terminal_reason !== 'script_exit'
            || $row->exit_code === null
            || (int) $row->exit_code === 125) {
            return null;
        }

        return false;
    }

    /** Only native SFTP missing-path replies justify an unavailable spool. */
    private function isMissingJobOutput(SshTargetConnectionException $exception): bool
    {
        return $exception->reason === 'file_unavailable'
            && ($exception->diagnostics['exception_class'] ?? null) === FileSystemException::class
            && in_array($exception->diagnostics['source_error_code'] ?? null, [2, 10], true);
    }

    /** @return array<string,mixed> */
    public function cancel(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        [$target, $row] = $this->existing($user, $targetId, $clientHash, $jobId, false);
        if (in_array($row->status, ['completed', 'failed', 'canceled', 'unsupported', 'retired'], true)) {
            return $this->summary($row);
        }
        // Reconcile an already-finished unit before issuing a stop, avoiding
        // mislabeling a prior systemd failure as a cancellation.
        $reconciled = $this->status($user, $targetId, $clientHash, $jobId);
        if (in_array($reconciled['status'], ['completed', 'failed', 'canceled', 'unsupported', 'retired'], true)) {
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
            8, (string) $row->target_binding_hash);
        if ($this->successful($response)) {
            // A successful stop request is not enough: independently inspect
            // the unit's active state and process identities. Never infer
            // cancellation solely from an absent PID or a failed query.
            $verification = $this->safeCommand($user, $target,
                $this->managerEnvironment((string) $row->unit_mode).'systemctl '.$scope.'show '.$unit
                .' --property=ActiveState --property=MainPID --property=ControlPID --no-pager',
                8, (string) $row->target_binding_hash);
            $state = (string) ($verification['stdout'] ?? '');
            if ($this->successful($verification)
                && preg_match('/(?:^|\\n)ActiveState=(?:inactive|failed)(?:\\n|$)/D', trim($state)) === 1
                && preg_match('/(?:^|\\n)MainPID=0(?:\\n|$)/D', trim($state)) === 1
                && preg_match('/(?:^|\\n)ControlPID=0(?:\\n|$)/D', trim($state)) === 1) {
                // The script might have exited before the stop request
                // won the race. Its durable exit marker outranks a cancel.
                $exit = $this->exitCode($user, $target, $jobId, (string) $row->target_binding_hash);
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
     * Local trusted deployment-operator escape hatch for unresolved/orphaned
     * metadata. The operator MUST independently verify the original systemd
     * unit has stopped and the ORIGINAL remote spool was removed. This
     * method never SSHes a possibly rebound Target, retries or replays.
     * Expired admission alone NEVER authorizes attestation.
     *
     * @return array<string,mixed>
     */
    public function operatorRetire(string $jobId, string $expectedBinding, string $reason): array
    {
        if (preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/D', $jobId) !== 1
            || preg_match('/^[a-f0-9]{64}$/D', $expectedBinding) !== 1
            || strlen($reason) < 12 || strlen($reason) > 240
            || preg_match('/[\x00-\x1f\x7f]/', $reason) === 1) {
            throw new SshTargetConnectionException('invalid_input');
        }

        $before = null;
        $result = DB::transaction(function () use ($jobId, $expectedBinding, $reason, &$before): array {
            $row = DB::table('ssh_command_jobs')->where('id', $jobId)->lockForUpdate()->first();
            if ($row === null || ! hash_equals((string) $row->target_binding_hash, $expectedBinding)) {
                throw new SshTargetConnectionException('target_not_found');
            }
            if ($row->status === 'retired') {
                return $this->summary($row);
            }
            if (! in_array($row->status, ['completed', 'failed', 'canceled', 'unsupported'], true)
                && ($row->admission_expires_at === null || $row->admission_expires_at > now()->toDateTimeString())) {
                // A late first dispatch could still be underway; the
                // operator cannot retire/reassign its slot during the lease.
                throw new SshTargetConnectionException('job_admission_active');
            }

            $before = ['status' => $row->status, 'reason' => $row->terminal_reason];
            $stamp = now();
            DB::table('ssh_command_jobs')->where('id', $jobId)->where('status', $row->status)->update([
                'status' => 'retired',
                'terminal_reason' => 'operator_attested_cleanup',
                'operator_attested_at' => $stamp,
                'operator_attested_reason' => $reason,
                'operator_attested_uid' => function_exists('posix_geteuid') ? posix_geteuid() : null,
                'expires_at' => $stamp->copy()->addHours($this->settings->sshJobLimits()['retention_hours']),
                'updated_at' => $stamp,
            ]);

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first());
        });
        if ($before !== null) {
            Log::warning('Deployment operator attested original remote SSH Job cleanup.', [
                'job_id' => $jobId,
                'previous_status' => $before['status'],
                'previous_terminal_reason' => $before['reason'],
                'actor_uid' => function_exists('posix_geteuid') ? posix_geteuid() : null,
            ]);
        }

        return $result;
    }

    /**
     * Expired completed evidence may be safely purged only while the original
     * user still has exact Target access and the remote job directory is
     * independently verified as private to the authenticated OS user.
     * Unknown or active jobs are NEVER purged automatically.
     */
    public function prune(): int
    {
        // All users, bounded by one indexed status/time update. Preparing is
        // the only state known to be free of remote side effects.
        $this->recoverStalePreparing();
        $done = 0;
        $rows = DB::table('ssh_command_jobs')
            ->where('expires_at', '<=', now())
            ->whereIn('status', ['completed', 'failed', 'canceled', 'unsupported', 'retired'])
            ->orderBy('expires_at')->limit(25)->get();
        foreach ($rows as $row) {
            if ($row->status === 'unsupported' || $row->status === 'retired'
                || ($row->status === 'failed' && $row->terminal_reason === 'pre_dispatch_abandoned')) {
                // No remote effects for unsupported/pre-dispatch; 'retired'
                // requires an explicit operator attestation that the original
                // remote unit AND spool have been independently cleaned.
                $done += DB::table('ssh_command_jobs')->where('id', $row->id)
                    ->where('status', $row->status)->delete();

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
                        ['script.sh', 'wrapper.sh', 'stdout', 'stderr', 'exit-code',
                            'stdout.pipe', 'stderr.pipe', 'stdout.truncated', 'stderr.truncated'],
                    ))
                    .' && rmdir -- '.escapeshellarg($directory);
                $result = $this->safeCommand($user, $target, $clean, 8, (string) $row->target_binding_hash);
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
        // Resolve the caller-visible Target without revealing pause state.
        // Job ownership/client/binding and current read permissions must
        // be verified before a paused Target is reported or audited.
        $target = $this->authorized($user, $targetId, false, checkPause: false);
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

        if (TargetOperationGate::isPaused($target)) {
            // This rejection belongs to a verified Job principal/client
            // binding, never an attacker-supplied or unrelated Job handle.
            throw new SshTargetConnectionException('target_paused');
        }

        return [$target, $row];
    }

    private function authorized(
        User $user, string $targetId, bool $requiresFileWrite, bool $checkPause = true,
    ): Target {
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
        if ($checkPause && TargetOperationGate::isPaused($target)) {
            throw new SshTargetConnectionException('target_paused');
        }

        return $target;
    }

    private function binding(Target $target): string
    {
        return $this->originalIdentity($target)['target_binding_hash'];
    }

    /**
     * Identity captured before initial admission, not looked up later from
     * mutable Target pointers. These non-secret immutable snapshots allow a
     * local operator to identify the ORIGINAL host after FK nullOnDelete or
     * credential/binding rotation. They do not authorize new SSH access.
     *
     * @return array<string, int|string>
     */
    private function originalIdentity(Target $target): array
    {
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
        if (! $config instanceof SshTargetConfig) {
            throw new SshTargetConnectionException('credential_unavailable');
        }

        return [
            'target_binding_hash' => SshTargetBinding::hash($target, $config),
            'original_target_record_id' => (string) $target->getKey(),
            'original_target_id' => (string) $target->target_id,
            'original_host' => (string) $config->host,
            'original_port' => (int) $config->port,
            'original_os_username' => (string) $config->username,
            'original_auth_method' => (string) $config->auth_method,
            'original_host_key_digest' => hash('sha256', (string) $config->pinned_host_key),
        ];
    }

    private function probe(User $user, Target $target, string $expectedTargetBinding): ?string
    {
        $command = 'command -v mkfifo >/dev/null && command -v head >/dev/null'
            .' && command -v wc >/dev/null && command -v rm >/dev/null'
            .' && if [ "$(id -u)" = 0 ]; then command -v systemd-run >/dev/null'
            .' && test "$(cat /proc/1/comm)" = systemd && printf system; else '
            .'test "$(loginctl show-user "$(id -u)" -p Linger --value 2>/dev/null)" = yes'
            .' && command -v systemd-run >/dev/null'
            .' && '.$this->managerEnvironment('user').'systemctl --user show-environment >/dev/null 2>&1'
            .' && printf user; fi';
        $result = $this->safeCommand($user, $target, $command, 5, $expectedTargetBinding);
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
    private function safeCommand(
        User $user, Target $target, string $command, int $seconds, ?string $expectedTargetBinding = null,
    ): ?array {
        try {
            return $this->commands->run($user, $target, $command, $seconds, $expectedTargetBinding);
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

    private function exitCode(User $user, Target $target, string $id, string $expectedTargetBinding): ?int
    {
        try {
            $file = $this->files->read($user, $target, $this->directory($id).'/exit-code', 0, 8,
                expectedTargetBinding: $expectedTargetBinding);
            $value = trim((string) base64_decode((string) $file['data'], true));
            if (preg_match('/^[0-9]{1,3}$/D', $value) === 1 && (int) $value <= 255) {
                return (int) $value;
            }
        } catch (Throwable) {
            // A missing/partially-written marker is not completion evidence.
        }

        return null;
    }

    /**
     * Freeze a conservative staging+dispatch+runtime+reconciliation budget
     * under the exact preparing -> launch_unknown fence, before ANY remote
     * side effect. The CAS and deadline check prevent a crashed/late probe
     * from reviving a released admission slot.
     *
     * @param  array<string,mixed>  $extra
     */
    private function transition(string $id, string $expected, string $next, array $extra = []): bool
    {
        if ($expected === 'preparing' && $next === 'launch_unknown') {
            return DB::transaction(function () use ($id, $next, $extra): bool {
                // This transition also extends admission at its old lease
                // boundary. Serialize with start()/dispatch renewal in the
                // same principal -> job lock order, never the reverse.
                $identity = DB::table('ssh_command_jobs')->where('id', $id)->first(['user_id']);
                if ($identity === null || $identity->user_id === null) {
                    return false;
                }
                $principal = User::query()->whereKey($identity->user_id)->lockForUpdate()->first();
                if (! $principal instanceof User || ! (bool) $principal->access_enabled) {
                    return false;
                }
                $row = DB::table('ssh_command_jobs')->where('id', $id)->lockForUpdate()->first();
                $stamp = now();
                if ($row === null || (string) $row->user_id !== (string) $principal->getKey()
                    || (string) $row->original_user_id !== (string) $principal->getKey()
                    || $row->status !== 'preparing'
                    || $row->preparing_expires_at === null
                    || $row->preparing_expires_at <= $stamp->toDateTimeString()
                    || $row->admission_expires_at === null
                    || $row->admission_expires_at <= $stamp->toDateTimeString()) {
                    return false;
                }

                $protected = $stamp->copy()->addSeconds(
                    self::STAGING_RESERVE_SECONDS + self::DISPATCH_RESERVE_SECONDS
                    + (int) $row->runtime_seconds
                    + (int) ($row->reconcile_grace_seconds ?? self::LEGACY_RECONCILE_GRACE_SECONDS),
                );
                // Never shorten a more conservative existing deadline.
                $deadline = max($row->admission_expires_at, $protected->toDateTimeString());

                return DB::table('ssh_command_jobs')->where('id', $id)
                    ->where('status', 'preparing')
                    ->where('preparing_expires_at', '>', $stamp)
                    ->where('admission_expires_at', '>', $stamp)
                    ->update([
                        'status' => $next,
                        'updated_at' => $stamp,
                        ...$extra,
                        'admission_expires_at' => $deadline,
                    ]) === 1;
            });
        }

        $query = DB::table('ssh_command_jobs')->where('id', $id)->where('status', $expected);
        if (in_array($next, ['completed', 'failed', 'canceled', 'unsupported', 'retired'], true)) {
            $extra['expires_at'] = now()->addHours($this->settings->sshJobLimits()['retention_hours']);
        }

        return $query->update(['status' => $next, 'updated_at' => now(), ...$extra]) === 1;
    }

    /**
     * Re-fence the lease directly before possibly effectful systemd-run.
     * The dispatch command has its own 90-second command-admission window,
     * followed by the ORIGINAL Job runtime and reconciliation grace. Never
     * re-read mutable Owner settings, shorten a lease, or revive an expired
     * admission after another Job might have been allowed to start.
     */
    private function reserveDispatchLease(string $id): bool
    {
        return DB::transaction(function () use ($id): bool {
            // Serialize with start() on the SAME principal, in user -> job
            // lock order. The preliminary lookup is only an immutable
            // routing hint; re-check it with both rows locked.
            $identity = DB::table('ssh_command_jobs')->where('id', $id)->first(['user_id']);
            if ($identity === null || $identity->user_id === null) {
                return false;
            }
            $principal = User::query()->whereKey($identity->user_id)->lockForUpdate()->first();
            if (! $principal instanceof User || ! (bool) $principal->access_enabled) {
                return false;
            }
            $row = DB::table('ssh_command_jobs')->where('id', $id)->lockForUpdate()->first();
            $stamp = now();
            if ($row === null || (string) $row->user_id !== (string) $principal->getKey()
                || (string) $row->original_user_id !== (string) $principal->getKey()
                || $row->status !== 'launch_unknown'
                || $row->admission_expires_at === null
                || $row->admission_expires_at <= $stamp->toDateTimeString()) {
                return false;
            }

            $protected = $stamp->copy()->addSeconds(
                self::DISPATCH_RESERVE_SECONDS + (int) $row->runtime_seconds
                + (int) ($row->reconcile_grace_seconds ?? self::LEGACY_RECONCILE_GRACE_SECONDS),
            );
            $deadline = max($row->admission_expires_at, $protected->toDateTimeString());
            if ($deadline === $row->admission_expires_at) {
                return true;
            }

            return DB::table('ssh_command_jobs')->where('id', $id)
                ->where('status', 'launch_unknown')
                ->where('admission_expires_at', '>', $stamp)
                ->update(['admission_expires_at' => $deadline, 'updated_at' => $stamp]) === 1;
        });
    }

    /**
     * Preparing is BEFORE the side-effect fence. Retire only when the
     * immutable per-Job deadline is past. This single conditional update is
     * race-safe against the prelaunch CAS and works on SQLite and MariaDB.
     */
    private function recoverStalePreparing(?int $userId = null, ?string $jobId = null): int
    {
        $stamp = now();
        $query = DB::table('ssh_command_jobs')->where('status', 'preparing')
            ->where(static function ($q) use ($stamp): void {
                $q->where('preparing_expires_at', '<=', $stamp)
                    ->orWhere(static function ($legacy) use ($stamp): void {
                        // NULL can occur only on an older partial/migrating
                        // prerelease row. Use the maximum grace, never a new
                        // Owner setting which could retire it too early.
                        $legacy->whereNull('preparing_expires_at')
                            ->where('created_at', '<=',
                                $stamp->copy()->subSeconds(self::LEGACY_PREPARING_GRACE_SECONDS));
                    });
            });
        if ($userId !== null) {
            $query->where('user_id', $userId);
        }
        if ($jobId !== null) {
            $query->where('id', $jobId);
        }

        return $query->update([
            'status' => 'failed',
            'terminal_reason' => 'pre_dispatch_abandoned',
            'expires_at' => $stamp->copy()->addHours($this->settings->sshJobLimits()['retention_hours']),
            'updated_at' => $stamp,
        ]);
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
            'continuation_available' => ! in_array($row->status, ['unsupported', 'retired'], true),
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

    /** @param array<string,mixed> $observed */
    private function record(
        Target $target, string $operation, string $outcome, ?string $code, array $observed = [],
    ): void {
        $this->activity->record(CorrelationId::current(), $operation, $outcome, $target, $code, [
            ...($outcome === 'unknown' ? [
                'failure_origin' => 'unknown',
                'failure_stage' => 'operation',
                'effect_unconfirmed' => true,
                'retry_safe' => false,
            ] : ($code === 'job_unsupported' ? [
                'failure_origin' => 'unknown',
                'failure_stage' => 'connection_setup',
                'provider_cause_unknown' => true,
                'gateway_error_message' => 'Job manager preflight could not confirm support; network or host capability may be unavailable.',
            ] : [])),
            ...$observed,
        ]);
    }
}
