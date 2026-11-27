<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Application\Access\OperationAdmission;
use App\Application\Files\VerifiedTransferSpool;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\CurrentReadTransaction;
use App\Support\OperationDiagnostics;
use Closure;
use Illuminate\Support\Facades\Crypt;
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
    private const MAX_SCRIPT_BYTES = 524288;

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
        private OperationAdmission $operationAdmission,
    ) {}

    /** @return array<string,mixed> */
    public function start(
        User $user, string $targetId, string $clientHash, string $requestId,
        string $script, int $runtimeSeconds = 60,
    ): array {
        $target = $this->authorized($user, $targetId, false, checkPause: false, requireConnected: false);
        $policy = $this->settings->sshJobLimits();
        $scriptBytes = strlen($script);
        if (strlen($clientHash) !== 64 || ! ctype_xdigit($clientHash)
            || Str::isUuid($requestId) === false
            || $scriptBytes > self::MAX_SCRIPT_BYTES || trim($script) === ''
            || str_contains($script, "\0") || ! mb_check_encoding($script, 'UTF-8')
            || $runtimeSeconds < self::MIN_RUNTIME_SECONDS || $runtimeSeconds > 604800) {
            throw new SshTargetConnectionException('invalid_input');
        }

        // Recover the exact already recorded intent before requiring a live
        // route, file-write authority or the current launch policy.
        $digest = hash_hmac('sha256', $script, (string) config('app.key'));
        $identity = [
            'target_record_id' => $target->getKey(),
            'user_id' => $user->getKey(),
            'client_identity_hash' => $clientHash,
            'request_id' => $requestId,
        ];
        $existing = DB::table('ssh_command_jobs')->where($identity)->first();
        if ($existing !== null) {
            return $this->recoverStart($existing, $digest, $runtimeSeconds);
        }
        $target = $this->authorized($user, $targetId, true);
        if ((string) $target->getKey() !== (string) $identity['target_record_id']) {
            throw new SshTargetConnectionException('target_changed');
        }
        $original = $this->originalIdentity($target);
        $binding = $original['target_binding_hash'];
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())
            ->where('connector_type', 'ssh_direct')->where('purpose', SshTargetVault::PURPOSE)->first();
        if (! $credential instanceof TargetCredential) {
            throw new SshTargetConnectionException('credential_unavailable');
        }
        $credentialDispatch = $credential->dispatchFingerprint();
        $original['original_user_id'] = $user->getKey();
        [$row, $created] = CurrentReadTransaction::run(function () use ($user, $targetId, $identity, $original, $digest, $runtimeSeconds, $policy, $scriptBytes): array {
            // Serialize simultaneous intents from one principal on the same
            // database user row, never while an SSH/network operation runs.
            User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $current = $this->authorized($user, $targetId, false, checkPause: false, requireConnected: false);
            if ((string) $current->getKey() !== (string) $identity['target_record_id']) {
                throw new SshTargetConnectionException('target_changed');
            }
            $existing = DB::table('ssh_command_jobs')->where($identity)->first();
            if ($existing !== null) {
                $this->recoverStart($existing, $digest, $runtimeSeconds);

                return [$existing, false];
            }
            $this->authorized($user, $targetId, true);
            if ($scriptBytes > $policy['max_script_bytes']
                || $runtimeSeconds > $policy['max_runtime_seconds']) {
                throw new SshTargetConnectionException('invalid_input');
            }
            // A crash before the durable launch_unknown fence can never have
            // dispatched work. Recover only this pre-side-effect state. The
            // in-flight probe is fenced by a conditional transition below.
            $this->recoverStalePreparing((int) $user->getKey());
            $this->recoverStaleUnlaunched((int) $user->getKey());
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
                'launch_admitted' => false,
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

        if (! $created || (string) $row->status !== 'preparing') {
            return $this->summary($row);
        }

        $id = (string) $row->id;
        $directory = $this->directory($id);
        $admission = new SshJobLaunchAdmission($this->access, $id, (int) $user->getKey(), (string) $target->getKey());
        $probe = [];
        $mode = $this->probe($user, $target, $binding, $credentialDispatch, $admission->stage('probe'), $probe);
        if ($mode === null) {
            return $this->settleLaunch($target, $id, 'probe', $probe);
        }

        if ($this->transition($id, 'preparing', 'launch_unknown', ['unit_mode' => $mode]) === false) {
            // A successful capability observation does not renew an expired
            // or retired intent. Preserve it separately from launch authority.
            $current = DB::table('ssh_command_jobs')->where('id', $id)->first();
            $expired = $current !== null && $current->status === 'preparing'
                && ($current->preparing_expires_at === null || now()->gte($current->preparing_expires_at)
                    || $current->admission_expires_at === null || now()->gte($current->admission_expires_at));

            return $this->settleLaunch($target, $id, 'probe', [
                ...$probe, 'error_code' => $expired ? 'dispatch_lease_expired' : 'job_attempt_retired',
                'diagnostics' => [
                    'failure_origin' => 'gateway_admission', 'failure_stage' => 'admission',
                ],
            ]);
        }
        // From here on, any lost SSH reply is non-retryable: the directory,
        // script or unit might already exist. Reconcile using stable job ID.
        $prepared = $this->safeCommand($user, $target,
            'umask 077; mkdir -m 700 -- '.escapeshellarg($directory).
            ' && test "$(stat -c %a -- '.escapeshellarg($directory).')" = 700'.
            ' && test "$(stat -c %u -- '.escapeshellarg($directory).')" = "$(id -u)"'
            .' && printf %s '.escapeshellarg(SshJobRemoteIdentity::witness($id, $original['original_peer_fingerprint']))
            .' > '.escapeshellarg($directory.'/'.SshJobRemoteIdentity::MARKER),
            8, $binding, $credentialDispatch, $admission->stage('staging'));
        if (! $this->successful($prepared)) {
            return $this->settleLaunch($target, $id, 'staging_directory', $prepared);
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
                    base64_encode($script), expectedTargetBinding: $binding, expectedCredentialDispatch: $credentialDispatch,
                    admitRemoteEffect: $admission->stage('staging'));
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
                        expectedTargetBinding: $binding, expectedCredentialDispatch: $credentialDispatch,
                        admitRemoteEffect: $admission->stage('staging'),
                    );
                } finally {
                    fclose($source);
                }
            }
            if (($scriptFile['status'] ?? '') !== 'completed') {
                // No wrapper/launch after an uncertain file stage. Retain any
                // observed native SFTP evidence from the in-process result.
                $diagnostics = is_array($scriptFile['__diagnostic_context'] ?? null)
                    ? $scriptFile['__diagnostic_context'] : [];
                throw new SshTargetConnectionException($diagnostics['provider_error_code'] ?? 'outcome_unknown', $diagnostics);
            }
            $wrapperFile = $this->files->write($user, $target, $directory.'/wrapper.sh',
                base64_encode($wrapper), expectedTargetBinding: $binding, expectedCredentialDispatch: $credentialDispatch,
                admitRemoteEffect: $admission->stage('staging'));
            if (($wrapperFile['status'] ?? '') !== 'completed') {
                $diagnostics = is_array($wrapperFile['__diagnostic_context'] ?? null)
                    ? $wrapperFile['__diagnostic_context'] : [];
                throw new SshTargetConnectionException($diagnostics['provider_error_code'] ?? 'outcome_unknown', $diagnostics);
            }
        } catch (Throwable $exception) {
            return $this->settleLaunch($target, $id, 'staging_files', $this->exceptionObservation($exception));
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
            return $this->settleLaunch($target, $id, 'dispatch_admission', [
                'status' => 'failed', 'error_code' => 'job_attempt_retired',
            ]);
        }

        $result = $this->safeCommand($user, $target, $launch, 8, $binding, $credentialDispatch, $admission->stage('launch'));

        return $this->settleLaunch($target, $id, 'launch', $result);
    }

    /** @return array<string,mixed> */
    private function recoverStart(object $row, string $digest, int $runtimeSeconds): array
    {
        if (! hash_equals((string) $row->script_digest, $digest)
            || (int) $row->runtime_seconds !== $runtimeSeconds) {
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->summary($row);
    }

    /**
     * Preserve exact launch evidence independently of Activity. A failed
     * staging phase may leave private files, but cannot have run the script
     * if the durable systemd-run admission marker is still explicitly false.
     *
     * @param  array<string,mixed>  $observation
     * @return array<string,mixed>
     */
    private function settleLaunch(Target $target, string $id, string $stage, array $observation): array
    {
        $reference = CorrelationId::current();
        $row = DB::transaction(function () use ($id, $stage, $observation, $reference): ?object {
            $row = DB::table('ssh_command_jobs')->where('id', $id)->lockForUpdate()->first();
            if ($row === null) {
                return null;
            }
            $this->storeLaunchObservation($id, $stage, $observation, $reference);
            if ($stage === 'probe') {
                if ($row->status === 'preparing') {
                    // Only an explicit completed negative capability observation
                    // is unsupported. Transport/admission failure proves nothing
                    // about the host's capabilities. Neither path staged files.
                    $unsupported = ($observation['error_code'] ?? null) === 'job_unsupported';
                    $this->transition($id, 'preparing', $unsupported ? 'unsupported' : 'failed',
                        ['terminal_reason' => $unsupported ? 'host_unsupported' : 'pre_dispatch_failed']);
                }
            } elseif ($row->status === 'launch_unknown') {
                if ($row->launch_admitted !== null && ! (bool) $row->launch_admitted) {
                    $this->transition($id, 'launch_unknown', 'failed', ['terminal_reason' => 'pre_launch_failed']);
                } elseif ($stage === 'launch' && $this->successful($observation)) {
                    $this->transition($id, 'launch_unknown', 'running');
                }
            }

            return DB::table('ssh_command_jobs')->where('id', $id)->first();
        });
        $admitted = $row !== null && ($row->launch_admitted === null || (bool) $row->launch_admitted);
        $acknowledged = $stage === 'launch' && $this->successful($observation) && $admitted;
        $code = $acknowledged ? null : ($admitted ? 'outcome_unknown' : ($observation['error_code'] ?? 'pre_launch_failed'));
        $this->record($target, 'ssh-job-start', $acknowledged ? 'success' : ($admitted ? 'unknown' : 'failure'),
            $code, [...$this->commandDiagnostics($observation), 'job_id' => $id, 'job_stage' => $stage,
                ...($stage === 'probe' ? ['effect_unconfirmed' => false, 'retry_safe' => false] : []),
                'job_launch_admitted' => $admitted, 'authoritative_status' => $row?->status], $reference);

        return $this->summary($row);
    }

    /** @param array<string,mixed> $observation */
    private function storeLaunchObservation(string $id, string $stage, array $observation, string $reference): void
    {
        DB::table('ssh_command_jobs')->where('id', $id)->whereNull('launch_observation_ciphertext')->update([
            'launch_observation_ciphertext' => Crypt::encryptString(json_encode([
                'stage' => $stage, 'observed_at' => now()->toISOString(),
                'diagnostic_reference' => $reference,
                'status' => $observation['status'] ?? 'outcome_unknown',
                'error_code' => $observation['error_code'] ?? null,
                'exit_code' => $observation['exit_code'] ?? null,
                'diagnostics' => OperationDiagnostics::safeContext([
                    ...$this->commandDiagnostics($observation),
                    ...($stage === 'probe' ? ['effect_unconfirmed' => false, 'retry_safe' => false] : []),
                ]),
            ], JSON_THROW_ON_ERROR)),
            'updated_at' => now(),
        ]);
    }

    /** @return array<string,mixed> */
    public function status(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        [$target, $row] = $this->existing($user, $targetId, $clientHash, $jobId, false);
        if ($row->status === 'preparing' || ($row->status === 'launch_unknown'
            && $row->launch_admitted !== null && ! (bool) $row->launch_admitted)) {
            // The exact native launch gate cannot cross either retired state.
            $this->recoverStalePreparing((int) $user->getKey(), $jobId);
            $this->recoverStaleUnlaunched((int) $user->getKey(), $jobId);

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first());
        }
        $recoverExit = $row->status === 'failed' && $row->exit_code === null
            && $row->terminal_reason === 'systemd_exit-code';
        if ($this->terminal($row) && ! $recoverExit) {
            return $this->summary($row);
        }

        try {
            $remote = SshJobRemoteIdentity::forJob($target, $row, $this->directory($jobId));
        } catch (SshTargetConnectionException $exception) {
            return $this->remoteFailure($target, $row, 'ssh-job-status', $this->exceptionObservation($exception));
        }

        // A missing marker is normal before completion. Permission or
        // transport failure is separate evidence, not a fabricated exit.
        $readFailure = null;
        try {
            $exit = $this->exitCode($user, $target, $jobId, $remote);
        } catch (Throwable $exception) {
            $exit = null;
            $readFailure = $this->exceptionObservation($exception);
            if (($exception instanceof SshTargetConnectionException && $exception->reason === 'job_identity_unverified') || $recoverExit) {
                return $this->remoteFailure($target, $row, 'ssh-job-status', $readFailure);
            }
        }
        if ($exit !== null) {
            if ($recoverExit) {
                DB::table('ssh_command_jobs')->where('id', $jobId)
                    ->where('status', 'failed')->whereNull('exit_code')
                    ->where('terminal_reason', 'systemd_exit-code')
                    ->update(['exit_code' => $exit, 'terminal_reason' => 'script_exit', 'updated_at' => now()]);
            } else {
                $this->transition($jobId, (string) $row->status, $exit === 0 ? 'completed' : 'failed',
                    ['exit_code' => $exit, 'terminal_reason' => 'script_exit']);
            }

            return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first(), remoteObserved: true);
        }
        if ($recoverExit) {
            return $this->summary($row, remoteObserved: false);
        }
        if (! in_array($row->unit_mode, ['user', 'system'], true)) {
            return $this->remoteFailure($target, $row, 'ssh-job-status', $readFailure ?? [
                'error_code' => 'job_state_unconfirmed', 'status' => 'outcome_unknown',
            ]);
        }

        $running = $this->safeCommand($user, $target,
            $this->managerEnvironment((string) $row->unit_mode).'systemctl '.($row->unit_mode === 'user' ? '--user ' : '')
            .'show '.escapeshellarg($this->unit($jobId))
            .' --property=LoadState --property=ActiveState --property=Result --property=ExecMainCode --property=ExecMainStatus --no-pager',
            8, remote: $remote);
        if (! $this->successful($running)) {
            return $this->remoteFailure($target, $row, 'ssh-job-status', $running);
        }
        $state = trim((string) ($running['stdout'] ?? ''));
        if (preg_match('/(?:^|\n)LoadState=loaded(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)ActiveState=(?:active|activating)(?:\n|$)/D', $state) === 1) {
            if ($row->status === 'launch_unknown') {
                $this->transition($jobId, 'launch_unknown', 'running');
            }
        } elseif (preg_match('/(?:^|\n)LoadState=loaded(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)ActiveState=failed(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)Result=(timeout|exit-code|signal|core-dump|resources|watchdog|start-limit-hit)(?:\n|$)/D', $state, $match) === 1) {
            $systemdExit = null;
            if ($match[1] === 'exit-code'
                && preg_match('/(?:^|\n)ExecMainCode=1(?:\n|$)/D', $state) === 1
                && preg_match('/(?:^|\n)ExecMainStatus=([0-9]{1,3})(?:\n|$)/D', $state, $exitMatch) === 1
                && (int) $exitMatch[1] > 0 && (int) $exitMatch[1] <= 255) {
                $systemdExit = (int) $exitMatch[1];
            }
            $this->transition($jobId, (string) $row->status, 'failed',
                ['exit_code' => $systemdExit, 'terminal_reason' => 'systemd_'.$match[1]]);
        } elseif ($row->status === 'cancel_requested'
            && preg_match('/(?:^|\n)LoadState=loaded(?:\n|$)/D', $state) === 1) {
            // A loaded unit can still be safely stopped by an explicit
            // cancel request, even without a readable natural exit marker.
            return $this->summary($row, remoteObserved: true);
        } else {
            // Unavailable/collected unit is not evidence that a prior
            // confirmed running state was false. Keep the journal intact.
            return $this->remoteFailure($target, $row, 'ssh-job-status', $readFailure ?? [
                'error_code' => 'job_state_unconfirmed', 'status' => 'outcome_unknown',
            ]);
        }

        return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first(), remoteObserved: true);
    }

    private function terminal(object $row): bool
    {
        return in_array($row->status, ['completed', 'failed', 'canceled', 'unsupported', 'retired'], true);
    }

    /** @param array<string,mixed> $observation
     * @return array<string,mixed>
     */
    private function remoteFailure(Target $target, object $row, string $operation, array $observation): array
    {
        $code = (string) ($observation['error_code'] ?? 'job_state_unconfirmed');
        $reference = CorrelationId::current();
        $this->record($target, $operation, ($observation['status'] ?? null) === 'outcome_unknown' ? 'unknown' : 'failure',
            $code, [...$this->commandDiagnostics($observation), 'job_id' => $row->id], $reference);

        return [
            ...$this->summary(DB::table('ssh_command_jobs')->where('id', $row->id)->first(), $code),
            'diagnostic_reference' => $reference,
        ];
    }

    /**
     * Database-only retained Job discovery. A cursor is authenticated to the
     * full caller/Target/filter scope and cannot be reused by another client.
     * Uncertain Jobs remain discoverable past their nominal expiration until
     * the existing operator reconciliation contract permits their retirement.
     *
     * @return array<string,mixed>
     */
    public function list(
        User $user, string $targetId, string $clientHash,
        ?string $status = null, ?string $cursor = null, int $limit = 20,
    ): array {
        $target = $this->authorized($user, $targetId, false, checkPause: false, requireConnected: false);
        if (strlen($clientHash) !== 64 || ! ctype_xdigit($clientHash)) {
            throw new SshTargetConnectionException('target_not_found');
        }
        $statuses = [
            'preparing', 'launch_unknown', 'running', 'cancel_requested',
            'completed', 'failed', 'canceled', 'unsupported', 'retired',
        ];
        if ($limit < 1 || $limit > 50 || ($status !== null && ! in_array($status, $statuses, true))) {
            throw new SshTargetConnectionException('invalid_input');
        }

        $after = null;
        if ($cursor !== null) {
            if (preg_match('/^([0-9A-HJKMNP-TV-Z]{26})\\.([a-f0-9]{64})$/D', $cursor, $match) !== 1
                || ! hash_equals($this->listCursorSignature(
                    $user, $target, $clientHash, $status, $match[1],
                ), $match[2])) {
                throw new SshTargetConnectionException('invalid_input');
            }
            $after = $match[1];
        }

        $rows = DB::table('ssh_command_jobs')
            ->select(['id', 'status', 'created_at', 'updated_at', 'expires_at',
                'runtime_seconds', 'exit_code', 'terminal_reason', 'launch_admitted'])
            ->where('user_id', $user->getKey())
            ->where('target_record_id', $target->getKey())
            ->where('client_identity_hash', $clientHash)
            ->where(static function ($query): void {
                $query->whereNotIn('status', ['completed', 'failed', 'canceled', 'unsupported', 'retired'])
                    ->orWhere('expires_at', '>', now());
            })
            ->when($status !== null, static fn ($query) => $query->where('status', $status))
            ->when($after !== null, static fn ($query) => $query->where('id', '<', $after))
            ->orderByDesc('id')
            ->limit($limit + 1)->get();

        $hasMore = $rows->count() > $limit;
        $items = $rows->take($limit)->map(static fn (object $row): array => [
            'job_id' => $row->id,
            'status' => $row->status,
            'created_at' => $row->created_at,
            'updated_at' => $row->updated_at,
            'expires_at' => $row->expires_at,
            'max_runtime_seconds' => $row->runtime_seconds,
            'exit_code' => $row->exit_code,
            'terminal_reason' => $row->terminal_reason,
            'complete' => in_array($row->status, ['completed', 'failed', 'canceled'], true),
            'retry_safe' => false,
            'launch_admitted' => $row->launch_admitted === null ? null : (bool) $row->launch_admitted,
        ])->values()->all();
        $last = $hasMore ? end($items)['job_id'] : null;

        return [
            'jobs' => $items,
            'next_cursor' => $last === null ? null : $last.'.'.$this->listCursorSignature(
                $user, $target, $clientHash, $status, $last,
            ),
            'has_more' => $hasMore,
        ];
    }

    private function listCursorSignature(
        User $user, Target $target, string $clientHash, ?string $status, string $id,
    ): string {
        return hash_hmac('sha256', implode("\0", [
            (string) $user->getKey(), (string) $target->getKey(), $clientHash,
            $status ?? '', $id,
        ]), (string) config('app.key'));
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
            || $offset < 0 || $offset > self::MAX_OUTPUT_BYTES || $length < 1
            || $length > $this->settings->sshJobOutputWindowBytes()) {
            throw new SshTargetConnectionException('invalid_input');
        }
        if ($row->launch_admitted !== null && ! (bool) $row->launch_admitted) {
            return [
                'job_id' => $jobId, 'stream' => $stream, 'available' => false,
                'offset' => $offset, 'encoding' => 'base64', 'data' => '',
                'complete' => $this->terminal($row), 'status' => $row->status,
                'launch_admitted' => false,
            ];
        }
        $remote = SshJobRemoteIdentity::forJob($target, $row, $this->directory($jobId));
        try {
            $file = $this->readJobFile($user, $target, $jobId, $stream, $offset, $length, $remote);
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
                $this->readJobFile($user, $target, $jobId, $stream.'.truncated', 0, 1, $remote);
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
        $row = CurrentReadTransaction::run(function () use ($user, $target, $clientHash, $jobId): object {
            User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $row = DB::table('ssh_command_jobs')->where('id', $jobId)
                ->where('user_id', $user->getKey())->where('target_record_id', $target->getKey())
                ->where('client_identity_hash', $clientHash)->lockForUpdate()->first();
            if ($row === null) {
                throw new SshTargetConnectionException('target_not_found');
            }
            $current = $this->authorized($user, $target->target_id, false, checkPause: false, requireConnected: false);
            if ((string) $current->getKey() !== (string) $target->getKey()) {
                throw new SshTargetConnectionException('target_not_found');
            }
            if (! $this->terminal($row)) {
                if ($row->status === 'preparing' || ($row->launch_admitted !== null && ! (bool) $row->launch_admitted)) {
                    $reason = $row->status === 'preparing' ? 'pre_dispatch_canceled' : 'pre_launch_canceled';
                    $this->transition($jobId, $row->status, 'canceled', ['terminal_reason' => $reason]);
                } elseif ($row->status !== 'cancel_requested') {
                    $this->transition($jobId, $row->status, 'cancel_requested');
                }
            }

            return DB::table('ssh_command_jobs')->where('id', $jobId)->firstOrFail();
        });
        if ($this->terminal($row)) {
            return $this->summary($row);
        }

        // A local cancellation request is not a stop confirmation.
        // Reconcile a prior natural exit first; no re-launch path exists.
        $reconciled = $this->status($user, $targetId, $clientHash, $jobId);
        $row = DB::table('ssh_command_jobs')->where('id', $jobId)->firstOrFail();
        if ($this->terminal($row) || isset($reconciled['remote_error_code'])) {
            return $reconciled;
        }
        try {
            $remote = SshJobRemoteIdentity::forJob($target, $row, $this->directory($jobId));
        } catch (SshTargetConnectionException $exception) {
            return $this->remoteFailure($target, $row, 'ssh-job-cancel', $this->exceptionObservation($exception));
        }
        if (! in_array($row->unit_mode, ['system', 'user'], true)) {
            return $this->summary($row, 'job_state_unconfirmed');
        }

        $scope = $row->unit_mode === 'user' ? '--user ' : '';
        $unit = escapeshellarg($this->unit($jobId));
        $systemctl = $this->managerEnvironment((string) $row->unit_mode).'systemctl '.$scope;
        // Prove this unique unit was actually loaded before stopping it.
        // A not-found unit could be a launch admitted but not yet sent.
        $cancelGate = (new SshJobLaunchAdmission($this->access, $jobId, (int) $user->getKey(), (string) $target->getKey()))->stage('cancel');
        $response = $this->safeCommand($user, $target,
            'test "$('.$systemctl.'show --property=LoadState --value '.$unit.')" = loaded && '.$systemctl.'stop '.$unit,
            8, admitRemoteEffect: $cancelGate, remote: $remote);
        if (! $this->successful($response)) {
            return $this->remoteFailure($target, $row, 'ssh-job-cancel', $response);
        }
        $verification = $this->safeCommand($user, $target,
            $systemctl.'show '.$unit.' --property=LoadState --property=ActiveState --property=MainPID --property=ControlPID --no-pager',
            8, remote: $remote);
        $state = (string) ($verification['stdout'] ?? '');
        if (! $this->successful($verification)
            || (! $this->stoppedUnitEvidence($state) && ! $this->collectedUnitEvidence($state))) {
            return $this->remoteFailure($target, $row, 'ssh-job-cancel',
                $this->successful($verification) ? ['status' => 'outcome_unknown', 'error_code' => 'job_state_unconfirmed'] : $verification);
        }

        // The exact loaded unit was stopped and its zero-PID state verified.
        // A durable natural exit marker, if available, outranks cancellation.
        $exit = null;
        try {
            $exit = $this->exitCode($user, $target, $jobId, $remote);
        } catch (SshTargetConnectionException $exception) {
            // Stop is proven; a failed read cannot erase that evidence.
            $this->record($target, 'ssh-job-cancel-exit-read', 'failure', $exception->reason, $exception->diagnostics);
        }
        $final = $exit === null ? 'canceled' : ($exit === 0 ? 'completed' : 'failed');
        if ($this->transition($jobId, 'cancel_requested', $final,
            ['exit_code' => $exit, 'terminal_reason' => $exit === null ? 'canceled' : 'script_exit'])) {
            $this->record($target, 'ssh-job-cancel', 'success', null);
        }

        return $this->summary(DB::table('ssh_command_jobs')->where('id', $jobId)->first(), remoteObserved: true);
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
            if ((! in_array($row->status, ['completed', 'failed', 'canceled', 'unsupported'], true)
                    || in_array($row->terminal_reason, ['pre_launch_failed', 'pre_launch_abandoned', 'pre_launch_canceled'], true))
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
     * Compatibility entry for existing callers. The installed scheduler uses
     * maintain() for bounded, diagnostic prune AND remote-status recovery.
     */
    public function prune(): int
    {
        return $this->pruneDetailed()['cleaned'];
    }

    /** @return array<string,mixed> */
    public function maintain(): array
    {
        $prune = $this->pruneDetailed();
        $reconcile = $this->reconcileStaleJobs();
        $report = [
            'diagnostic_id' => (string) Str::ulid(),
            'preparing_recovered' => $prune['preparing_recovered'],
            'prune' => $prune,
            'reconcile' => $reconcile,
            'expired_terminal_backlog' => DB::table('ssh_command_jobs')
                ->where('expires_at', '<=', now())
                ->whereIn('status', ['completed', 'failed', 'canceled', 'unsupported', 'retired'])->count(),
            'expired_unresolved_backlog' => DB::table('ssh_command_jobs')
                ->where('expires_at', '<=', now())
                ->whereIn('status', ['preparing', 'running', 'launch_unknown', 'cancel_requested'])->count(),
        ];
        Log::info('SSH Job maintenance progress.', $report);

        return $report;
    }

    /**
     * Keyset progress persists across scheduler invocations. Blocked oldest
     * identities cannot starve later cleanable rows, even after a restart.
     * Unknown or active Jobs remain durable; only verified private remote
     * spools or known no-effect intents can be deleted.
     *
     * @return array<string,int>
     */
    private function pruneDetailed(): array
    {
        $stats = [
            'preparing_recovered' => $this->recoverStalePreparing() + $this->recoverStaleUnlaunched(),
            'scanned' => 0, 'eligible' => 0, 'processed' => 0, 'cleaned' => 0,
            'blocked_by_identity' => 0, 'retained_by_policy' => 0,
            'remote_unavailable' => 0, 'error' => 0,
        ];
        $cursor = $this->maintenanceCursor('prune');
        $query = function (?object $cursor) {
            return DB::table('ssh_command_jobs')
                ->where('expires_at', '<=', now())
                ->whereIn('status', ['completed', 'failed', 'canceled', 'unsupported', 'retired'])
                ->when($cursor !== null && $cursor->last_expires_at !== null && $cursor->last_id !== null,
                    static fn ($q) => $q->where(static function ($after) use ($cursor): void {
                        $after->where('expires_at', '>', $cursor->last_expires_at)
                            ->orWhere(static function ($same) use ($cursor): void {
                                $same->where('expires_at', $cursor->last_expires_at)
                                    ->where('id', '>', $cursor->last_id);
                            });
                    }))
                ->orderBy('expires_at')->orderBy('id')->limit(250)->get();
        };
        $rows = $query($cursor);
        if ($rows->isEmpty() && $cursor->last_id !== null) {
            // One bounded wrap; never loop through the same blocked head.
            $this->advanceMaintenanceCursor('prune', null, null);
            $rows = $query(null);
        }

        $last = null;
        foreach ($rows as $row) {
            // Limit costly remote effects independently of cheap DB skips.
            if ($stats['processed'] >= 25) {
                break;
            }
            $last = $row;
            $stats['scanned']++;
            if ($row->status === 'unsupported' || $row->status === 'retired'
                || in_array($row->terminal_reason, ['pre_dispatch_abandoned', 'pre_dispatch_canceled'], true)
                || ($row->status === 'failed' && $row->terminal_reason === 'pre_dispatch_failed'
                    && $row->launch_admitted !== null && ! (bool) $row->launch_admitted)) {
                $stats['eligible']++;
                $stats['cleaned'] += DB::table('ssh_command_jobs')->where('id', $row->id)
                    ->where('status', $row->status)->delete();

                continue;
            }
            $target = Target::query()->whereKey($row->target_record_id)->first();
            $user = User::query()->whereKey($row->user_id)->first();
            if (! $target instanceof Target || ! $user instanceof User) {
                $stats['blocked_by_identity']++;

                continue;
            }
            try {
                $this->authorized($user, $target->target_id, false);
                $remote = SshJobRemoteIdentity::forJob($target, $row, $this->directory((string) $row->id));
                $stats['eligible']++;
                $stats['processed']++;
                // A never-admitted launch cannot have created a detached
                // unit; still wait out its staging lease before cleanup.
                $neverLaunched = $row->launch_admitted !== null && ! (bool) $row->launch_admitted
                    && in_array($row->terminal_reason, ['pre_launch_failed', 'pre_launch_abandoned', 'pre_launch_canceled'], true);
                if ($neverLaunched && ($row->admission_expires_at === null || now()->lt($row->admission_expires_at))) {
                    $stats['retained_by_policy']++;

                    continue;
                }
                $stopProof = $neverLaunched ? 'never_launched' : $this->remoteUnitStopProof($user, $target, $row, $remote);
                if ($stopProof === null) {
                    $stats['retained_by_policy']++;
                    Log::notice('SSH Job spool retained: remote process stop was not proven.', [
                        'job_id' => $row->id,
                        'unit_mode' => $row->unit_mode,
                    ]);

                    continue;
                }
                $clean = $this->spoolCleanupCommand(
                    $this->directory((string) $row->id),
                    $stopProof === 'exit_marker' ? (int) $row->exit_code : null,
                    $row->original_peer_fingerprint !== null,
                );
                $result = $this->safeCommand($user, $target, $clean, 8, remote: $remote);
                if (! $this->successful($result)) {
                    $stderr = ($result['stderr_encoding'] ?? null) === 'utf-8'
                        ? (string) ($result['stderr'] ?? '') : '';
                    $reason = match (true) {
                        str_contains($stderr, 'ssh_job_spool_unexpected_entry') => 'unexpected_spool_entry',
                        str_contains($stderr, 'ssh_job_spool_incompatible_entry') => 'incompatible_spool_entry',
                        str_contains($stderr, 'ssh_job_spool_invalid_directory') => 'invalid_spool_directory',
                        str_contains($stderr, 'ssh_job_spool_exit_marker_mismatch') => 'exit_marker_mismatch',
                        default => 'remote_command_unavailable',
                    };
                    if ($reason === 'remote_command_unavailable') {
                        $stats['remote_unavailable']++;
                    } else {
                        $stats['retained_by_policy']++;
                    }
                    Log::notice('SSH Job spool cleanup retained without deleting durable Job.', [
                        'job_id' => $row->id, 'reason' => $reason,
                        'remote_exit_code' => $result['exit_code'] ?? null,
                    ]);

                    continue;
                }
                $stats['cleaned'] += DB::table('ssh_command_jobs')->where('id', $row->id)
                    ->where('status', $row->status)->delete();
            } catch (SshTargetConnectionException $exception) {
                $stats[in_array($exception->reason, ['target_changed', 'job_identity_unverified'], true) ? 'blocked_by_identity' : 'retained_by_policy']++;
                Log::notice('SSH Job cleanup retained without authority.', [
                    'job_id' => $row->id, 'reason' => $exception->reason,
                ]);
            } catch (Throwable $exception) {
                $stats['error']++;
                Log::warning('SSH Job cleanup failed without deleting durable evidence.', [
                    'job_id' => $row->id, 'exception_class' => $exception::class,
                ]);
            }
        }
        if ($last !== null) {
            $this->advanceMaintenanceCursor('prune', (string) $last->id, (string) $last->expires_at);
        }

        return $stats;
    }

    /**
     * Preflight the entire original private spool before unlinking ANY entry.
     * Unknown files, directories, symlinks and mismatched exit witnesses must
     * preserve all evidence; never substitute a recursive removal.
     */
    private function spoolCleanupCommand(string $directory, ?int $exitCode, bool $hasWitness = false): string
    {
        $files = ['script.sh', 'wrapper.sh', 'stdout', 'stderr', 'exit-code',
            'stdout.pipe', 'stderr.pipe', 'stdout.truncated', 'stderr.truncated'];
        if ($hasWitness) {
            $files[] = SshJobRemoteIdentity::MARKER;
        }
        $quoted = escapeshellarg($directory);
        $expected = implode('|', array_map(
            static fn (string $file): string => escapeshellarg($directory.'/'.$file), $files,
        ));
        $preflight = 'for entry in '.$quoted.'/* '.$quoted.'/.[!.]* '.$quoted.'/..?*; do '
            .'if test -e "$entry" || test -L "$entry"; then '
            .'case "$entry" in '
            .$expected.') '
            .'if test -L "$entry" || { ! test -f "$entry" && ! test -p "$entry"; }; then '
            .'printf "ssh_job_spool_incompatible_entry\n" >&2; exit 1; fi ;; '
            .'*) printf "ssh_job_spool_unexpected_entry\n" >&2; exit 1 ;; '
            .'esac; fi; done';

        return 'if ! test -e '.$quoted.' && ! test -L '.$quoted.'; then exit 0; fi; '
            .'if ! { test -d '.$quoted.' && test ! -L '.$quoted
            .' && test "$(stat -c %a -- '.$quoted.')" = 700'
            .' && test "$(stat -c %u -- '.$quoted.')" = "$(id -u)"; }; then '
            .'printf "ssh_job_spool_invalid_directory\n" >&2; exit 1; fi; '
            // Collected systemd units need a matching original wrapper exit
            // marker in the very same validated cleanup command.
            .($exitCode !== null
                ? 'if ! test "$(cat -- '.escapeshellarg($directory.'/exit-code').')" = '
                    .escapeshellarg((string) $exitCode).'; then '
                    .'printf "ssh_job_spool_exit_marker_mismatch\n" >&2; exit 1; fi; '
                : '')
            .$preflight.' && rm -f -- '.implode(' ', array_map(
                static fn (string $file): string => escapeshellarg($directory.'/'.$file), $files,
            ))
            .' && rmdir -- '.$quoted;
    }

    /**
     * The original authenticated systemd manager can prove a loaded unit is
     * stopped. Collected units (LoadState=not-found) are different: systemctl
     * exits zero and reports inactive/zero PIDs even for a NEVER-EXISTING Job.
     * Permit cleanup only with another positive independent terminal witness:
     * a prior verified cancel transition, or a previously recorded exit code
     * whose exact remote private marker is rechecked during the cleanup CAS.
     *
     * @return 'loaded'|'canceled'|'exit_marker'|null
     */
    private function remoteUnitStopProof(User $user, Target $target, object $row, SshJobRemoteIdentity $remote): ?string
    {
        if (! in_array($row->unit_mode, ['system', 'user'], true)) {
            return null;
        }
        $mode = (string) $row->unit_mode;
        $result = $this->safeCommand($user, $target,
            $this->managerEnvironment($mode).'systemctl '.($mode === 'user' ? '--user ' : '')
            .'show '.escapeshellarg($this->unit((string) $row->id))
            .' --property=LoadState --property=ActiveState --property=MainPID --property=ControlPID --no-pager',
            8, remote: $remote);
        if (! $this->successful($result)) {
            return null;
        }
        $state = (string) ($result['stdout'] ?? '');
        if ($this->stoppedUnitEvidence($state)) {
            return 'loaded';
        }
        if (! $this->collectedUnitEvidence($state)) {
            return null;
        }

        return $this->collectedTerminalProof($row);
    }

    /** @return 'canceled'|'exit_marker'|null */
    private function collectedTerminalProof(object $row): ?string
    {
        // The only runtime transition to canceled required a successful
        // systemctl stop AND a separate inactive/zero-PID verification.
        if ($row->status === 'canceled' && $row->terminal_reason === 'canceled'
            && $row->exit_code === null) {
            return 'canceled';
        }
        // Never trust a stored terminal claim alone. A real wrapper may have
        // completed after systemd's status was read and its unit collected;
        // require a matching durable exit marker in the original private
        // spool in the SAME cleanup command that unlinks the files.
        if (in_array($row->status, ['completed', 'failed'], true)
            && $row->exit_code !== null && (int) $row->exit_code >= 0
            && (int) $row->exit_code <= 255
            && $row->terminal_reason !== 'pre_dispatch_abandoned') {
            return 'exit_marker';
        }

        return null;
    }

    private function stoppedUnitEvidence(string $response): bool
    {
        $state = trim($response);

        return preg_match('/(?:^|\n)LoadState=loaded(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)ActiveState=(?:inactive|failed)(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)MainPID=0(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)ControlPID=0(?:\n|$)/D', $state) === 1;
    }

    private function collectedUnitEvidence(string $response): bool
    {
        $state = trim($response);

        return preg_match('/(?:^|\n)LoadState=not-found(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)ActiveState=inactive(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)MainPID=0(?:\n|$)/D', $state) === 1
            && preg_match('/(?:^|\n)ControlPID=0(?:\n|$)/D', $state) === 1;
    }

    /**
     * Read-only remote evidence probes for stale, previously launched Jobs.
     * Runs as the genuinely scheduled CLI maintenance actor and reuses the
     * original user/Target/client/binding checks in status(). No script replay.
     *
     * @return array<string,int>
     */
    private function reconcileStaleJobs(): array
    {
        $stats = [
            'scanned' => 0, 'eligible' => 0, 'processed' => 0, 'terminal_reconciled' => 0,
            'blocked_by_identity' => 0, 'retained_by_policy' => 0,
            'remote_unavailable' => 0, 'unresolved' => 0, 'error' => 0,
        ];
        $cursor = $this->maintenanceCursor('reconcile');
        $query = function (?object $cursor) {
            return DB::table('ssh_command_jobs')
                ->whereIn('status', ['running', 'launch_unknown', 'cancel_requested'])
                ->where('updated_at', '<=', now()->subMinutes(5))
                ->when($cursor?->last_id !== null,
                    static fn ($q) => $q->where('id', '>', $cursor->last_id))
                ->orderBy('id')->limit(100)->get();
        };
        $rows = $query($cursor);
        if ($rows->isEmpty() && $cursor->last_id !== null) {
            $this->advanceMaintenanceCursor('reconcile', null, null);
            $rows = $query(null);
        }
        $last = null;
        foreach ($rows as $row) {
            if ($stats['processed'] >= 10) {
                break;
            }
            $last = $row;
            $stats['scanned']++;
            $target = Target::query()->whereKey($row->target_record_id)->first();
            $user = User::query()->whereKey($row->user_id)->first();
            if (! $target instanceof Target || ! $user instanceof User) {
                $stats['blocked_by_identity']++;

                continue;
            }
            // status() rechecks original Target binding, OAuth-admitted actor's
            // live role/Target permissions, Pause and read-only SSH identity.
            try {
                $stats['eligible']++;
                $stats['processed']++;
                $current = $this->status($user, $target->target_id,
                    (string) $row->client_identity_hash, (string) $row->id);
                if (isset($current['remote_error_code'])) {
                    $stats['remote_unavailable']++;
                } elseif (in_array($current['status'], ['completed', 'failed', 'canceled'], true)) {
                    $stats['terminal_reconciled']++;
                } else {
                    $stats['unresolved']++;
                }
            } catch (SshTargetConnectionException $exception) {
                $stats['retained_by_policy']++;
                Log::notice('SSH Job status reconciliation retained.', [
                    'job_id' => $row->id, 'reason' => $exception->reason,
                ]);
            } catch (Throwable $exception) {
                $stats['error']++;
                Log::warning('SSH Job status reconciliation failed.', [
                    'job_id' => $row->id, 'exception_class' => $exception::class,
                ]);
            }
        }
        if ($last !== null) {
            $this->advanceMaintenanceCursor('reconcile', (string) $last->id, null);
        }

        return $stats;
    }

    private function maintenanceCursor(string $operation): object
    {
        $cursor = DB::table('ssh_job_maintenance_progress')->where('operation', $operation)->first();
        if ($cursor === null) {
            throw new \RuntimeException('SSH Job maintenance migration is missing.');
        }

        return $cursor;
    }

    private function advanceMaintenanceCursor(string $operation, ?string $id, ?string $expiresAt): void
    {
        DB::table('ssh_job_maintenance_progress')->where('operation', $operation)->update([
            'last_id' => $id, 'last_expires_at' => $expiresAt, 'updated_at' => now(),
        ]);
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
        $target = $this->authorized($user, $targetId, false, checkPause: false, requireConnected: false);
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
        $actor = $this->operationAdmission->currentActor($this->operationAdmission->capture($user), $user);
        if ($row === null || ! $actor instanceof User
            || ! $this->access->allows($actor, GatewayPermission::SshCommandRun, $target)
            || ($requireFileRead && ! $this->access->allows($actor, GatewayPermission::SshFileRead, $target))) {
            throw new SshTargetConnectionException('target_not_found');
        }

        return [$target, $row];
    }

    private function authorized(
        User $user, string $targetId, bool $requiresFileWrite, bool $checkPause = true, bool $requireConnected = true,
    ): Target {
        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            throw new SshTargetConnectionException('target_not_found');
        }
        $actor = $this->operationAdmission->currentActor($this->operationAdmission->capture($user), $user);
        if (! $actor instanceof User) {
            throw new SshTargetConnectionException('target_not_found');
        }
        $target = $this->access->scopeTargets(Target::query(), $actor, GatewayPermission::SshCommandRun)
            ->where('target_id', $targetId)->where('connector_type', 'ssh_direct')->first();
        if (! $target instanceof Target || ($requireConnected && $target->getAttribute('connection_state') !== TargetConnectionState::Connected)
            || ($requiresFileWrite && (! $this->access->allows($actor, GatewayPermission::SshFileWrite, $target)
                || ! $this->access->allows($actor, GatewayPermission::SshFileRead, $target)))) {
            throw new SshTargetConnectionException('target_not_found');
        }
        if ($checkPause && TargetOperationGate::isPaused($target)) {
            throw new SshTargetConnectionException('target_paused');
        }

        return $target;
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
            'original_peer_fingerprint' => SshJobRemoteIdentity::peerFingerprint($target, $config),
            'original_target_record_id' => (string) $target->getKey(),
            'original_target_id' => (string) $target->target_id,
            'original_host' => (string) $config->host,
            'original_port' => (int) $config->port,
            'original_os_username' => (string) $config->username,
            'original_auth_method' => (string) $config->auth_method,
            'original_host_key_digest' => hash('sha256', (string) $config->pinned_host_key),
        ];
    }

    /** @param array<string,mixed> $observation */
    private function probe(User $user, Target $target, string $expectedTargetBinding, string $expectedCredentialDispatch, Closure $gate, array &$observation): ?string
    {
        // Use an explicit completed capability-negative result. Nonzero
        // exit, failed login or unknown transport response is not evidence
        // that this host lacks the required persistent manager.
        $command = 'for requirement in mkfifo head wc rm systemd-run; do '
            .'command -v "$requirement" >/dev/null 2>&1 || { printf unsupported; exit 0; }; done; '
            .'uid="$(id -u)" || exit 1; if [ "$uid" = 0 ]; then '
            .'manager="$(cat /proc/1/comm)" || exit 1; '
            .'if [ "$manager" = systemd ]; then printf system; else printf unsupported; fi; '
            .'else command -v loginctl >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 '
            .'|| { printf unsupported; exit 0; }; '
            .'linger="$(loginctl show-user "$uid" -p Linger --value 2>/dev/null)" || exit 1; '
            .'case "$linger" in no) printf unsupported ;; yes) '
            .$this->managerEnvironment('user').'systemctl --user show-environment >/dev/null 2>&1 && printf user ;; *) exit 1 ;; esac; fi';
        $result = $this->safeCommand($user, $target, $command, 5, $expectedTargetBinding, $expectedCredentialDispatch, $gate);
        $observation = $this->classifyProbe($result);

        return isset($observation['error_code']) ? null : trim((string) $observation['stdout']);
    }

    /**
     * @param  array<string,mixed>  $result
     * @return array<string,mixed>
     */
    private function classifyProbe(array $result): array
    {
        if ($this->successful($result)) {
            $mode = trim((string) ($result['stdout'] ?? ''));
            if (in_array($mode, ['user', 'system'], true)) {
                return $result;
            }
            $result['error_code'] = $mode === 'unsupported' ? 'job_unsupported' : 'job_state_unconfirmed';
        }
        $code = $result['error_code'] ?? 'job_state_unconfirmed';
        $defaults = match ($code) {
            'egress_denied' => ['failure_origin' => 'gateway_admission', 'failure_stage' => 'connection_setup', 'request_not_sent' => true],
            'forbidden', 'authorization_revoked', 'target_changed', 'target_paused', 'target_not_found',
            'job_attempt_retired', 'dispatch_lease_expired', 'rate_limited', 'connection_busy', 'admission_unavailable',
            'timeout_unsupported', 'ssh_output_collector_unavailable', 'credential_unavailable', 'credential_invalid',
            'reverse_route_not_approved' => ['failure_origin' => 'gateway_admission', 'failure_stage' => 'admission', 'request_not_sent' => true],
            'host_key_mismatch', 'authentication_failed', 'ssh_handshake_failed',
            'tcp_unreachable', 'tcp_peer_mismatch', 'reverse_listener_unavailable', 'relay_unavailable' => [
                'failure_origin' => 'gateway_transport', 'failure_stage' => 'connection_setup', 'request_not_sent' => true,
            ],
            'job_unsupported', 'remote_exit_nonzero' => ['failure_origin' => 'gateway_response', 'failure_stage' => 'operation'],
            default => ['failure_origin' => 'unknown', 'failure_stage' => 'operation', 'provider_cause_unknown' => true],
        };

        return [
            ...$result, 'error_code' => $code,
            'diagnostics' => [...$defaults, ...($result['diagnostics'] ?? []), 'job_stage' => 'probe', 'job_launch_admitted' => false],
        ];
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

    /** @return array<string,mixed> */
    private function safeCommand(
        User $user, Target $target, string $command, int $seconds, ?string $expectedTargetBinding = null,
        ?string $expectedCredentialDispatch = null, ?Closure $admitRemoteEffect = null,
        ?SshJobRemoteIdentity $remote = null,
    ): array {
        try {
            $result = $this->commands->run($user, $target, $remote?->command($command) ?? $command, $seconds,
                $remote->binding ?? $expectedTargetBinding,
                expectedCredentialDispatch: $remote->credentialDispatch ?? $expectedCredentialDispatch,
                admitRemoteEffect: $admitRemoteEffect);
            if ($remote !== null && ($result['exit_code'] ?? null) === 1
                && trim((string) ($result['stderr'] ?? '')) === 'ssh_job_identity_unverified') {
                return [...$result, 'error_code' => 'job_identity_unverified'];
            }
            if (($result['status'] ?? null) === 'outcome_unknown') {
                return [...$result, 'error_code' => 'outcome_unknown'];
            }
            if (($result['exit_code'] ?? null) !== 0) {
                return [...$result, 'error_code' => 'remote_exit_nonzero'];
            }

            return $result;
        } catch (Throwable $exception) {
            return $this->exceptionObservation($exception);
        }
    }

    /** @return array<string,mixed> */
    private function exceptionObservation(Throwable $exception): array
    {
        return [
            'status' => $exception instanceof SshTargetConnectionException ? 'failed' : 'outcome_unknown',
            'error_code' => $exception instanceof SshTargetConnectionException ? $exception->reason : 'job_unavailable',
            'diagnostics' => [
                ...($exception instanceof SshTargetConnectionException ? $exception->diagnostics : []),
                'exception_class' => $exception::class,
            ],
        ];
    }

    /** @param array<string,mixed> $result
     * @return array<string,mixed>
     */
    private function commandDiagnostics(array $result): array
    {
        return [
            ...($result['diagnostics'] ?? []),
            ...isset($result['error_code']) ? ['provider_error_code' => $result['error_code'],
                'source_error_code' => $result['diagnostics']['source_error_code'] ?? $result['error_code']] : [],
            ...is_int($result['exit_code'] ?? null) ? ['remote_exit_code' => $result['exit_code']] : [],
            ...($result['status'] ?? null) === 'outcome_unknown' ? ['effect_unconfirmed' => true] : [],
        ];
    }

    /** @param array<string,mixed>|null $result */
    private function successful(?array $result): bool
    {
        return is_array($result)
            && ($result['status'] ?? '') === 'completed'
            && ($result['exit_code'] ?? null) === 0;
    }

    /**
     * Every retained Job observation composes command scope with the native
     * SFTP read grant, without borrowing the original launch lease or write
     * authority. The native guard follows both rights through artifact proof
     * and the actual read on the current authenticated connection.
     *
     * @return array<string,mixed>
     */
    private function readJobFile(User $user, Target $target, string $id, string $file, int $offset, int $length, SshJobRemoteIdentity $remote): array
    {
        return $this->files->read($user, $target, $this->directory($id).'/'.$file, $offset, $length,
            expectedTargetBinding: $remote->binding, expectedCredentialDispatch: $remote->credentialDispatch,
            verifySource: $remote->sftpVerifier(), additionalPermissions: [GatewayPermission::SshCommandRun]);
    }

    private function exitCode(User $user, Target $target, string $id, SshJobRemoteIdentity $remote): ?int
    {
        try {
            $file = $this->readJobFile($user, $target, $id, 'exit-code', 0, 8, $remote);
            $value = trim((string) base64_decode((string) $file['data'], true));
            if (preg_match('/^[0-9]{1,3}$/D', $value) === 1 && (int) $value <= 255) {
                return (int) $value;
            }
        } catch (SshTargetConnectionException $exception) {
            if (! $this->isMissingJobOutput($exception)) {
                throw $exception;
            }
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

    private function recoverStaleUnlaunched(?int $userId = null, ?string $jobId = null): int
    {
        $stamp = now();

        return DB::table('ssh_command_jobs')->where('status', 'launch_unknown')
            ->where('launch_admitted', false)->whereNotNull('admission_expires_at')
            ->where('admission_expires_at', '<=', $stamp)
            ->when($userId !== null, static fn ($q) => $q->where('user_id', $userId))
            ->when($jobId !== null, static fn ($q) => $q->where('id', $jobId))
            ->update([
                'status' => 'failed', 'terminal_reason' => 'pre_launch_abandoned',
                'expires_at' => $stamp->copy()->addHours($this->settings->sshJobLimits()['retention_hours']),
                'updated_at' => $stamp,
            ]);
    }

    /** @return array<string,mixed> */
    private function summary(?object $row, ?string $remoteReason = null, bool $remoteObserved = false): array
    {
        if ($row === null) {
            throw new SshTargetConnectionException('target_not_found');
        }

        $evidence = [];
        if ($row->launch_observation_ciphertext !== null) {
            try {
                $observation = json_decode(Crypt::decryptString($row->launch_observation_ciphertext), true, 512, JSON_THROW_ON_ERROR);
                $evidence = [
                    'launch_error_code' => $observation['error_code'] ?? null,
                    'launch_diagnostic_reference' => $observation['diagnostic_reference'] ?? null,
                ];
            } catch (Throwable) {
                $evidence = ['launch_evidence_available' => false];
            }
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
            'continuation_available' => $remoteReason === null && ! in_array($row->status, ['unsupported', 'retired'], true)
                && ! ($this->terminal($row) && $row->launch_admitted !== null && ! (bool) $row->launch_admitted),
            'launch_admitted' => $row->launch_admitted === null ? null : (bool) $row->launch_admitted,
            'remote_observed' => $remoteObserved,
            ...$evidence,
            ...$remoteReason === null ? [] : ['remote_error_code' => $remoteReason],
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
        Target $target, string $operation, string $outcome, ?string $code, array $observed = [], ?string $reference = null,
    ): void {
        $this->activity->record($reference ?? CorrelationId::current(), $operation, $outcome, $target, $code, [
            ...($outcome === 'unknown' ? [
                'failure_origin' => 'unknown',
                'failure_stage' => 'operation',
                'effect_unconfirmed' => true,
                'retry_safe' => false,
            ] : []),
            ...$observed,
        ]);
    }
}
