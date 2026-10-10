<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Persists the latest admitted SSH verification attempt and fences its outcome.
 * The Target row lock is held only for short database transactions, never I/O.
 */
final readonly class SshVerificationState
{
    public function __construct(private ActivityRecorder $activity) {}

    public function begin(Target $target, SshTargetConfig $config, TargetCredential $credential): string
    {
        $attemptId = (string) Str::ulid();

        DB::transaction(function () use ($target, $config, $credential, $attemptId): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->first();
            $currentCredential = TargetCredential::query()->whereKey($credential->getKey())->first();
            $currentConfig = SshTargetConfig::query()->whereKey($config->getKey())->first();
            if (! $this->sameIdentity($locked, $currentConfig, $currentCredential, $target, $config, $credential)) {
                throw new SshTargetConnectionException('target_changed');
            }

            // A later attempt supersedes an older one even if the older PHP
            // worker outlives its finite cache admission lease.
            $currentConfig->forceFill(['verification_attempt_id' => $attemptId])->save();
        });

        return $attemptId;
    }

    public function succeeded(
        Target $target, SshTargetConfig $config, TargetCredential $credential,
        string $attemptId, string $peerIp,
    ): void {
        DB::transaction(function () use ($target, $config, $credential, $attemptId, $peerIp): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->first();
            $currentCredential = TargetCredential::query()->whereKey($credential->getKey())->first();
            $currentConfig = SshTargetConfig::query()->whereKey($config->getKey())->first();
            if (! $this->sameIdentity($locked, $currentConfig, $currentCredential, $target, $config, $credential)) {
                throw new SshTargetConnectionException('target_changed');
            }
            if (! hash_equals($attemptId, (string) $currentConfig->verification_attempt_id)) {
                throw new SshTargetConnectionException('verification_superseded');
            }

            $now = now();
            $currentConfig->forceFill([
                'verification_attempt_id' => null,
                'observed_peer_ip' => $peerIp,
                'observed_at' => $now,
            ])->save();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Connected,
                'last_error_code' => null,
                'last_tested_at' => $now,
                'connected_at' => $now,
                'last_success_at' => $now,
            ])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-login-verify', 'success', $locked);
        });
    }

    public function failed(
        Target $target, SshTargetConfig $config, TargetCredential $credential,
        string $attemptId, string $reason,
    ): void {
        DB::transaction(function () use ($target, $config, $credential, $attemptId, $reason): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->first();
            $currentCredential = TargetCredential::query()->whereKey($credential->getKey())->first();
            $currentConfig = SshTargetConfig::query()->whereKey($config->getKey())->first();
            if (! $this->sameIdentity($locked, $currentConfig, $currentCredential, $target, $config, $credential)
                || ! hash_equals($attemptId, (string) $currentConfig->verification_attempt_id)) {
                // A later attempt, credential replacement or disconnect owns
                // Target health. Suppress stale failure writes and audit.
                return;
            }

            $currentConfig->forceFill(['verification_attempt_id' => null])->save();
            $now = now();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Error,
                'last_error_code' => $reason,
                'last_tested_at' => $now,
                'last_failure_at' => $now,
                'last_failure_code' => $reason,
            ])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-login-verify', 'failure', $locked, $reason);
        });
    }

    private function sameIdentity(
        ?Target $locked, ?SshTargetConfig $currentConfig, ?TargetCredential $currentCredential,
        Target $target, SshTargetConfig $config, TargetCredential $credential,
    ): bool {
        return $locked instanceof Target
            && $locked->connector_type === 'ssh_direct'
            && $currentCredential instanceof TargetCredential
            && $currentConfig instanceof SshTargetConfig
            && (string) $currentCredential->target_record_id === (string) $target->getKey()
            && $currentCredential->connector_type === 'ssh_direct'
            && $currentCredential->purpose === SshTargetVault::PURPOSE
            && (string) $currentConfig->target_record_id === (string) $target->getKey()
            && hash_equals((string) $credential->encrypted_payload, (string) $currentCredential->encrypted_payload)
            && hash_equals((string) $config->pinned_host_key, (string) $currentConfig->pinned_host_key);
    }
}
