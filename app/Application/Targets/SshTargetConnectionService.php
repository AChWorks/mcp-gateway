<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshConnectionAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;
use Throwable;

final readonly class SshTargetConnectionService
{
    public function __construct(
        private SshTargetVault $vault,
        private SshVerifiedTransport $transport,
        private SshConnectionAdmission $admission,
        private ActivityRecorder $activity,
    ) {}

    /** Authenticates a single pinned connection without running any command. */
    public function test(Target $target): string
    {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
        $credential = TargetCredential::query()
            ->where('target_record_id', $target->getKey())
            ->where('connector_type', 'ssh_direct')
            ->where('purpose', SshTargetVault::PURPOSE)->first();
        if (! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
            throw new SshTargetConnectionException('credential_unavailable');
        }

        try {
            $ip = $this->admission->run((string) $target->getKey(), function () use ($target, $config, $credential): string {
                $material = $this->vault->open($target, $config, $credential);

                return $this->transport->authenticate(
                    $config->endpoint(), SshHostKeyPin::fromLine($config->pinned_host_key),
                    $config->auth_method, $material['secret'], $material['passphrase'],
                );
            });
        } catch (SshTargetConnectionException $exception) {
            if (! in_array($exception->reason, ['connection_busy', 'rate_limited', 'admission_unavailable'], true)) {
                $this->recordFailure($target, $credential, $exception->reason);
            }
            throw $exception;
        } catch (Throwable) {
            $this->recordFailure($target, $credential, 'credential_unavailable');
            throw new SshTargetConnectionException('credential_unavailable');
        }

        // Never keep row locks across TCP, KEX, key verification or login.
        // Late completion may not resurrect a removed/replaced credential.
        DB::transaction(function () use ($target, $credential, $config, $ip): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->first();
            $current = TargetCredential::query()->whereKey($credential->getKey())->first();
            $endpoint = SshTargetConfig::query()->whereKey($config->getKey())->first();
            if (! $locked instanceof Target || ! $current instanceof TargetCredential
                || ! $endpoint instanceof SshTargetConfig
                || ! hash_equals((string) $credential->encrypted_payload, (string) $current->encrypted_payload)
                || ! hash_equals((string) $config->pinned_host_key, (string) $endpoint->pinned_host_key)) {
                throw new SshTargetConnectionException('target_changed');
            }
            $endpoint->forceFill(['observed_peer_ip' => $ip, 'observed_at' => now()])->save();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Connected,
                'last_error_code' => null,
                'last_tested_at' => now(),
                'connected_at' => now(),
                'last_success_at' => now(),
            ])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-login-verify', 'success', $locked);
        });

        return $ip;
    }

    /** Local credential deletion; it does not revoke a remote Unix login. */
    public function disconnect(Target $target): void
    {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }
        DB::transaction(function () use ($target): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            TargetCredential::query()->where('target_record_id', $locked->getKey())
                ->where('connector_type', 'ssh_direct')->delete();
            SshTargetConfig::query()->where('target_record_id', $locked->getKey())
                ->update(['observed_peer_ip' => null, 'observed_at' => null]);
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Disconnected,
                'last_error_code' => null,
                'connected_at' => null,
            ])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-credential-disconnect', 'success', $locked);
        });
    }

    private function recordFailure(Target $target, TargetCredential $credential, string $reason): void
    {
        DB::transaction(function () use ($target, $credential, $reason): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->first();
            $current = TargetCredential::query()->whereKey($credential->getKey())->first();
            if (! $locked instanceof Target || ! $current instanceof TargetCredential
                || ! hash_equals((string) $credential->encrypted_payload, (string) $current->encrypted_payload)) {
                return;
            }
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Error,
                'last_error_code' => $reason,
                'last_tested_at' => now(),
                'last_failure_at' => now(),
                'last_failure_code' => $reason,
            ])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-login-verify', 'failure', $locked, $reason);
        });
    }
}
