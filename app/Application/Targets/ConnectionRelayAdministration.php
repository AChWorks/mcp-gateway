<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;
use Throwable;

/** Serializes administrative disable with all bound Target epochs. */
final readonly class ConnectionRelayAdministration
{
    public function __construct(
        private SshTargetVault $vault,
        private ActivityRecorder $activity,
    ) {}

    public function disable(ConnectionRelay $relay, int $expectedRevision): bool
    {
        return DB::transaction(function () use ($relay, $expectedRevision): bool {
            $locked = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $locked->lifecycle_revision !== $expectedRevision) {
                throw new TargetConnectorFailure(__('The Relay changed since this form was opened. Reload and review.'), 'relay_revision');
            }
            // A fresh second Disable is a no-op; it must not unnecessarily
            // fence already-disabled Target epochs. A stale revision failed above.
            if (! $locked->enabled) {
                return false;
            }
            if ((int) $locked->configuration_revision >= 4294967295 || (int) $locked->lifecycle_revision >= 4294967295) {
                throw new TargetConnectorFailure(__('The Relay security generation is exhausted. Contact the operator before changing its state.'), 'relay_revision');
            }
            // Disable and advance the host-fingerprint generation atomically
            // with Target fencing. Any old Enable form and attestation is stale.
            DB::table('connection_relays')->where('id', $locked->getKey())->update([
                'enabled' => false,
                'configuration_revision' => (int) $locked->configuration_revision + 1,
                'lifecycle_revision' => (int) $locked->lifecycle_revision + 1,
                'updated_at' => now(),
            ]);

            $targets = Target::query()->where('relay_record_id', $locked->getKey())->lockForUpdate()->get();
            foreach ($targets as $target) {
                $epoch = (int) ($target->getAttribute('relay_binding_revision') ?? 0);
                // Saturation must not prevent a requested disable. Enabling
                // stays prohibited while any bound Target has no fresh epoch.
                $nextEpoch = min(4294967295, $epoch + 1);
                if ($target->connector_type === 'ssh_direct') {
                    $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
                    $credential = TargetCredential::query()->where('target_record_id', $target->getKey())
                        ->where('connector_type', 'ssh_direct')
                        ->where('purpose', SshTargetVault::PURPOSE)->first();
                    if ($config instanceof SshTargetConfig && $credential instanceof TargetCredential) {
                        try {
                            $material = $this->vault->open($target, $config, $credential);
                            $nextTarget = clone $target;
                            $nextTarget->setRawAttributes([
                                ...$target->getAttributes(), 'relay_binding_revision' => $nextEpoch,
                            ], true);
                            $credential->forceFill(['encrypted_payload' => $this->vault->seal(
                                $nextTarget, $config, $material['secret'], $material['passphrase'],
                            )])->save();
                        } catch (Throwable) {
                            // A damaged/unknown old credential must not
                            // prevent disabling the route. It remains
                            // unreadable under the NEW binding, requiring
                            // explicit Owner credential recovery.
                        }
                    }
                    DB::table('ssh_direct_target_configs')->where('target_record_id', $target->getKey())
                        ->update(['verification_attempt_id' => null, 'observed_peer_ip' => null, 'observed_at' => null]);
                }
                DB::table('targets')->where('id', $target->getKey())->update([
                    'relay_binding_revision' => $nextEpoch,
                    'connection_state' => TargetConnectionState::Error->value,
                    'last_error_code' => 'relay_disabled',
                    'connected_at' => null,
                    'last_tested_at' => null,
                    'updated_at' => now(),
                ]);
                $this->activity->recordRequired(
                    CorrelationId::current(), 'target-relay-disabled', 'success', $target,
                );
            }
            $this->activity->recordRequired(CorrelationId::current(), 'connection-relay-disable', 'success');

            return true;
        }, 3);
    }
}
