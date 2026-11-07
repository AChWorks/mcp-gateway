<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * Only owner/password-gated controller may change Target transport routes.
 * No outbound operations under a lock; all old SSH jobs become unreplayable.
 */
final readonly class ConnectionRelayTargetBinding
{
    public function __construct(
        private ConnectionRelayRoutes $routes,
        private SshTargetVault $vault,
        private ActivityRecorder $activity,
    ) {}

    public function onRegistration(Target $target, ?string $relayId): void
    {
        $relay = $this->routes->selectedForBinding($relayId);
        if ($relay === null) {
            return;
        }

        // The caller's existing registration transaction owns new Target
        // creation; this only seals the transport binding before credentials.
        DB::table('targets')->where('id', $target->getKey())->update([
            'relay_record_id' => $relay->getKey(),
            'relay_binding_revision' => 1,
        ]);
        $target->refresh();
    }

    public function revision(Target $target): string
    {
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->first();

        return hash('sha256', json_encode([
            (string) $target->getKey(),
            (string) $target->target_id,
            (string) $target->connector_type,
            (string) $target->getRawOriginal('connection_state'),
            (string) $target->getAttribute('relay_record_id'),
            (int) ($target->getAttribute('relay_binding_revision') ?? 0),
            $credential?->getKey(),
            $credential?->encrypted_payload,
        ], JSON_THROW_ON_ERROR));
    }

    public function change(Target $target, string $revision, ?string $relayId): bool
    {
        return DB::transaction(function () use ($target, $revision, $relayId): bool {
            // Match Disable's Relay->Target lock order. An enabled route
            // cannot be disabled between admission and binding commit.
            $relay = $this->routes->selectedForBinding($relayId);
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            if (! hash_equals($this->revision($locked), $revision)) {
                throw new TargetConnectorFailure(__('The Target route changed since this form was opened. Reload the current Target.'), 'route_revision');
            }

            $nextId = $relay?->getKey();
            $currentId = $locked->getAttribute('relay_record_id');
            if ($nextId === $currentId) {
                return false;
            }

            if (! in_array($locked->getAttribute('connection_state'), [
                TargetConnectionState::Disconnected, TargetConnectionState::Error,
            ], true)) {
                throw new TargetConnectorFailure(__('Disconnect and settle the existing Target operation before changing its route.'), 'connection_relay_id');
            }

            $epoch = (int) ($locked->getAttribute('relay_binding_revision') ?? 0);
            if ($epoch >= 4294967295) {
                throw new TargetConnectorFailure(__('The Target Relay revision is exhausted. Do not reuse historical job identities.'), 'route_revision');
            }

            if ($locked->connector_type === 'ssh_direct') {
                $config = SshTargetConfig::query()->where('target_record_id', $locked->getKey())
                    ->lockForUpdate()->firstOrFail();
                // Reverse SSH has its own distinct Owner key publication and
                // listener trust boundary. Never combine it with a Relay.
                if (($config->route_mode ?? 'direct') !== 'direct') {
                    throw new TargetConnectorFailure(__('Revoke and switch the existing Reverse route to Direct before selecting a Relay.'), 'connection_relay_id');
                }
                $credential = TargetCredential::query()->where('target_record_id', $locked->getKey())
                    ->where('connector_type', 'ssh_direct')->where('purpose', SshTargetVault::PURPOSE)
                    ->lockForUpdate()->first();
                if ($credential instanceof TargetCredential) {
                    try {
                        $material = $this->vault->open($locked, $config, $credential);
                        $nextTarget = clone $locked;
                        $nextTarget->setRawAttributes([
                            ...$locked->getAttributes(),
                            'relay_record_id' => $nextId,
                            'relay_binding_revision' => $epoch + 1,
                        ], true);
                        $encrypted = $this->vault->seal(
                            $nextTarget, $config, $material['secret'], $material['passphrase'],
                        );
                    } catch (RuntimeException) {
                        throw new TargetConnectorFailure(__('Stored SSH credentials cannot be safely rebound. Restore the original encryption key.'), 'connection_relay_id');
                    }
                    $credential->forceFill(['encrypted_payload' => $encrypted])->save();
                }

                DB::table('ssh_direct_target_configs')->where('target_record_id', $locked->getKey())->update([
                    'verification_attempt_id' => null,
                    'observed_peer_ip' => null,
                    'observed_at' => null,
                ]);
            } elseif ($locked->connector_type === 'wp_ai_bridge') {
                // Do not move OAuth code/token/refresh/revocation intents to
                // another route, or silently transfer a live bearer secret.
                if (TargetCredential::query()->where('target_record_id', $locked->getKey())->exists()) {
                    throw new TargetConnectorFailure(__('Finish WordPress authorization revocation before changing the connection route.'), 'connection_relay_id');
                }
                foreach ([
                    'wp_ai_bridge_oauth_flows',
                    'wp_ai_bridge_refresh_intents',
                    'wp_ai_bridge_revocation_intents',
                ] as $table) {
                    if (DB::table($table)->where('target_record_id', $locked->getKey())->exists()) {
                        throw new TargetConnectorFailure(__('Resolve the outstanding WordPress OAuth intent before changing the connection route.'), 'connection_relay_id');
                    }
                }
            } else {
                throw new TargetConnectorFailure(__('This connector does not support a Connection Relay.'), 'connection_relay_id');
            }

            // Eloquent's normal model guard intentionally cannot mutate
            // these fields outside this serialized, audited Owner workflow.
            DB::table('targets')->where('id', $locked->getKey())->update([
                'relay_record_id' => $nextId,
                'relay_binding_revision' => $epoch + 1,
                'connection_state' => TargetConnectionState::Disconnected->value,
                'last_error_code' => null,
                'connected_at' => null,
                'last_tested_at' => null,
                'updated_at' => now(),
            ]);
            $this->activity->recordRequired(CorrelationId::current(), 'target-relay-reconfigure', 'success', $locked);

            return true;
        }, 3);
    }
}
