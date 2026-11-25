<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;

/**
 * Only a scoped Target configuration/password-gated controller may change Target transport routes.
 * No outbound operations under a lock; all old SSH jobs become unreplayable.
 */
final readonly class ConnectionRelayTargetBinding
{
    public function __construct(
        private ConnectionRelayRoutes $routes,
        private ActivityRecorder $activity,
        private TargetConnectorRegistry $connectors,
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

        return TargetConfigurationRevision::make($target, [], $credential);
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

            if (! TargetConnectorRegistry::supports($locked->connector_type)) {
                throw new TargetConnectorFailure(__('The Target connector is not available.'), 'connection_relay_id');
            }
            // Reassignment is a shared lifecycle transition. Ordinary pending
            // connector work is handled by the adapter under this same lock.
            if ($locked->getAttribute('connection_state') === TargetConnectionState::Reassigning) {
                throw new TargetConnectorFailure(__('Settle the existing connection transition before changing its route.'), 'connection_relay_id');
            }

            $epoch = (int) ($locked->getAttribute('relay_binding_revision') ?? 0);
            if ($epoch >= 4294967295) {
                throw new TargetConnectorFailure(__('The Target Relay revision is exhausted. Do not reuse historical job identities.'), 'route_revision');
            }

            $this->applyBinding($locked, $nextId, $epoch + 1, false);

            return true;
        }, 3);
    }

    /**
     * The Relay administrator holds the Relay and Target locks. Disabling
     * cannot be prevented by an exhausted epoch or an unresolved connector
     * transition; the disabled route itself prevents new network dispatch.
     */
    public function disableBoundTarget(Target $locked): void
    {
        $epoch = (int) $locked->relay_binding_revision;
        $this->applyBinding(
            $locked, $locked->getAttribute('relay_record_id'), min(4294967295, $epoch + 1), true,
        );
    }

    private function applyBinding(Target $locked, ?string $relayId, int $epoch, bool $disabling): void
    {
        $next = clone $locked;
        $next->setRawAttributes([
            ...$locked->getAttributes(),
            'relay_record_id' => $relayId,
            'relay_binding_revision' => $epoch,
        ], true);

        // A connector contributes only its real protocol-specific lifecycle
        // work. The common route mutation and fencing have exactly one owner.
        $adapter = $this->connectors->availableForTarget($locked);
        if ($adapter instanceof TargetRelayBindingContributor) {
            $adapter->prepareRelayBindingChange($locked, $next, $disabling);
        }

        DB::table('targets')->where('id', $locked->getKey())->update([
            'relay_record_id' => $relayId,
            'relay_binding_revision' => $epoch,
            'connection_state' => $disabling ? TargetConnectionState::Error->value : TargetConnectionState::Disconnected->value,
            'last_error_code' => $disabling ? 'relay_disabled' : null,
            'connected_at' => null,
            'last_tested_at' => null,
            ...($disabling ? [] : [
                'last_success_at' => null,
                'last_failure_at' => null,
                'last_failure_code' => null,
            ]),
            'updated_at' => now(),
        ]);
        $this->activity->recordRequired(CorrelationId::current(),
            $disabling ? 'target-relay-disabled' : 'target-relay-reconfigure', 'success', $locked);
    }
}
