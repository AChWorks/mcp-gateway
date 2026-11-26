<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\Relay\ConnectionRelayUnavailable;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Support\CorrelationId;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;

/**
 * Only a scoped Target configuration/password-gated controller may change Target transport routes.
 * No outbound operations under a lock; all old SSH jobs become unreplayable.
 */
final readonly class TargetTransportBinding
{
    public function __construct(
        private ConnectionRelayRoutes $routes,
        private ActivityRecorder $activity,
    ) {}

    public function onRegistration(Target $target, ?string $relayId): void
    {
        $relay = $this->routes->selectedForBinding($relayId);
        if ($relay !== null) {
            $this->applyBinding($target, (string) $relay->getKey(), null, null, 1, 'target-relay-reconfigure');
        }
    }

    public function revision(Target $target): string
    {
        // A route edit is independent of credential rotation, OAuth flows
        // and connector health. Fence only the exact Target and route.
        return hash('sha256', json_encode([
            (string) $target->getKey(),
            $target->getAttribute('relay_record_id'),
            $target->reverse_listener_port,
            $target->reverse_tunnel_identity,
            (int) $target->transport_revision,
        ], JSON_THROW_ON_ERROR));
    }

    public function change(Target $target, string $revision, ?string $relayId): bool
    {
        return DB::transaction(function () use ($target, $revision, $relayId): bool {
            // Match Disable's Relay->Target lock order. An enabled route
            // cannot be disabled between admission and binding commit.
            $relay = $this->routes->selectedForBinding($relayId, allowDisabled: true);
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            if (! hash_equals($this->revision($locked), $revision)) {
                throw new TargetConnectorFailure(__('The Target route changed since this form was opened. Reload the current Target.'), 'route_revision');
            }

            $nextId = $relay?->getKey();
            $currentId = $locked->getAttribute('relay_record_id');
            if ($nextId === $currentId) {
                return false;
            }

            if ($relay !== null && ! $relay->enabled) {
                throw new ConnectionRelayUnavailable;
            }
            // A fixed local Reverse listener and a SOCKS intermediary are
            // alternative paths to the same endpoint, not stacked routes.
            // Inspect the actual configured path, never the Target type.
            if ($nextId !== null && $locked->usesReverseRoute() && SshManagedReverseEnrollment::query()
                ->where('target_record_id', $locked->getKey())
                ->where(static fn ($query) => $query->where('state', '!=', 'revoked')->orWhere('publication_pending', true))->exists()) {
                throw new TargetConnectorFailure(__('Revoke and reconcile the previous managed Reverse control route before switching. Target credentials are preserved.'), 'connection_relay_id');
            }

            $epoch = (int) ($locked->getAttribute('transport_revision') ?? 0);
            if ($epoch >= 4294967295) {
                throw new TargetConnectorFailure(__('The Target transport revision is exhausted. Do not reuse historical job identities.'), 'route_revision');
            }

            $this->applyBinding($locked, $nextId, null, null, $epoch + 1, 'target-relay-reconfigure');

            return true;
        }, 3);
    }

    /**
     * The route administrator holds the provider and Target locks. Disabling
     * cannot be prevented by an exhausted epoch or an unresolved connector
     * transition; the disabled route itself prevents new network dispatch.
     */
    public function disableBoundTarget(Target $locked): void
    {
        $epoch = (int) $locked->transport_revision;
        $this->applyBinding(
            $locked, $locked->getAttribute('relay_record_id'), $locked->reverse_listener_port,
            $locked->reverse_tunnel_identity, min(4294967295, $epoch + 1),
            $locked->usesReverseRoute() ? 'target-reverse-disabled' : 'target-relay-disabled',
        );
    }

    /**
     * Called under the managed gateway row lock, before committing the new
     * control intent. Manual Reverse and Direct/Relay Targets are unaffected.
     */
    public function changeManagedReverseAvailability(bool $enabled): void
    {
        $targets = Target::query()->whereExists(static function (Builder $query): void {
            $query->selectRaw('1')->from((new SshManagedReverseEnrollment)->getTable())
                ->whereColumn('target_record_id', 'targets.id')
                ->where('state', '!=', 'revoked')
                ->whereColumn('listener_port', 'targets.reverse_listener_port')
                ->whereColumn('tunnel_identity', 'targets.reverse_tunnel_identity');
        })->orderBy('id')->lockForUpdate()->get();
        foreach ($targets as $target) {
            if ($enabled) {
                if ((int) $target->transport_revision >= 4294967295) {
                    throw new TargetConnectorFailure(__('The Target transport revision is exhausted.'), 'enabled');
                }
            } else {
                $this->disableBoundTarget($target);
            }
        }
    }

    /** Caller owns the Target lock and has validated/allocated the listener. */
    public function changeReverseLocked(Target $locked, ?int $port, ?string $identity, bool $forceFence = false): void
    {
        if (($port === null) !== ($identity === null)) {
            throw new TargetConnectorFailure(__('Conflicting network paths.'), 'ssh_route_mode');
        }
        if (! $forceFence && $port === $locked->reverse_listener_port && $identity === $locked->reverse_tunnel_identity) {
            return;
        }
        $epoch = (int) $locked->transport_revision;
        if ($epoch >= 4294967295 && ! $forceFence) {
            throw new TargetConnectorFailure(__('The Target transport revision is exhausted.'), 'route_revision');
        }
        $this->applyBinding($locked, $port !== null ? null : $locked->getAttribute('relay_record_id'), $port, $identity, min(4294967295, $epoch + 1), 'target-reverse-reconfigure');
    }

    private function applyBinding(Target $locked, ?string $relayId, ?int $port, ?string $identity, int $epoch, string $operation): void
    {
        // Shared transport mutation only. Authentication and the outcome of
        // already dispatched protocol operations belong to the Target, not
        // to the path they happened to use.
        DB::table('targets')->where('id', $locked->getKey())->update([
            'relay_record_id' => $relayId,
            'transport_revision' => $epoch,
            'reverse_listener_port' => $port,
            'reverse_tunnel_identity' => $identity,
            'last_tested_at' => null,
            'updated_at' => now(),
        ]);
        $this->activity->recordRequired(CorrelationId::current(),
            $operation, 'success', $locked);
        $locked->refresh();
    }
}
