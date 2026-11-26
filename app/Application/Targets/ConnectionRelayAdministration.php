<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;

/** Serializes administrative availability changes with all bound Target epochs. */
final readonly class ConnectionRelayAdministration
{
    public function __construct(
        private TargetTransportBinding $bindings,
        private ActivityRecorder $activity,
    ) {}

    public function setEnabled(ConnectionRelay $relay, int $expectedRevision, bool $enabled): bool
    {
        return DB::transaction(function () use ($relay, $expectedRevision, $enabled): bool {
            $locked = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $locked->lifecycle_revision !== $expectedRevision) {
                throw new TargetConnectorFailure(__('The Relay changed since this form was opened. Reload and review.'), 'relay_revision');
            }
            // Reconciled no-ops never advance provider or Target authority.
            if ((bool) $locked->enabled === $enabled) {
                return false;
            }
            if ((int) $locked->lifecycle_revision >= 4294967295) {
                throw new TargetConnectorFailure(__('The Relay revision is exhausted. Contact the operator before changing its state.'), 'relay_revision');
            }
            // Both availability edges supersede admitted route snapshots.
            DB::table('connection_relays')->where('id', $locked->getKey())->update([
                'enabled' => $enabled,
                'lifecycle_revision' => (int) $locked->lifecycle_revision + 1,
                'updated_at' => now(),
            ]);

            $targets = Target::query()->where('relay_record_id', $locked->getKey())->orderBy('id')->lockForUpdate()->get();
            foreach ($targets as $target) {
                $this->bindings->changeBoundTargetAvailability($target, $enabled);
            }
            $this->activity->recordRequired(CorrelationId::current(), $enabled ? 'connection-relay-enable' : 'connection-relay-disable', 'success');

            return true;
        }, 3);
    }
}
