<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;

/** Serializes administrative disable with all bound Target epochs. */
final readonly class ConnectionRelayAdministration
{
    public function __construct(
        private ConnectionRelayTargetBinding $bindings,
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
            if ((int) $locked->lifecycle_revision >= 4294967295) {
                throw new TargetConnectorFailure(__('The Relay revision is exhausted. Contact the operator before changing its state.'), 'relay_revision');
            }
            // Disable the route and invalidate retained Target binding epochs.
            DB::table('connection_relays')->where('id', $locked->getKey())->update([
                'enabled' => false,
                'lifecycle_revision' => (int) $locked->lifecycle_revision + 1,
                'updated_at' => now(),
            ]);

            $targets = Target::query()->where('relay_record_id', $locked->getKey())->lockForUpdate()->get();
            foreach ($targets as $target) {
                $this->bindings->disableBoundTarget($target);
            }
            $this->activity->recordRequired(CorrelationId::current(), 'connection-relay-disable', 'success');

            return true;
        }, 3);
    }
}
