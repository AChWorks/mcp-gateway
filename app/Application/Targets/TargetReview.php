<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use Illuminate\Database\Eloquent\Builder;

final readonly class TargetReview
{
    public function __construct(private TargetConnectorRegistry $connectors) {}

    /** @param Builder<Target> $query
     * @return Builder<Target>
     */
    public function apply(Builder $query): Builder
    {
        return $query->where(function (Builder $review): void {
            $review->whereIn('targets.connection_state', [
                TargetConnectionState::Error->value,
                TargetConnectionState::ReconnectRequired->value,
                TargetConnectionState::Reassigning->value,
            ]);

            // Runtime eligibility has one owner. A connector may add its own
            // persisted recovery evidence without a Dashboard type switch.
            foreach ($this->connectors->types() as $type) {
                $adapter = $this->connectors->forType($type);
                if ($adapter instanceof TargetReviewContributor) {
                    $review->orWhere(function (Builder $connector) use ($adapter, $type): void {
                        $connector->where('targets.connector_type', $type);
                        $adapter->constrainReview($connector);
                    });
                }
            }
        });
    }
}
