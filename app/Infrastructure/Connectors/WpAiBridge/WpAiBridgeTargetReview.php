<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Domain\Targets\Target;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;

/** Read only the same persisted blockers used by WordPress recovery. */
final readonly class WpAiBridgeTargetReview
{
    /** @param Builder<Target> $query */
    public function constrain(Builder $query): void
    {
        $query->where(function (Builder $pending): void {
            $pending->whereExists(function (QueryBuilder $intent): void {
                $intent->selectRaw('1')->from('wp_ai_bridge_refresh_intents')
                    ->whereColumn('wp_ai_bridge_refresh_intents.target_record_id', 'targets.id');
            })->orWhereExists(function (QueryBuilder $intent): void {
                $intent->selectRaw('1')->from('wp_ai_bridge_revocation_intents')
                    ->whereColumn('wp_ai_bridge_revocation_intents.target_record_id', 'targets.id');
            });
        });
    }
}
