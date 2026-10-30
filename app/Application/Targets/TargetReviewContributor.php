<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use Illuminate\Database\Eloquent\Builder;

/**
 * Optional connector-owned, local-only evidence for the Admin review queue.
 * This filters an already authorized query; it never grants operation rights.
 */
interface TargetReviewContributor
{
    /** @param Builder<Target> $query */
    public function constrainReview(Builder $query): void;
}
