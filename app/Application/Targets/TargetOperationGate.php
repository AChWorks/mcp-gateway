<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;

/**
 * A fresh, per-remote-stage pause fence. A Target removed mid-operation also
 * fails closed. Perform authorization before revealing any paused status.
 */
final class TargetOperationGate
{
    public static function isPaused(Target $target): bool
    {
        return ! Target::query()->whereKey($target->getKey())
            ->where('operations_paused', false)->exists();
    }
}
