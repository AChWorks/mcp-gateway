<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;

/**
 * Connector-owned work needed when the shared outbound route epoch changes.
 * Called under the Target lock, in the same transaction as the new binding.
 * Never dispatch network requests here.
 */
interface TargetRelayBindingContributor
{
    public function prepareRelayBindingChange(Target $current, Target $next, bool $disabling): void;
}
