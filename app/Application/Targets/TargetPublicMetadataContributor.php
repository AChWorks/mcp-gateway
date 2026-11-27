<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;

/** Local, non-secret metadata for an already authorized, bounded Target set. */
interface TargetPublicMetadataContributor
{
    /**
     * Key results by immutable Target record ID. Never query remote hosts or
     * select credential material; use batched local reads for the whole set.
     *
     * @param  list<Target>  $targets
     * @return array<string,array<string,mixed>>
     */
    public function publicMetadata(array $targets): array;
}
