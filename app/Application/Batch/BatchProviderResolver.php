<?php

namespace App\Application\Batch;

/** Trusted, server-owned provider resolution, never caller-supplied class IDs. */
interface BatchProviderResolver
{
    public function find(string $key): ?TargetBatchOperationProvider;
}
