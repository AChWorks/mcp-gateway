<?php

namespace App\Application\Batch;

use App\Domain\Targets\Target;

/**
 * Optional connector capability: prove that a deferred Batch still names the
 * same downstream principal, endpoint, credential and trust binding.
 *
 * The connector owns what changes its identity; ordinary token refresh or
 * health observations must not invalidate a durable Batch. A missing/invalid
 * proof prevents dispatch, never falls back to a shared weak identifier.
 */
interface TargetBatchBindingContributor
{
    /**
     * Return binding parts keyed by immutable Target record ID, or null when
     * unbound. Never return credential plaintext or a reusable secret.
     *
     * @param  list<Target>  $targets  Only the already-scoped, selected Targets of this connector
     * @return array<string, list<string>|null>
     */
    public function batchBindingParts(array $targets): array;
}
