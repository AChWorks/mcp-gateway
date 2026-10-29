<?php

namespace App\Application\Targets;

/**
 * Optional, connector-owned admission to the shared read-only enrollment probe.
 *
 * Implementing this interface does not grant network access by itself. The
 * connector must use its reviewed transport policy; an unsupported connector
 * is never implicitly probed by an arbitrary URL/host submitted by a client.
 */
interface TargetEnrollmentPreflight
{
    /** @return array<string, array<int, mixed>> */
    public function preflightRules(): array;

    /** @param array<string, mixed> $input */
    public function preflight(array $input): TargetPreflightResult;
}
