<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;

/** Presentation only: existing adapters and AccessControl retain authority. */
interface TargetConnectorAdminPresenter
{
    public function definition(): TargetConnectorAdminDefinition;

    /**
     * Enrich only an already authorized, bounded inventory page using local
     * batched reads. Never call remote systems or adminDetails once per row.
     *
     * @param  list<Target>  $targets
     * @return array<string, array<string, mixed>>
     */
    public function inventory(array $targets): array;

    /**
     * @param  array<string, mixed>  $details
     * @return array<string, mixed>
     */
    public function recovery(Target $target, array $details): array;

    /** @param array<string, mixed> $details */
    public function hasConfiguration(array $details): bool;
}
