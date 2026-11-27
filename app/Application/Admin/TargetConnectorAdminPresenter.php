<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;

/** Presentation only: existing adapters and AccessControl retain authority. */
interface TargetConnectorAdminPresenter
{
    public function definition(): TargetConnectorAdminDefinition;

    /**
     * Only explicitly replayable non-secret form fields may be flashed to
     * the browser. Unknown fields remain private by default.
     *
     * @return list<string>
     */
    public function safeOldInputFields(): array;

    public function registrationStatus(): string;

    /** @return array<string,mixed> */
    public function details(Target $target): array;

    /**
     * Enrich only an already authorized, bounded inventory page using local
     * batched reads. Never call remote systems or details once per row.
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
