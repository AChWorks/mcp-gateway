<?php

namespace App\Application\Admin;

/** Reviewed local view names, never provider- or request-supplied UI. */
final readonly class TargetConnectorAdminDefinition
{
    public function __construct(
        public string $type,
        public string $label,
        public ?string $enrollmentView = null,
        public ?string $configurationView = null,
        public ?string $inventoryIdentityView = null,
        public ?string $inventoryStatusView = null,
        public ?string $detailRowsView = null,
        public ?string $detailActionsView = null,
        public ?string $recoveryActionsView = null,
        public ?string $operationsView = null,
        public ?string $extraView = null,
    ) {}
}
