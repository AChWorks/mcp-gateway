<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;
use App\Support\TargetRecoveryPresentation;

final class ArvanTargetAdminPresenter implements TargetConnectorAdminPresenter
{
    public function definition(): TargetConnectorAdminDefinition
    {
        return new TargetConnectorAdminDefinition(
            type: 'arvancloud',
            label: __('ArvanCloud API'),
            enrollmentView: 'admin.targets.connectors.arvan.enrollment',
            configurationView: 'admin.targets.connectors.arvan.configuration',
            detailRowsView: 'admin.targets.connectors.arvan.detail-rows',
            detailActionsView: 'admin.targets.connectors.arvan.detail-actions',
        );
    }

    public function inventory(array $targets): array
    {
        return [];
    }

    public function recovery(Target $target, array $details): array
    {
        return TargetRecoveryPresentation::describe($target);
    }

    public function hasConfiguration(array $details): bool
    {
        return ($details['arvanConfig'] ?? null) !== null;
    }
}
