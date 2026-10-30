<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshTargetIdentity;
use App\Support\TargetRecoveryPresentation;

final class SshTargetAdminPresenter implements TargetConnectorAdminPresenter
{
    public function definition(): TargetConnectorAdminDefinition
    {
        return new TargetConnectorAdminDefinition(
            type: 'ssh_direct',
            label: __('Direct SSH'),
            enrollmentView: 'admin.targets.connectors.ssh.enrollment',
            configurationView: 'admin.targets.connectors.ssh.configuration',
            enrollmentScriptView: 'admin.targets.connectors.ssh.enrollment-script',
            inventoryIdentityView: 'admin.targets.connectors.ssh.inventory-identity',
            inventoryStatusView: 'admin.targets.connectors.ssh.inventory-status',
            detailRowsView: 'admin.targets.connectors.ssh.detail-rows',
            detailActionsView: 'admin.targets.connectors.ssh.detail-actions',
            extraView: 'admin.targets.connectors.ssh.file-exchange',
        );
    }

    public function inventory(array $targets): array
    {
        $result = [];
        foreach ($targets as $target) {
            // TargetInventory already projects the authorized page's SSH identity.
            $result[$target->target_id] = [
                'identity' => ! $target->relationLoaded('sshConfig') || $target->getRelation('sshConfig') === null
                    ? null : SshTargetIdentity::safeMetadata($target),
            ];
        }

        return $result;
    }

    public function recovery(Target $target, array $details): array
    {
        return TargetRecoveryPresentation::describe($target);
    }

    public function hasConfiguration(array $details): bool
    {
        return ($details['sshConfig'] ?? null) !== null;
    }
}
