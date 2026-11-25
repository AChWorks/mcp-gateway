<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshTargetIdentity;

final class SshTargetAdminPresenter implements TargetConnectorAdminPresenter
{
    public function definition(): TargetConnectorAdminDefinition
    {
        return new TargetConnectorAdminDefinition(
            type: 'ssh_direct',
            label: __('SSH'),
            enrollmentView: 'admin.targets.connectors.ssh.enrollment',
            configurationView: 'admin.targets.connectors.ssh.configuration',
            inventoryIdentityView: 'admin.targets.connectors.ssh.inventory-identity',
            inventoryStatusView: 'admin.targets.connectors.ssh.inventory-status',
            detailRowsView: 'admin.targets.connectors.ssh.detail-rows',
            detailActionsView: 'admin.targets.connectors.ssh.detail-actions',
            extraView: 'admin.targets.connectors.ssh.file-exchange',
            validationMessages: [
                'connection_relay_id.prohibited_if' => __('This connection method does not support a Relay.'),
            ],
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
        return [
            'title' => (string) $target->getRawOriginal('connection_state') === TargetConnectionState::Connected->value
                ? __('SSH connection last verified') : __('SSH connection needs attention'),
            'description' => __('SSH identity and login verification are separate from WordPress OAuth; a previous SSH probe is not a live connection.'),
            'reachability' => __('Inspect SSH host-key and login verification details below.'),
            'authorization' => __('SSH uses stored login credentials, not OAuth revocation.'),
            'operation' => __('No WordPress OAuth operation applies.'),
            'history' => $target->last_error_code === null ? null
                : __('Recorded error (diagnostic, not proof of current reachability): :code', ['code' => $target->last_error_code]),
            'tone' => (string) $target->getRawOriginal('connection_state') === TargetConnectionState::Connected->value ? 'neutral' : 'caution',
            'canFinish' => false, 'canCancel' => false, 'needsExternalProof' => false,
        ];
    }

    public function hasConfiguration(array $details): bool
    {
        return ($details['sshConfig'] ?? null) !== null;
    }
}
