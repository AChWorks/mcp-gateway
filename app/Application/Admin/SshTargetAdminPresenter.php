<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetIdentity;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;

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
            detailRowsView: 'admin.targets.connectors.ssh.detail-rows',
            detailActionsView: 'admin.targets.connectors.ssh.detail-actions',
            extraView: 'admin.targets.connectors.ssh.file-exchange',
            validationMessages: [
                'connection_relay_id.prohibited_if' => __('This connection method does not support a Relay.'),
            ],
        );
    }

    public function safeOldInputFields(): array
    {
        // ssh_host_key is the server's PUBLIC pin; no login secrets are flashed.
        return [
            'ssh_host', 'ssh_port', 'ssh_username', 'ssh_host_key',
            'ssh_auth_method', 'ssh_trust_confirmed', 'ssh_route_mode',
            'ssh_reverse_port', 'ssh_tunnel_identity',
        ];
    }

    public function registrationStatus(): string
    {
        return __('SSH Target registered with encrypted credentials and an out-of-band host-key pin. Authentication has NOT yet been verified.');
    }

    public function details(Target $target): array
    {
        $id = $target->getKey();
        $config = SshTargetConfig::query()->where('target_record_id', $id)->first();

        return [
            'sshConfig' => $config,
            'managedReverse' => SshManagedReverseEnrollment::query()->where('target_record_id', $id)->first(),
            'sshFingerprint' => $config instanceof SshTargetConfig
                ? SshHostKeyPin::fromLine($config->pinned_host_key)->fingerprint()
                : null,
            'sshHasCredential' => TargetCredential::query()
                ->where('target_record_id', $id)->where('connector_type', 'ssh_direct')
                ->where('purpose', SshTargetVault::PURPOSE)->exists(),
        ];
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
                ? __('SSH authorization stored') : __('SSH connection needs attention'),
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
