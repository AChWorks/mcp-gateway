<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetConfig;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetVault;

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
            validationMessages: ArvanApiTargetFormCopy::messages(),
            validationAttributes: ArvanApiTargetFormCopy::attributes(),
        );
    }

    public function safeOldInputFields(): array
    {
        return ['api_base_url', 'api_spec_url', 'api_probe_path'];
    }

    public function registrationStatus(): string
    {
        return __('ArvanCloud API Target saved with an encrypted key. Use the unauthenticated HTTPS endpoint check now, or configure an optional known read-only GET probe to verify the key.');
    }

    public function details(Target $target): array
    {
        return [
            'arvanConfig' => ArvanApiTargetConfig::query()->where('target_record_id', $target->getKey())->first(),
            'arvanHasCredential' => TargetCredential::query()->where('target_record_id', $target->getKey())
                ->where('connector_type', 'arvancloud')->where('purpose', ArvanApiTargetVault::PURPOSE)->exists(),
        ];
    }

    public function inventory(array $targets): array
    {
        return [];
    }

    public function recovery(Target $target, array $details): array
    {
        $verified = (string) $target->getRawOriginal('connection_state') === TargetConnectionState::Connected->value;

        return [
            'title' => $verified ? __('ArvanCloud API last verified') : __('ArvanCloud API needs verification'),
            'description' => __('ArvanCloud connection state records only successful authenticated GET verification. A disconnected state after changing the API root, key or probe does not prove other authorized API calls fail. A separate HTTPS HEAD check uses no key and never changes authentication state.'),
            'reachability' => $target->last_tested_at === null
                ? __('No authenticated GET verification has been recorded for this Target.')
                : __('Recorded GET probe time (may predate the current API settings): :time', ['time' => (string) $target->last_tested_at]),
            'authorization' => __('Machine User key presence is shown below; authenticated requests require a saved key and appropriate provider-side API scopes.'),
            'operation' => __('API requests use this exact registered Target. Target Pause prevents new requests.'),
            'history' => $target->last_error_code === null ? null
                : __('Recorded diagnostic: :code', ['code' => $target->last_error_code]),
            'tone' => $verified ? 'neutral' : 'caution',
            'canFinish' => false, 'canCancel' => false, 'needsExternalProof' => false,
        ];
    }

    public function hasConfiguration(array $details): bool
    {
        return ($details['arvanConfig'] ?? null) !== null;
    }
}
