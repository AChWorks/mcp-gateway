<?php

namespace App\Application\Admin;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Support\TargetRecoveryPresentation;
use Illuminate\Support\Facades\DB;

final class WordpressTargetAdminPresenter implements TargetConnectorAdminPresenter
{
    public function definition(): TargetConnectorAdminDefinition
    {
        return new TargetConnectorAdminDefinition(
            type: 'wp_ai_bridge',
            label: __('WordPress (WP AI Bridge)'),
            enrollmentView: 'admin.targets.connectors.wordpress.enrollment',
            configurationView: 'admin.targets.connectors.wordpress.configuration',
            inventoryStatusView: 'admin.targets.connectors.wordpress.inventory-status',
            detailRowsView: 'admin.targets.connectors.wordpress.detail-rows',
            detailActionsView: 'admin.targets.connectors.wordpress.detail-actions',
            recoveryActionsView: 'admin.targets.connectors.wordpress.recovery-actions',
            operationsView: 'admin.targets.connectors.wordpress.operations',
        );
    }

    public function inventory(array $targets): array
    {
        if ($targets === []) {
            return [];
        }
        $ids = array_map(static fn (Target $target): string => (string) $target->getKey(), $targets);
        $revocations = DB::table('wp_ai_bridge_revocation_intents')
            ->whereIn('target_record_id', $ids)->get()->keyBy('target_record_id');
        $refreshIds = DB::table('wp_ai_bridge_refresh_intents')
            ->whereIn('target_record_id', $ids)->pluck('target_record_id')->all();
        $configs = DB::table('wp_ai_bridge_target_configs')
            ->whereIn('target_record_id', $ids)
            ->get(['target_record_id', 'metadata_checked_at', 'metadata_reachable'])->keyBy('target_record_id');
        $credentialIds = TargetCredential::query()
            ->whereIn('target_record_id', $ids)->where('connector_type', 'wp_ai_bridge')
            ->where('purpose', 'wordpress_oauth')->pluck('target_record_id')->all();
        $result = [];
        foreach ($targets as $target) {
            $hasCredential = in_array((string) $target->getKey(), $credentialIds, true);
            $recovery = TargetRecoveryPresentation::describe(
                $target, $revocations->get($target->getKey()),
                in_array($target->getKey(), $refreshIds, true), $hasCredential,
                $configs->get($target->getKey()),
            );
            $recovery['credential_present'] = $hasCredential;
            $result[$target->target_id] = ['recovery' => $recovery];
        }

        return $result;
    }

    public function recovery(Target $target, array $details): array
    {
        return TargetRecoveryPresentation::describe(
            $target, $details['revocationIntent'] ?? null,
            $details['refreshPending'] ?? false, $details['hasCredential'] ?? false,
            $details['wpConfig'] ?? null, $details['credentialMetadata'] ?? null,
            $details['oauthFlowPending'] ?? false,
        );
    }

    public function hasConfiguration(array $details): bool
    {
        return ($details['wpConfig'] ?? null) !== null;
    }
}
