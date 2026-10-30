<?php

namespace App\Application\Admin;

use App\Application\Access\AccessControl;
use App\Application\Targets\TargetReview;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Models\User;

final readonly class TargetDashboardOverview
{
    public const REVIEW_LIMIT = 5;

    public function __construct(
        private AccessControl $access,
        private TargetReview $review,
        private TargetConnectorAdmin $connectors,
    ) {}

    /**
     * Local, scoped and bounded. No connector detail/network call per Target.
     *
     * @return array{targetCount:int,connectedCount:int,attentionCount:int,pausedCount:int,lifecycle:list<array{state:string,label:string,count:int}>,connectorBreakdown:list<array{type:string,label:string,count:int}>,reviewTargets:list<Target>}
     */
    public function forUser(User $user): array
    {
        $targets = $this->access->scopeTargets(
            Target::query(),
            $user,
            GatewayPermission::TargetsView,
        );

        // One grouped read supplies the fleet counts, even for large inventories.
        $groups = (clone $targets)
            ->select(['connection_state', 'connector_type'])
            ->selectRaw('COUNT(*) AS aggregate_count')
            ->selectRaw('SUM(CASE WHEN operations_paused = ? THEN 1 ELSE 0 END) AS paused_count', [true])
            ->groupBy('connection_state', 'connector_type')
            ->get();
        $lifecycle = [];
        foreach (TargetConnectionState::cases() as $state) {
            $lifecycle[$state->value] = [
                'state' => $state->value,
                'label' => match ($state) {
                    TargetConnectionState::Disconnected => __('Disconnected'),
                    TargetConnectionState::Pending => __('Pending'),
                    TargetConnectionState::Connected => __('Connected'),
                    TargetConnectionState::Reassigning => __('Reassigning'),
                    TargetConnectionState::ReconnectRequired => __('Reconnect required'),
                    TargetConnectionState::Error => __('Error'),
                },
                'count' => 0,
            ];
        }

        $count = 0;
        $paused = 0;
        $byConnector = [];
        foreach ($groups as $group) {
            $amount = (int) $group->getAttribute('aggregate_count');
            $state = (string) $group->getRawOriginal('connection_state');
            $count += $amount;
            $paused += (int) $group->getAttribute('paused_count');
            $lifecycle[$state]['count'] += $amount;
            $type = (string) $group->connector_type;
            $byConnector[$type] = ($byConnector[$type] ?? 0) + $amount;
        }
        ksort($byConnector);
        $connectorBreakdown = [];
        foreach ($byConnector as $type => $amount) {
            $connectorBreakdown[] = [
                'type' => $type,
                'label' => $this->connectors->label($type),
                'count' => $amount,
            ];
        }

        // COUNT and list share exactly the same OR predicate. EXISTS avoids
        // duplicates when a lifecycle failure has several recovery intents.
        $needsReview = $this->review->apply(clone $targets);
        $attentionCount = (clone $needsReview)->count();
        $reviewTargets = $needsReview->select([
            'targets.id',
            'targets.target_id',
            'targets.display_name',
            'targets.connector_type',
            'targets.connection_state',
            'targets.operations_paused',
            'targets.last_failure_at',
            'targets.last_failure_code',
            'targets.last_tested_at',
            'targets.last_success_at',
        ])->orderBy('targets.display_name')->orderBy('targets.target_id')
            ->limit(self::REVIEW_LIMIT)->get()->all();

        return [
            'targetCount' => $count,
            'connectedCount' => $lifecycle[TargetConnectionState::Connected->value]['count'],
            'attentionCount' => $attentionCount,
            'pausedCount' => $paused,
            'lifecycle' => array_values($lifecycle),
            'connectorBreakdown' => $connectorBreakdown,
            'reviewTargets' => $reviewTargets,
        ];
    }
}
