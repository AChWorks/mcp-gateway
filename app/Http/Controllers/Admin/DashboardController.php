<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityFeed;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class DashboardController extends Controller
{
    public function __invoke(
        Request $request,
        AccessControl $access,
        ActivityFeed $activity,
    ): View {
        Gate::authorize(GatewayPermission::DashboardView->value);

        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $targets = $access->scopeTargets(
            Target::query(),
            $user,
            GatewayPermission::TargetsView,
        );

        return view('admin.dashboard', [
            'targetCount' => (clone $targets)->count(),
            'connectedCount' => (clone $targets)
                ->where('connection_state', TargetConnectionState::Connected->value)
                ->count(),
            'attentionCount' => (clone $targets)
                ->whereIn('connection_state', [
                    TargetConnectionState::ReconnectRequired->value,
                    TargetConnectionState::Error->value,
                    TargetConnectionState::Reassigning->value,
                ])
                ->count(),
            'configuredCount' => (clone $targets)
                ->where('connection_state', TargetConnectionState::Disconnected->value)
                ->count(),
            'recentActivity' => Gate::allows(GatewayPermission::ActivityView->value)
                ? $activity->page($user, 1, 5)['items']
                : [],
        ]);
    }
}
