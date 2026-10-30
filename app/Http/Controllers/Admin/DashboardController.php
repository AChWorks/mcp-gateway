<?php

namespace App\Http\Controllers\Admin;

use App\Application\Admin\TargetConnectorAdmin;
use App\Application\Admin\TargetDashboardOverview;
use App\Domain\Access\GatewayPermission;
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
        TargetDashboardOverview $overview,
        TargetConnectorAdmin $connectors,
        ActivityFeed $activity,
    ): View {
        Gate::authorize(GatewayPermission::DashboardView->value);

        $user = $request->user();
        abort_unless($user instanceof User, 401);

        return view('admin.dashboard', [
            ...$overview->forUser($user),
            'connectorLabels' => $connectors,
            'recentActivity' => Gate::allows(GatewayPermission::ActivityView->value)
                ? $activity->page($user, 1, 10)['items']
                : [],
        ]);
    }
}
