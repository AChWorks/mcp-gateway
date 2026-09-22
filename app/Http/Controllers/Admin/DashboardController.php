<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityFeed;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class DashboardController extends Controller
{
    public function __invoke(Request $request, AccessControl $access, ActivityFeed $activity): View
    {
        Gate::authorize(GatewayPermission::DashboardView->value);

        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $sites = $access->scopeSites(
            Site::query(),
            $user,
            GatewayPermission::SitesView,
        );

        return view('admin.dashboard', [
            'siteCount' => (clone $sites)->count(),
            'connectedCount' => (clone $sites)
                ->where('connection_state', SiteConnectionState::Connected->value)
                ->count(),
            'attentionCount' => (clone $sites)
                ->whereIn('connection_state', [
                    SiteConnectionState::ReconnectRequired->value,
                    SiteConnectionState::Error->value,
                    SiteConnectionState::Reassigning->value,
                ])
                ->count(),
            'recentActivity' => Gate::allows(GatewayPermission::ActivityView->value)
                ? $activity->page($user, 1, 5)['items']
                : [],
        ]);
    }
}
