<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Sites\SiteHealth;
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
    public function __invoke(
        Request $request,
        AccessControl $access,
        ActivityFeed $activity,
        SiteHealth $health,
    ): View {
        Gate::authorize(GatewayPermission::DashboardView->value);

        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $sites = $access->scopeSites(
            Site::query(),
            $user,
            GatewayPermission::SitesView,
        );

        $staleCutoff = $health->staleCutoff();

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
            'staleCount' => (clone $sites)
                ->where('connection_state', SiteConnectionState::Connected->value)
                ->where(function ($query) use ($staleCutoff): void {
                    $query
                        ->where(function ($query) use ($staleCutoff): void {
                            $query->whereNull('last_success_at')
                                ->orWhere('last_success_at', '<', $staleCutoff);
                        })
                        ->where(function ($query) use ($staleCutoff): void {
                            $query->whereNull('connected_at')
                                ->orWhere('connected_at', '<', $staleCutoff);
                        })
                        ->where(function ($query) use ($staleCutoff): void {
                            $query->whereNotNull('last_error_code')
                                ->orWhereNull('last_tested_at')
                                ->orWhere('last_tested_at', '<', $staleCutoff);
                        });
                })
                ->count(),
            'recentActivity' => Gate::allows(GatewayPermission::ActivityView->value)
                ? $activity->page($user, 1, 5)['items']
                : [],
        ]);
    }
}
