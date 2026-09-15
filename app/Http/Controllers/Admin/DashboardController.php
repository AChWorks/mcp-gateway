<?php

namespace App\Http\Controllers\Admin;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityFeed;
use Illuminate\View\View;

final class DashboardController extends Controller
{
    public function __invoke(ActivityFeed $activity): View
    {
        $sites = Site::query()->get();

        return view('admin.dashboard', [
            'siteCount' => $sites->count(),
            'connectedCount' => $sites
                ->filter(static fn (Site $site): bool => $site->connection_state === SiteConnectionState::Connected)
                ->count(),
            'attentionCount' => $sites
                ->filter(static fn (Site $site): bool => in_array(
                    $site->connection_state,
                    [SiteConnectionState::ReconnectRequired, SiteConnectionState::Error, SiteConnectionState::Reassigning],
                    true,
                ))
                ->count(),
            'recentActivity' => $activity->page(1, 5)['items'],
        ]);
    }
}
