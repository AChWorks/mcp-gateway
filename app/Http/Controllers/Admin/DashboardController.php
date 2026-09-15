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
        return view('admin.dashboard', [
            'siteCount' => Site::query()->count(),
            'connectedCount' => Site::query()
                ->where('connection_state', SiteConnectionState::Connected->value)
                ->count(),
            'attentionCount' => Site::query()
                ->whereIn('connection_state', [
                    SiteConnectionState::ReconnectRequired->value,
                    SiteConnectionState::Error->value,
                    SiteConnectionState::Reassigning->value,
                ])
                ->count(),
            'recentActivity' => $activity->page(1, 5)['items'],
        ]);
    }
}
