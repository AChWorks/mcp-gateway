<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityFeed;
use Illuminate\Http\Request;
use Illuminate\View\View;

final class ActivityController extends Controller
{
    public function __invoke(Request $request, ActivityFeed $activity): View
    {
        $validated = $request->validate([
            'page' => ['nullable', 'integer', 'min:1'],
            'site_id' => ['nullable', 'string', 'max:128'],
            'operation' => ['nullable', 'string', 'max:128'],
        ]);

        $siteId = isset($validated['site_id']) ? trim((string) $validated['site_id']) : null;
        $operation = isset($validated['operation']) ? trim((string) $validated['operation']) : null;
        $siteId = $siteId === '' ? null : $siteId;
        $operation = $operation === '' ? null : $operation;

        return view('admin.activity.index', [
            'feed' => $activity->page(
                isset($validated['page']) ? (int) $validated['page'] : 1,
                25,
                $siteId,
                $operation,
            ),
            'filters' => [
                'site_id' => $siteId,
                'operation' => $operation,
            ],
        ]);
    }
}
