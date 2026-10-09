<?php

namespace App\Http\Controllers\Admin;

use App\Domain\Access\GatewayPermission;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityFeed;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class ActivityController extends Controller
{
    public function __invoke(Request $request, ActivityFeed $activity): View
    {
        Gate::authorize(GatewayPermission::ActivityView->value);

        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $validated = $request->validate([
            'page' => ['nullable', 'integer', 'min:1'],
            'target_id' => ['nullable', 'string', 'max:64'],
            'operation' => ['nullable', 'string', 'max:128'],
        ]);

        $targetId = isset($validated['target_id']) ? trim((string) $validated['target_id']) : null;
        $operation = isset($validated['operation']) ? trim((string) $validated['operation']) : null;
        $targetId = $targetId === '' ? null : $targetId;
        $operation = $operation === '' ? null : $operation;

        return view('admin.activity.index', [
            'feed' => $activity->page(
                $user,
                isset($validated['page']) ? (int) $validated['page'] : 1,
                25,
                $targetId,
                $operation,
            ),
            'filters' => [
                'target_id' => $targetId,
                'operation' => $operation,
            ],
        ]);
    }
}
