<?php

namespace App\Http\Controllers\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Support\CorrelationId;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

final class TargetOperationsController extends Controller
{
    public function update(Request $request, string $target, ActivityRecorder $activity): RedirectResponse
    {
        // A scalar route parameter prevents Laravel implicit model binding
        // from resolving Target existence BEFORE the Owner-only gate. All
        // non-Owners receive 403 for both existing and nonexistent IDs.
        abort_unless((string) $request->user()?->getRawOriginal('role') === GatewayRole::Owner->value, 403);
        $target = Target::query()->where('target_id', $target)->firstOrFail();
        Gate::authorize(GatewayPermission::TargetsView->value, $target);
        $validated = $request->validate([
            'state' => ['required', Rule::in(['paused', 'enabled'])],
        ]);
        $paused = $validated['state'] === 'paused';

        DB::transaction(static function () use ($target, $activity, $paused): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            if ((bool) $locked->operations_paused === $paused) {
                return; // Idempotent repeated Owner submission.
            }

            $locked->forceFill(['operations_paused' => $paused])->save();
            $activity->recordRequired(
                CorrelationId::current(),
                $paused ? 'target-operations-pause' : 'target-operations-resume',
                'success',
                $locked,
            );
        });

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', $paused
                ? __('Target operations paused. Connection, credentials and permissions are preserved.')
                : __('Target operations resumed using the saved connection and permissions.'));
    }
}
