<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\TargetGroupManager;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetGroup;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

final class TargetGroupTargetController extends Controller
{
    public function index(
        Request $request,
        TargetGroup $targetGroup,
        TargetInventory $inventory,
        TargetGroupManager $groups,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $actor = $request->user();
        abort_unless($actor instanceof User, 401);

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'connection_state' => ['nullable', 'string', Rule::enum(TargetConnectionState::class)],
            'page' => ['nullable', 'integer', 'min:1'],
        ]);
        $search = $this->nullableTrim($validated['search'] ?? null);
        $connectionState = $this->nullableTrim($validated['connection_state'] ?? null);
        $page = (int) ($validated['page'] ?? 1);
        $inventoryPage = $inventory->adminPage($actor, $page, $search, $connectionState);
        $targets = $inventoryPage['items'];
        $baseQuery = array_filter([
            'search' => $search,
            'connection_state' => $connectionState,
        ], static fn (mixed $value): bool => $value !== null && $value !== '');

        return view('admin.target-groups.targets.index', [
            'targetGroup' => $targetGroup,
            'targets' => $targets,
            'memberships' => $groups->targetMembershipSummaries($targetGroup, $targets),
            'pagination' => [
                'page' => $inventoryPage['page'],
                'previous_url' => $page > 1
                    ? route('admin.target-groups.targets.index', [
                        'targetGroup' => $targetGroup->id,
                        ...$baseQuery,
                        'page' => $page - 1,
                    ])
                    : null,
                'next_url' => $inventoryPage['has_more']
                    ? route('admin.target-groups.targets.index', [
                        'targetGroup' => $targetGroup->id,
                        ...$baseQuery,
                        'page' => $page + 1,
                    ])
                    : null,
            ],
            'filters' => [
                'search' => $search,
                'connection_state' => $connectionState,
            ],
            'connectionStates' => TargetConnectionState::cases(),
        ]);
    }

    public function edit(
        TargetGroup $targetGroup,
        Target $target,
        TargetGroupManager $groups,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.target-groups.targets.edit', [
            'targetGroup' => $targetGroup,
            'target' => $target,
            'assigned' => $groups->targetIsAssigned($targetGroup, $target),
        ]);
    }

    public function update(
        Request $request,
        TargetGroup $targetGroup,
        Target $target,
        AdministratorPasswordConfirmation $confirmation,
        TargetGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $request->validate(['assigned' => ['nullable', 'boolean']]);

        $groups->updateTargetMembership($targetGroup, $target, $request->boolean('assigned'));

        return redirect()
            ->route('admin.target-groups.targets.edit', [
                'targetGroup' => $targetGroup->id,
                'target' => $target->target_id,
            ])
            ->with('status', __('Target group membership updated.'));
    }

    private function nullableTrim(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
