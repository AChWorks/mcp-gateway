<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\TargetGroupManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\TargetGroup;
use App\Http\Controllers\Controller;
use App\Models\User;
use DomainException;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class TargetGroupUserController extends Controller
{
    public function index(
        Request $request,
        TargetGroup $targetGroup,
        TargetGroupManager $groups,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'page' => ['nullable', 'integer', 'min:1'],
        ]);
        $search = $this->nullableTrim($validated['search'] ?? null);

        $users = User::query()
            ->when($search !== null, function (Builder $query) use ($search): void {
                $query->where(function (Builder $query) use ($search): void {
                    $query
                        ->where('name', 'like', '%'.$search.'%')
                        ->orWhere('email', 'like', '%'.$search.'%');
                });
            })
            ->orderBy('id')
            ->simplePaginate(50)
            ->withQueryString();

        return view('admin.target-groups.users.index', [
            'targetGroup' => $targetGroup,
            'users' => $users,
            'assignments' => $groups->userAssignmentSummaries($targetGroup, $users->items()),
            'search' => $search,
        ]);
    }

    public function edit(
        TargetGroup $targetGroup,
        User $user,
        TargetGroupManager $groups,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.target-groups.users.edit', [
            'targetGroup' => $targetGroup,
            'managedUser' => $user,
            'assigned' => $groups->userIsAssigned($targetGroup, $user),
            'isOwner' => $this->role($user) === GatewayRole::Owner,
        ]);
    }

    public function update(
        Request $request,
        TargetGroup $targetGroup,
        User $user,
        AdministratorPasswordConfirmation $confirmation,
        TargetGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $request->validate(['assigned' => ['nullable', 'boolean']]);

        try {
            $groups->updateUserAssignment($targetGroup, $user, $request->boolean('assigned'));
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'owner_unrestricted') {
                return back()->withErrors([
                    'assigned' => __('Owners remain unrestricted and cannot be assigned to narrowing target groups.'),
                ]);
            }

            throw $exception;
        }

        return redirect()
            ->route('admin.target-groups.users.edit', [
                'targetGroup' => $targetGroup->id,
                'user' => $user->id,
            ])
            ->with('status', __('Target group user assignment updated.'));
    }

    private function role(User $user): GatewayRole
    {
        $role = $user->getAttribute('role');

        return $role instanceof GatewayRole
            ? $role
            : GatewayRole::from((string) $role);
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
