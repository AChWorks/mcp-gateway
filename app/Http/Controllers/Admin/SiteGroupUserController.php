<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\SiteGroupManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteGroup;
use App\Http\Controllers\Controller;
use App\Models\User;
use DomainException;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class SiteGroupUserController extends Controller
{
    public function index(
        Request $request,
        SiteGroup $siteGroup,
        SiteGroupManager $groups,
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

        return view('admin.site-groups.users.index', [
            'siteGroup' => $siteGroup,
            'users' => $users,
            'assignments' => $groups->userAssignmentSummaries($siteGroup, $users->items()),
            'search' => $search,
        ]);
    }

    public function edit(
        SiteGroup $siteGroup,
        User $user,
        SiteGroupManager $groups,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.site-groups.users.edit', [
            'siteGroup' => $siteGroup,
            'managedUser' => $user,
            'assigned' => $groups->userIsAssigned($siteGroup, $user),
            'isOwner' => $this->role($user) === GatewayRole::Owner,
        ]);
    }

    public function update(
        Request $request,
        SiteGroup $siteGroup,
        User $user,
        AdministratorPasswordConfirmation $confirmation,
        SiteGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $request->validate(['assigned' => ['nullable', 'boolean']]);

        try {
            $groups->updateUserAssignment($siteGroup, $user, $request->boolean('assigned'));
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'owner_unrestricted') {
                return back()->withErrors([
                    'assigned' => __('Owners remain unrestricted and cannot be assigned to narrowing site groups.'),
                ]);
            }

            throw $exception;
        }

        return redirect()
            ->route('admin.site-groups.users.edit', [
                'siteGroup' => $siteGroup->id,
                'user' => $user->id,
            ])
            ->with('status', __('Site group user assignment updated.'));
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
