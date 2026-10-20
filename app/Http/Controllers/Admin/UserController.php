<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Http\Controllers\Controller;
use App\Models\User;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

final class UserController extends Controller
{
    public function index(): View
    {
        Gate::authorize(GatewayPermission::UsersView->value);

        return view('admin.users.index', [
            'users' => User::query()
                ->orderBy('id')
                ->simplePaginate(50),
        ]);
    }

    public function create(): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.users.create', [
            ...$this->formData(),
            'sshDefaultDenials' => array_map(
                static fn (GatewayPermission $permission): string => $permission->value,
                GatewayPermission::sshCapabilities(),
            ),
        ]);
    }

    public function store(
        Request $request,
        AdministratorPasswordConfirmation $confirmation,
        UserAccessManager $access,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);

        $validated = $this->validated($request);
        $validated['email'] = Str::lower(trim((string) $validated['email']));
        $validated['access_enabled'] = $request->boolean('access_enabled');
        if ($request->has('ai_access_enabled')) {
            $validated['ai_access_enabled'] = $request->boolean('ai_access_enabled');
        }
        $this->guardSshUserChanges($request, $validated);

        $user = $access->create(
            $validated,
            $this->deniedPermissions($validated),
            $request->boolean('ssh_permissions_reviewed')
                && $request->boolean('confirm_ssh_permission_changes')
                && $this->isOwner($request)
                && $validated['target_scope_mode'] === TargetScopeMode::Selected->value,
        );

        return redirect()
            ->route('admin.users.edit', ['user' => $user->id])
            ->with('status', __('User created.'));
    }

    public function edit(User $user, UserAccessManager $access): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.users.edit', [
            ...$this->formData(),
            'managedUser' => $user,
            'deniedPermissions' => $access->globalDenials($user),
            'sshPermissionsEditable' => $this->isOwner(request()),
        ]);
    }

    public function update(
        Request $request,
        User $user,
        AdministratorPasswordConfirmation $confirmation,
        UserAccessManager $access,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);

        $validated = $this->validated($request, $user);
        $validated['email'] = Str::lower(trim((string) $validated['email']));
        $validated['access_enabled'] = $request->boolean('access_enabled');
        if ($request->has('ai_access_enabled')) {
            $validated['ai_access_enabled'] = $request->boolean('ai_access_enabled');
        }
        $this->guardSshUserChanges($request, $validated, $user, $access);
        $revokesSshByScope = $user->getAttribute('target_scope_mode') === TargetScopeMode::Selected
            && $validated['target_scope_mode'] === TargetScopeMode::All->value
            && $validated['role'] !== GatewayRole::Owner->value
            && $user->getAttribute('role') !== GatewayRole::Owner;

        try {
            $access->update(
                $user,
                $validated,
                $this->deniedPermissions($validated),
                $request->boolean('ssh_permissions_reviewed')
                    && $request->boolean('confirm_ssh_permission_changes')
                    && $this->isOwner($request)
                    && $validated['target_scope_mode'] === TargetScopeMode::Selected->value,
            );
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'last_owner') {
                return back()
                    ->withInput()
                    ->withErrors([
                        'access_enabled' => __('Create or enable another owner before disabling or demoting the last recoverable owner.'),
                    ]);
            }

            throw $exception;
        }

        return redirect()
            ->route('admin.users.edit', ['user' => $user->id])
            ->with('status', $revokesSshByScope
                ? __('User access updated. All Target scope disables all non-Owner SSH command and SFTP grants.')
                : __('User access updated.'));
    }

    /** @return array<string,mixed> */
    private function validated(Request $request, ?User $user = null): array
    {
        $password = $user instanceof User
            ? ['nullable', 'string', 'max:255', 'confirmed', Password::min(12)->mixedCase()->numbers()->symbols()]
            : ['required', 'string', 'max:255', 'confirmed', Password::min(12)->mixedCase()->numbers()->symbols()];

        return $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => [
                'required',
                'string',
                'email:rfc',
                'max:254',
                Rule::unique('users', 'email')->ignore($user?->id),
            ],
            'password' => $password,
            'role' => ['required', Rule::enum(GatewayRole::class)],
            'target_scope_mode' => ['required', Rule::enum(TargetScopeMode::class)],
            'access_enabled' => ['nullable', 'boolean'],
            'ai_access_enabled' => ['nullable', 'boolean'],
            'denied_permissions' => ['nullable', 'array'],
            'denied_permissions.*' => ['string', Rule::enum(GatewayPermission::class)],
            'confirm_ssh_permission_changes' => ['nullable', 'boolean'],
            'ssh_permissions_reviewed' => ['nullable', 'in:1'],
        ]);
    }

    /**
     * A checked box represents a DENIAL. An unchecked box that removes an
     * SSH denial is an explicit high-trust grant attempt, not a normal
     * by-product of changing the user's name, role or target scope.
     * Older/API callers without the review marker retain default-deny.
     *
     * @param  array<string,mixed>  $validated
     */
    private function guardSshUserChanges(
        Request $request, array $validated, ?User $managedUser = null,
        ?UserAccessManager $access = null,
    ): void {
        if (! $request->boolean('ssh_permissions_reviewed')) {
            return;
        }

        $role = GatewayRole::from((string) $validated['role']);
        if ($role === GatewayRole::Owner) {
            return;
        }

        $available = array_values(array_map(
            static fn (GatewayPermission $permission): string => $permission->value,
            array_filter(
                GatewayPermission::sshCapabilities(),
                static fn (GatewayPermission $permission): bool => $role->allows($permission),
            ),
        ));
        if ($available === []) {
            return;
        }

        $requested = array_values(array_intersect($this->deniedPermissions($validated), $available));
        $prior = $managedUser instanceof User && $access instanceof UserAccessManager
            ? $access->globalDenials($managedUser) : $available;
        $prior = array_values(array_intersect($prior, $available));
        sort($requested);
        sort($prior);
        // Grant attempts on an All-scope account must be rejected explicitly:
        // SSH authority can only be granted on individually selected Targets.
        $attemptedGrant = array_diff($available, $requested) !== [];
        // Changing an existing Selected-scope user to All intentionally
        // revokes every SSH grant in UserAccessManager. Allow that exact
        // unchanged-checkbox transition so a routine scope edit is usable,
        // but do not accept NEW SSH grants on an All-scope account.
        $revokeByScope = $managedUser instanceof User
            && $managedUser->getAttribute('target_scope_mode') === TargetScopeMode::Selected
            && $validated['target_scope_mode'] === TargetScopeMode::All->value
            && $requested === $prior;
        if ($attemptedGrant && $validated['target_scope_mode'] !== TargetScopeMode::Selected->value
            && ! $revokeByScope) {
            throw ValidationException::withMessages([
                'target_scope_mode' => __('SSH can only be granted with Selected Target scope. Uncheck no new SSH denials while using All Target scope.'),
            ]);
        }

        if (($requested !== $prior || $attemptedGrant && (
            $managedUser === null || $managedUser->getAttribute('role')->value !== $role->value
        ))
            && (! $request->boolean('confirm_ssh_permission_changes') || ! $this->isOwner($request))) {
            throw ValidationException::withMessages([
                'confirm_ssh_permission_changes' => __('Review each SSH permission and confirm the changes as Owner before saving. Unchecking a denial may grant remote shell/file access.'),
            ]);
        }
    }

    private function isOwner(Request $request): bool
    {
        $actor = $request->user();

        return $actor !== null && $actor->getAttribute('role') === GatewayRole::Owner;
    }

    /** @param array<string,mixed> $validated
     * @return list<string>
     */
    private function deniedPermissions(array $validated): array
    {
        $values = $validated['denied_permissions'] ?? [];

        return is_array($values)
            ? array_values(array_filter($values, 'is_string'))
            : [];
    }

    /** @return array<string,mixed> */
    private function formData(): array
    {
        return [
            'roles' => GatewayRole::cases(),
            'targetScopeModes' => TargetScopeMode::cases(),
            'permissions' => GatewayPermission::cases(),
        ];
    }
}
