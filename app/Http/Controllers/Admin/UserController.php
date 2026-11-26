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
        if ($request->has('self_created_target_access')) {
            $validated['self_created_target_access'] = $request->boolean('self_created_target_access');
        }
        $this->guardCreatorScopeSelection($validated);
        $this->guardSshUserChanges($request, $validated);

        $user = $access->create(
            $validated,
            $this->deniedPermissions($validated),
            $request->boolean('ssh_permissions_reviewed')
                && $request->boolean('confirm_ssh_permission_changes')
                && $this->isOwner($request),
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
        $this->guardPersistableDenyChoices($validated, $user, $access);
        $validated['email'] = Str::lower(trim((string) $validated['email']));
        $validated['access_enabled'] = $request->boolean('access_enabled');
        if ($request->has('ai_access_enabled')) {
            $validated['ai_access_enabled'] = $request->boolean('ai_access_enabled');
        }
        if ($request->has('self_created_target_access')) {
            $validated['self_created_target_access'] = $request->boolean('self_created_target_access');
        }
        $this->guardCreatorScopeSelection($validated);
        $this->guardSshUserChanges($request, $validated, $user, $access);

        try {
            $access->update(
                $user,
                $validated,
                $this->deniedPermissions($validated),
                $request->boolean('ssh_permissions_reviewed')
                    && $request->boolean('confirm_ssh_permission_changes')
                    && $this->isOwner($request),
            );
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'ssh_scope_review_required') {
                throw ValidationException::withMessages([
                    'confirm_ssh_permission_changes' => __('Expanding to All Targets while SSH is granted requires explicit Owner confirmation. Review the SSH permissions or deny them before saving.'),
                ]);
            }
            if ($exception->getMessage() === 'last_owner') {
                // Explicit withInput() bypasses Laravel's exception-handler
                // dontFlash filter. Keep only non-secret User draft controls:
                // the Admin one-use feedback middleware also transports old
                // input, so passwords must never enter session flash.
                return back()
                    ->withInput($request->only([
                        'name', 'email', 'role', 'target_scope_mode',
                        'access_enabled', 'ai_access_enabled', 'self_created_target_access', 'denied_permissions',
                        'ssh_permissions_reviewed', 'confirm_ssh_permission_changes',
                    ]))
                    ->withErrors([
                        'access_enabled' => __('Create or enable another owner before disabling or demoting the last recoverable owner.'),
                    ]);
            }

            throw $exception;
        }

        return redirect()
            ->route('admin.users.edit', ['user' => $user->id])
            ->with('status', __('User access updated.'));
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
            'self_created_target_access' => ['nullable', 'boolean'],
            'denied_permissions' => ['nullable', 'array'],
            'denied_permissions.*' => ['string', Rule::enum(GatewayPermission::class)],
            'confirm_ssh_permission_changes' => ['nullable', 'boolean'],
            'ssh_permissions_reviewed' => ['nullable', 'in:1'],
        ]);
    }

    /** @param array<string,mixed> $values */
    private function guardCreatorScopeSelection(array $values): void
    {
        if (($values['role'] ?? null) === GatewayRole::Owner->value
            && (bool) ($values['self_created_target_access'] ?? false)) {
            throw ValidationException::withMessages([
                'self_created_target_access' => __('Owner accounts already reach every Target. Leave the optional self-created Target access setting disabled.'),
            ]);
        }
    }

    /**
     * The editor renders the full permission catalog for role changes, but
     * the access engine stores only Deny choices allowed by the selected
     * role. Never claim a successful save while silently dropping checked
     * choices (including unrestricted Owner restrictions).
     *
     * @param  array<string,mixed>  $validated
     */
    private function guardPersistableDenyChoices(
        array $validated, User $user, UserAccessManager $access,
    ): void {
        // Previously saved checks may become outside a *new* role on a
        // downgrade/Owner promotion. Let existing role normalization handle
        // those unchanged choices. Reject newly checked impossible choices
        // rather than saying they were saved.
        $newChoices = array_values(array_diff(
            $this->deniedPermissions($validated),
            $access->globalDenials($user),
        ));
        if ($newChoices === []) {
            return;
        }

        $role = GatewayRole::from((string) $validated['role']);
        if ($role === GatewayRole::Owner) {
            throw ValidationException::withMessages([
                'denied_permissions' => __('Owner accounts cannot save new global Deny restrictions. Uncheck newly selected Deny choices before saving; no changes were applied.'),
            ]);
        }

        $unsupported = array_values(array_unique(array_filter(
            $newChoices,
            static fn (string $key): bool => ! $role->allows(GatewayPermission::from($key)),
        )));
        if ($unsupported !== []) {
            sort($unsupported);
            throw ValidationException::withMessages([
                'denied_permissions' => __('These Deny choices are already outside the selected role and cannot be saved as global restrictions: :permissions. Uncheck them or choose a role that allows those capabilities. No changes were applied.', [
                    'permissions' => implode(', ', $unsupported),
                ]),
            ]);
        }
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
        // A permission newly available after a role change starts denied.
        if ($managedUser instanceof User) {
            $previousRole = $managedUser->getAttribute('role');
            foreach ($available as $permission) {
                if ($previousRole === GatewayRole::Owner || ! $previousRole->allows(GatewayPermission::from($permission))) {
                    $prior[] = $permission;
                }
            }
        }
        $grants = array_diff($available, $requested);
        $addsGrant = array_intersect($grants, $prior) !== [];
        $expandsScope = $managedUser instanceof User
            && $managedUser->getAttribute('target_scope_mode') === TargetScopeMode::Selected
            && $validated['target_scope_mode'] === TargetScopeMode::All->value;

        if (($addsGrant || ($expandsScope && $grants !== []))
            && (! $request->boolean('confirm_ssh_permission_changes') || ! $this->isOwner($request))) {
            throw ValidationException::withMessages([
                'confirm_ssh_permission_changes' => __('Review SSH permissions and confirm the grant as Owner before saving. All Targets includes current and future SSH Targets unless explicitly denied.'),
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
