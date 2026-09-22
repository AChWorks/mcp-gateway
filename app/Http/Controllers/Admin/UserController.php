<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Http\Controllers\Controller;
use App\Models\User;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
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

        return view('admin.users.create', $this->formData());
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

        $user = $access->create(
            $validated,
            $this->deniedPermissions($validated),
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

        try {
            $access->update(
                $user,
                $validated,
                $this->deniedPermissions($validated),
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
            'site_scope_mode' => ['required', Rule::enum(SiteScopeMode::class)],
            'access_enabled' => ['nullable', 'boolean'],
            'denied_permissions' => ['nullable', 'array'],
            'denied_permissions.*' => ['string', Rule::enum(GatewayPermission::class)],
        ]);
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
            'siteScopeModes' => SiteScopeMode::cases(),
            'permissions' => GatewayPermission::cases(),
        ];
    }
}
