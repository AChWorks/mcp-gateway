<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\UserAccessManager;
use App\Application\Sites\SiteInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Http\Controllers\Controller;
use App\Models\User;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

final class UserSiteAccessController extends Controller
{
    public function index(
        Request $request,
        User $user,
        SiteInventory $inventory,
        UserAccessManager $access,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        $actor = $request->user();
        abort_unless($actor instanceof User, 401);

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'connection_state' => ['nullable', 'string', Rule::enum(SiteConnectionState::class)],
            'page' => ['nullable', 'integer', 'min:1'],
        ]);
        $search = $this->nullableTrim($validated['search'] ?? null);
        $connectionState = $this->nullableTrim($validated['connection_state'] ?? null);
        $page = (int) ($validated['page'] ?? 1);

        $inventoryPage = $inventory->adminPage($actor, $page, $search, $connectionState);
        $sites = $inventoryPage['items'];
        $baseQuery = array_filter([
            'search' => $search,
            'connection_state' => $connectionState,
        ], static fn (mixed $value): bool => $value !== null && $value !== '');

        return view('admin.users.sites.index', [
            'managedUser' => $user,
            'sites' => $sites,
            'siteRules' => $access->siteRuleSummaries($user, $sites),
            'pagination' => [
                'page' => $inventoryPage['page'],
                'has_more' => $inventoryPage['has_more'],
                'previous_url' => $page > 1
                    ? route('admin.users.sites.index', [
                        'user' => $user->id,
                        ...$baseQuery,
                        'page' => $page - 1,
                    ])
                    : null,
                'next_url' => $inventoryPage['has_more']
                    ? route('admin.users.sites.index', [
                        'user' => $user->id,
                        ...$baseQuery,
                        'page' => $page + 1,
                    ])
                    : null,
            ],
            'filters' => [
                'search' => $search,
                'connection_state' => $connectionState,
            ],
            'connectionStates' => SiteConnectionState::cases(),
            'isOwner' => $this->role($user) === GatewayRole::Owner,
        ]);
    }

    public function edit(
        User $user,
        Site $site,
        UserAccessManager $access,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.users.sites.edit', [
            'managedUser' => $user,
            'site' => $site,
            'siteRule' => $access->siteRule($user, $site),
            'sitePermissions' => $access->sitePermissions(),
            'isOwner' => $this->role($user) === GatewayRole::Owner,
        ]);
    }

    public function update(
        Request $request,
        User $user,
        Site $site,
        AdministratorPasswordConfirmation $confirmation,
        UserAccessManager $access,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);

        $validated = $request->validate([
            'access_rule' => ['required', 'string', Rule::in(['inherit', 'allow', 'deny'])],
            'denied_permissions' => ['nullable', 'array'],
            'denied_permissions.*' => ['string', Rule::enum(GatewayPermission::class)],
        ]);

        try {
            $access->updateSiteRule(
                $user,
                $site,
                (string) $validated['access_rule'],
                $this->deniedPermissions($validated),
            );
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'owner_unrestricted') {
                return back()->withErrors([
                    'access_rule' => __('Owners always retain unrestricted site access for recovery.'),
                ]);
            }

            throw $exception;
        }

        return redirect()
            ->route('admin.users.sites.edit', ['user' => $user->id, 'site' => $site->site_id])
            ->with('status', __('Site-specific access updated.'));
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

    private function role(User $user): GatewayRole
    {
        $role = $user->role;

        return $role instanceof GatewayRole ? $role : GatewayRole::from((string) $role);
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
