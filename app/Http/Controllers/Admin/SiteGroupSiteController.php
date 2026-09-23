<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\SiteGroupManager;
use App\Application\Sites\SiteInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\SiteGroup;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

final class SiteGroupSiteController extends Controller
{
    public function index(
        Request $request,
        SiteGroup $siteGroup,
        SiteInventory $inventory,
        SiteGroupManager $groups,
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

        return view('admin.site-groups.sites.index', [
            'siteGroup' => $siteGroup,
            'sites' => $sites,
            'memberships' => $groups->siteMembershipSummaries($siteGroup, $sites),
            'pagination' => [
                'page' => $inventoryPage['page'],
                'previous_url' => $page > 1
                    ? route('admin.site-groups.sites.index', [
                        'siteGroup' => $siteGroup->id,
                        ...$baseQuery,
                        'page' => $page - 1,
                    ])
                    : null,
                'next_url' => $inventoryPage['has_more']
                    ? route('admin.site-groups.sites.index', [
                        'siteGroup' => $siteGroup->id,
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
        ]);
    }

    public function edit(
        SiteGroup $siteGroup,
        Site $site,
        SiteGroupManager $groups,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.site-groups.sites.edit', [
            'siteGroup' => $siteGroup,
            'site' => $site,
            'assigned' => $groups->siteIsAssigned($siteGroup, $site),
        ]);
    }

    public function update(
        Request $request,
        SiteGroup $siteGroup,
        Site $site,
        AdministratorPasswordConfirmation $confirmation,
        SiteGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $request->validate(['assigned' => ['nullable', 'boolean']]);

        $groups->updateSiteMembership($siteGroup, $site, $request->boolean('assigned'));

        return redirect()
            ->route('admin.site-groups.sites.edit', [
                'siteGroup' => $siteGroup->id,
                'site' => $site->site_id,
            ])
            ->with('status', __('Site group membership updated.'));
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
