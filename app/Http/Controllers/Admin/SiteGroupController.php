<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\SiteGroupManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\SiteGroup;
use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

final class SiteGroupController extends Controller
{
    public function index(): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.site-groups.index', [
            'groups' => SiteGroup::query()
                ->withCount(['sites', 'users'])
                ->orderBy('name')
                ->simplePaginate(50),
        ]);
    }

    public function create(SiteGroupManager $groups): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.site-groups.create', [
            'sitePermissions' => $groups->sitePermissions(),
        ]);
    }

    public function store(
        Request $request,
        AdministratorPasswordConfirmation $confirmation,
        SiteGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $validated = $this->validated($request);

        $group = $groups->create(
            (string) $validated['name'],
            $this->deniedPermissions($validated),
        );

        return redirect()
            ->route('admin.site-groups.edit', ['siteGroup' => $group->id])
            ->with('status', __('Site group created.'));
    }

    public function edit(SiteGroup $siteGroup, SiteGroupManager $groups): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.site-groups.edit', [
            'siteGroup' => $siteGroup,
            'sitePermissions' => $groups->sitePermissions(),
            'deniedPermissions' => $groups->permissionDenials($siteGroup),
        ]);
    }

    public function update(
        Request $request,
        SiteGroup $siteGroup,
        AdministratorPasswordConfirmation $confirmation,
        SiteGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $validated = $this->validated($request, $siteGroup);

        $groups->update(
            $siteGroup,
            (string) $validated['name'],
            $this->deniedPermissions($validated),
        );

        return redirect()
            ->route('admin.site-groups.edit', ['siteGroup' => $siteGroup->id])
            ->with('status', __('Site group updated.'));
    }

    public function destroy(
        Request $request,
        SiteGroup $siteGroup,
        AdministratorPasswordConfirmation $confirmation,
        SiteGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $groups->delete($siteGroup);

        return redirect()
            ->route('admin.site-groups.index')
            ->with('status', __('Site group deleted. Direct user/site rules were preserved.'));
    }

    /** @return array<string,mixed> */
    private function validated(Request $request, ?SiteGroup $siteGroup = null): array
    {
        return $request->validate([
            'name' => [
                'required',
                'string',
                'max:160',
                Rule::unique('site_groups', 'name')->ignore($siteGroup?->getKey()),
            ],
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
}
