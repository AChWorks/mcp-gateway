<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\TargetGroupManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\TargetGroup;
use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

final class TargetGroupController extends Controller
{
    public function index(): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.target-groups.index', [
            'groups' => TargetGroup::query()
                ->withCount(['targets', 'users'])
                ->orderBy('name')
                ->simplePaginate(50),
        ]);
    }

    public function create(TargetGroupManager $groups): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.target-groups.create', [
            'targetPermissions' => $groups->targetPermissions(),
        ]);
    }

    public function store(
        Request $request,
        AdministratorPasswordConfirmation $confirmation,
        TargetGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $validated = $this->validated($request);

        $group = $groups->create(
            (string) $validated['name'],
            $this->deniedPermissions($validated),
        );

        return redirect()
            ->route('admin.target-groups.edit', ['targetGroup' => $group->id])
            ->with('status', __('Target group created.'));
    }

    public function edit(TargetGroup $targetGroup, TargetGroupManager $groups): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.target-groups.edit', [
            'targetGroup' => $targetGroup,
            'targetPermissions' => $groups->targetPermissions(),
            'deniedPermissions' => $groups->permissionDenials($targetGroup),
        ]);
    }

    public function update(
        Request $request,
        TargetGroup $targetGroup,
        AdministratorPasswordConfirmation $confirmation,
        TargetGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $validated = $this->validated($request, $targetGroup);

        $groups->update(
            $targetGroup,
            (string) $validated['name'],
            $this->deniedPermissions($validated),
        );

        return redirect()
            ->route('admin.target-groups.edit', ['targetGroup' => $targetGroup->id])
            ->with('status', __('Target group updated.'));
    }

    public function destroy(
        Request $request,
        TargetGroup $targetGroup,
        AdministratorPasswordConfirmation $confirmation,
        TargetGroupManager $groups,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::UsersManage->value);
        $confirmation->confirm($request);
        $groups->delete($targetGroup);

        return redirect()
            ->route('admin.target-groups.index')
            ->with('status', __('Target group deleted. Direct user/target rules were preserved.'));
    }

    /** @return array<string,mixed> */
    private function validated(Request $request, ?TargetGroup $targetGroup = null): array
    {
        return $request->validate([
            'name' => [
                'required',
                'string',
                'max:160',
                Rule::unique('target_groups', 'name')->ignore($targetGroup?->getKey()),
            ],
            'denied_permissions' => ['nullable', 'array'],
            'denied_permissions.*' => [
                'string',
                Rule::in(array_map(
                    static fn (GatewayPermission $permission): string => $permission->value,
                    GatewayPermission::targetScoped(),
                )),
            ],
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
