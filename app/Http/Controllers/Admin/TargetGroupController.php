<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\AuthorizationRevision;
use App\Application\Access\TargetGroupManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\TargetGroup;
use App\Http\Controllers\Controller;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

final class TargetGroupController extends Controller
{
    public function index(Request $request): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        $fields = $request->validate(['search' => ['nullable', 'string', 'max:160']]);
        $search = trim((string) ($fields['search'] ?? ''));

        return view('admin.target-groups.index', [
            'groups' => TargetGroup::query()
                ->withCount(['targets', 'users'])
                ->when($search !== '', static fn ($query) => $query->where('name', 'like', '%'.$search.'%'))
                ->orderBy('name')->orderBy('id')
                ->simplePaginate(50)->withQueryString(),
            'search' => $search,
        ]);
    }

    public function create(TargetGroupManager $groups): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.target-groups.create', [
            'targetPermissions' => $groups->targetPermissions(),
            'sshPermissionsEditable' => true,
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
        $this->confirmSshChanges($request, $this->deniedPermissions($validated), []);

        $group = $groups->create(
            (string) $validated['name'],
            $this->deniedPermissions($validated),
        );

        return redirect()
            ->route('admin.target-groups.targets.index', ['targetGroup' => $group->id])
            ->with('status', __('Target group created.'));
    }

    public function edit(TargetGroup $targetGroup, TargetGroupManager $groups): View
    {
        Gate::authorize(GatewayPermission::UsersManage->value);

        // The fingerprint must describe exactly the denials displayed in
        // this form, rather than a later, separately read DB state.
        $denials = $groups->permissionDenials($targetGroup);

        return view('admin.target-groups.edit', [
            'targetGroup' => $targetGroup,
            'targetPermissions' => $groups->targetPermissions(),
            'sshPermissionsEditable' => true,
            'deniedPermissions' => $denials,
            'denialRevision' => AuthorizationRevision::groupDenials($denials),
            'sshAccessImpact' => $groups->hasSshAccessImpact($targetGroup),
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
        // The transaction-held group lock and submitted denial snapshot
        // are authoritative. Pre-lock comparisons cannot approve stale edits.
        try {
            $groups->update(
                $targetGroup,
                (string) $validated['name'],
                $this->deniedPermissions($validated),
                $request->boolean('confirm_ssh_group_changes'),
                isset($validated['denial_revision']) ? (string) $validated['denial_revision'] : null,
            );
        } catch (DomainException $exception) {
            $this->rethrowUnconfirmedSsh($exception);
        }

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
        try {
            $groups->delete($targetGroup, $request->boolean('confirm_ssh_group_changes'));
        } catch (DomainException $exception) {
            $this->rethrowUnconfirmedSsh($exception);
        }

        return redirect()
            ->route('admin.target-groups.index')
            ->with('status', __('Target group deleted. Direct user/target rules were preserved.'));
    }

    /** Translate service-level, transaction-fenced acknowledgement into a form error. */
    private function rethrowUnconfirmedSsh(DomainException $exception): never
    {
        if ($exception->getMessage() === 'group_revision_stale') {
            throw ValidationException::withMessages([
                'denial_revision' => __('Group restrictions have changed since you opened this form. Reload and review the latest denials before confirming the update.'),
            ]);
        }

        if ($exception->getMessage() === 'ssh_confirmation_required') {
            throw ValidationException::withMessages([
                'confirm_ssh_group_changes' => __(
                    'Explicitly confirm SSH group changes. Deleting a group or changing its restrictions can expand previously authorized SSH access.',
                ),
            ]);
        }

        throw $exception;
    }

    /**
     * Removing an SSH group denial can increase authority for users previously
     * granted SSH access. Require an explicit Owner decision.
     *
     * @param  list<string>  $requested
     * @param  list<string>  $existing
     */
    private function confirmSshChanges(Request $request, array $requested, array $existing): void
    {
        $sshOnly = static fn (array $values): array => array_values(array_filter(
            $values, static fn (string $value): bool => str_starts_with($value, 'ssh.'),
        ));
        $requestedSsh = $sshOnly($requested);
        $existingSsh = $sshOnly($existing);
        sort($requestedSsh);
        sort($existingSsh);

        if ($requestedSsh !== $existingSsh) {
            Gate::authorize(GatewayPermission::SecurityManage->value);
            if (! $request->boolean('confirm_ssh_group_changes')) {
                throw ValidationException::withMessages([
                    'confirm_ssh_group_changes' => __('Explicitly confirm changed SSH group restrictions. Removing a denial can expand previously authorized SSH access.'),
                ]);
            }
        }
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
            'denial_revision' => ['nullable', 'string', 'regex:/\\A[a-f0-9]{64}\\z/D'],
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
