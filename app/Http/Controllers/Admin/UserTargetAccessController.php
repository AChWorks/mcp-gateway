<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Access\UserAccessManager;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Http\Controllers\Controller;
use App\Models\User;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

final class UserTargetAccessController extends Controller
{
    public function index(
        Request $request,
        User $user,
        TargetInventory $inventory,
        UserAccessManager $access,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        $actor = $request->user();
        abort_unless($actor instanceof User, 401);

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'connection_state' => ['nullable', 'string', Rule::enum(TargetConnectionState::class)],
            'page' => ['nullable', 'integer', 'min:1'],
        ]);
        $search = $this->nullableTrim($validated['search'] ?? null);
        $connectionState = $this->nullableTrim($validated['connection_state'] ?? null);
        $page = (int) ($validated['page'] ?? 1);

        $inventoryPage = $inventory->adminPage($actor, $page, $search, $connectionState);
        $targets = $inventoryPage['items'];
        $baseQuery = array_filter([
            'search' => $search,
            'connection_state' => $connectionState,
        ], static fn (mixed $value): bool => $value !== null && $value !== '');

        return view('admin.users.targets.index', [
            'managedUser' => $user,
            'targets' => $targets,
            'targetRules' => $access->targetRuleSummaries($user, $targets),
            'pagination' => [
                'page' => $inventoryPage['page'],
                'has_more' => $inventoryPage['has_more'],
                'previous_url' => $page > 1
                    ? route('admin.users.targets.index', [
                        'user' => $user->id,
                        ...$baseQuery,
                        'page' => $page - 1,
                    ])
                    : null,
                'next_url' => $inventoryPage['has_more']
                    ? route('admin.users.targets.index', [
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
            'connectionStates' => TargetConnectionState::cases(),
            'isOwner' => $this->role($user) === GatewayRole::Owner,
        ]);
    }

    public function edit(
        User $user,
        Target $target,
        UserAccessManager $access,
    ): View {
        Gate::authorize(GatewayPermission::UsersManage->value);

        return view('admin.users.targets.edit', [
            'managedUser' => $user,
            'target' => $target,
            'targetRule' => $access->targetRule($user, $target),
            'targetPermissions' => $access->targetPermissions(),
            'isOwner' => $this->role($user) === GatewayRole::Owner,
        ]);
    }

    public function update(
        Request $request,
        User $user,
        Target $target,
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
            $access->updateTargetRule(
                $user,
                $target,
                (string) $validated['access_rule'],
                $this->deniedPermissions($validated),
            );
        } catch (DomainException $exception) {
            if ($exception->getMessage() === 'owner_unrestricted') {
                return back()->withErrors([
                    'access_rule' => __('Owners always retain unrestricted target access for recovery.'),
                ]);
            }

            throw $exception;
        }

        return redirect()
            ->route('admin.users.targets.edit', ['user' => $user->id, 'target' => $target->target_id])
            ->with('status', __('Target-specific access updated.'));
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
        return GatewayRole::from((string) $user->role);
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
