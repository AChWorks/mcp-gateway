<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use DomainException;
use Illuminate\Support\Facades\DB;

final readonly class UserAccessManager
{
    public function __construct(private ActivityRecorder $activity) {}

    /**
     * @param  array{name:string,email:string,password:string,role:string,target_scope_mode:string,access_enabled:bool}  $attributes
     * @param  list<string>  $deniedPermissions
     */
    public function create(array $attributes, array $deniedPermissions): User
    {
        $role = GatewayRole::from((string) $attributes['role']);
        $scope = $role === GatewayRole::Owner
            ? TargetScopeMode::All
            : TargetScopeMode::from((string) $attributes['target_scope_mode']);

        $user = DB::transaction(function () use ($attributes, $role, $scope, $deniedPermissions): User {
            $user = User::query()->create([
                'name' => (string) $attributes['name'],
                'email' => (string) $attributes['email'],
                'password' => (string) $attributes['password'],
                'role' => $role->value,
                'target_scope_mode' => $scope->value,
                'access_enabled' => (bool) $attributes['access_enabled'],
            ]);

            $this->replaceGlobalDenials($user, $role, [
                ...$deniedPermissions,
                ...$this->defaultConnectorDenials($role),
            ]);
            $this->normalizeOwnerState($user, $role);
            $this->recordRequired('user-access-create:'.$user->id);

            return $user->refresh();
        });

        return $user;
    }

    /**
     * @param  array{name:string,email:string,password?:string|null,role:string,target_scope_mode:string,access_enabled:bool}  $attributes
     * @param  list<string>  $deniedPermissions
     */
    public function update(User $user, array $attributes, array $deniedPermissions, bool $allowSshPermissionChanges = false): User
    {
        $role = GatewayRole::from((string) $attributes['role']);
        $enabled = (bool) $attributes['access_enabled'];
        $scope = $role === GatewayRole::Owner
            ? TargetScopeMode::All
            : TargetScopeMode::from((string) $attributes['target_scope_mode']);

        DB::transaction(function () use ($user, $attributes, $role, $enabled, $scope, $deniedPermissions, $allowSshPermissionChanges): void {
            $enabledOwners = User::query()
                ->where('role', GatewayRole::Owner->value)
                ->where('access_enabled', true)
                ->orderBy('id')
                ->lockForUpdate()
                ->get(['id']);

            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $currentRole = $this->role($lockedUser);
            $removesRecoverableOwner = $currentRole === GatewayRole::Owner
                && (bool) $lockedUser->access_enabled
                && ($role !== GatewayRole::Owner || ! $enabled);

            if ($removesRecoverableOwner && $enabledOwners->count() <= 1) {
                throw new DomainException('last_owner');
            }

            $values = [
                'name' => (string) $attributes['name'],
                'email' => (string) $attributes['email'],
                'role' => $role->value,
                'target_scope_mode' => $scope->value,
                'access_enabled' => $enabled,
            ];

            if (isset($attributes['password']) && $attributes['password'] !== '') {
                $values['password'] = $attributes['password'];
            }

            $lockedUser->fill($values)->save();
            // Editing ordinary user fields must not erase migration-seeded connector
            // denials merely because the form omitted newly introduced permissions.
            $this->replaceGlobalDenials($lockedUser, $role, [
                ...$deniedPermissions,
                // Existing Agent denials always survive regular user edits.
                // A distinct, freshly authenticated Owner action is required
                // to change any default-denied SSH permission.
                ...array_filter($this->existingConnectorDenials($lockedUser),
                    static fn (string $permission): bool => ! $allowSshPermissionChanges
                        || $permission !== GatewayPermission::SshCommandRun->value),
                ...($currentRole !== $role ? $this->defaultConnectorDenials($role) : []),
                // Changing away from Selected always revokes dormant SSH grants;
                // returning to Selected later requires a new explicit Owner grant.
                ...($scope !== TargetScopeMode::Selected
                    ? array_filter($this->defaultConnectorDenials($role),
                        static fn (string $permission): bool => str_starts_with($permission, 'ssh.'))
                    : []),
            ]);
            $this->normalizeOwnerState($lockedUser, $role);
            $this->recordRequired('user-access-update:'.$lockedUser->id);
        });

        return $user->refresh();
    }

    /** @param list<string> $deniedPermissions */
    public function updateTargetRule(
        User $user,
        Target $target,
        string $accessRule,
        array $deniedPermissions,
    ): void {
        if (in_array($accessRule, ['inherit', 'allow', 'deny'], true) === false) {
            throw new DomainException('invalid_target_rule');
        }

        DB::transaction(function () use ($user, $target, $accessRule, $deniedPermissions): void {
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            if ($this->role($lockedUser) === GatewayRole::Owner) {
                throw new DomainException('owner_unrestricted');
            }

            $identity = [
                'user_id' => $lockedUser->getKey(),
                'target_record_id' => $target->getKey(),
            ];

            if ($accessRule === 'inherit') {
                DB::table('user_target_access')->where($identity)->delete();
            } else {
                DB::table('user_target_access')->updateOrInsert(
                    $identity,
                    [
                        'allowed' => $accessRule === 'allow',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ],
                );
            }

            DB::table('user_target_permission_denials')->where($identity)->delete();

            $permissions = $this->normalizedDenials(
                $this->role($lockedUser),
                $deniedPermissions,
                true,
            );
            $rows = array_map(
                static fn (GatewayPermission $permission): array => [
                    ...$identity,
                    'permission' => $permission->value,
                    'created_at' => now(),
                    'updated_at' => now(),
                ],
                $permissions,
            );

            if ($rows !== []) {
                DB::table('user_target_permission_denials')->insert($rows);
            }

            $this->recordRequired(sprintf(
                'user-target-access-update:%d:%s',
                $lockedUser->id,
                $target->target_id,
            ));
        });
    }

    /** @return list<string> */
    public function globalDenials(User $user): array
    {
        return DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->orderBy('permission')
            ->pluck('permission')
            ->map(static fn (mixed $value): string => (string) $value)
            ->all();
    }

    /** @return array{access_rule:string,denied_permissions:list<string>} */
    public function targetRule(User $user, Target $target): array
    {
        $allowed = DB::table('user_target_access')
            ->where('user_id', $user->getKey())
            ->where('target_record_id', $target->getKey())
            ->value('allowed');

        $accessRule = $allowed === null
            ? 'inherit'
            : ((bool) $allowed ? 'allow' : 'deny');

        return [
            'access_rule' => $accessRule,
            'denied_permissions' => DB::table('user_target_permission_denials')
                ->where('user_id', $user->getKey())
                ->where('target_record_id', $target->getKey())
                ->orderBy('permission')
                ->pluck('permission')
                ->map(static fn (mixed $value): string => (string) $value)
                ->all(),
        ];
    }

    /**
     * @param  list<Target>  $targets
     * @return array<string,array{access_rule:string,denied_count:int}>
     */
    public function targetRuleSummaries(User $user, array $targets): array
    {
        $ids = array_map(
            static fn (Target $target): string => (string) $target->getKey(),
            $targets,
        );

        if ($ids === []) {
            return [];
        }

        $access = DB::table('user_target_access')
            ->where('user_id', $user->getKey())
            ->whereIn('target_record_id', $ids)
            ->pluck('allowed', 'target_record_id');

        $deniedCounts = DB::table('user_target_permission_denials')
            ->selectRaw('target_record_id, COUNT(*) as aggregate')
            ->where('user_id', $user->getKey())
            ->whereIn('target_record_id', $ids)
            ->groupBy('target_record_id')
            ->pluck('aggregate', 'target_record_id');

        $result = [];
        foreach ($targets as $target) {
            $id = (string) $target->getKey();
            $allowed = $access->get($id);

            $result[$id] = [
                'access_rule' => $allowed === null ? 'inherit' : ((bool) $allowed ? 'allow' : 'deny'),
                'denied_count' => (int) ($deniedCounts->get($id) ?? 0),
            ];
        }

        return $result;
    }

    /** @return list<GatewayPermission> */
    public function targetPermissions(): array
    {
        return GatewayPermission::targetScoped();
    }

    /** @return list<string> */
    private function defaultConnectorDenials(GatewayRole $role): array
    {
        if ($role === GatewayRole::Owner) {
            return [];
        }

        $allowedByDefault = [
            GatewayPermission::AgentEnvironmentRead,
            GatewayPermission::AgentCommandRun,
        ];

        return array_values(array_map(
            static fn (GatewayPermission $permission): string => $permission->value,
            array_filter($role->permissions(), static fn (GatewayPermission $permission): bool => (str_starts_with($permission->value, 'agent.')
                    && ! in_array($permission, $allowedByDefault, true))
                || str_starts_with($permission->value, 'ssh.'),
            ),
        ));
    }

    /** @return list<string> */
    private function existingConnectorDenials(User $user): array
    {
        return DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->where(function ($query): void {
                $query->where('permission', 'like', 'agent.%')
                    ->orWhere('permission', 'like', 'ssh.%');
            })
            ->pluck('permission')
            ->map(static fn (mixed $value): string => (string) $value)
            ->all();
    }

    /** @param  list<string>  $deniedPermissions */
    private function replaceGlobalDenials(
        User $user,
        GatewayRole $role,
        array $deniedPermissions,
    ): void {
        DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->delete();

        $permissions = $this->normalizedDenials($role, $deniedPermissions);
        if ($permissions === []) {
            return;
        }

        DB::table('user_permission_denials')->insert(array_map(
            static fn (GatewayPermission $permission): array => [
                'user_id' => $user->getKey(),
                'permission' => $permission->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            $permissions,
        ));
    }

    /**
     * @param  list<string>  $values
     * @return list<GatewayPermission>
     */
    private function normalizedDenials(
        GatewayRole $role,
        array $values,
        bool $targetOnly = false,
    ): array {
        if ($role === GatewayRole::Owner) {
            return [];
        }

        $rolePermissions = $role->permissions();
        $targetPermissions = $targetOnly ? $this->targetPermissions() : null;
        $result = [];

        foreach (array_unique($values) as $value) {
            $permission = GatewayPermission::tryFrom($value);
            if ($permission === null
                || in_array($permission, $rolePermissions, true) === false
                || ($targetPermissions !== null && in_array($permission, $targetPermissions, true) === false)) {
                continue;
            }

            $result[] = $permission;
        }

        return $result;
    }

    private function normalizeOwnerState(User $user, GatewayRole $role): void
    {
        if ($role !== GatewayRole::Owner) {
            return;
        }

        $user->forceFill(['target_scope_mode' => TargetScopeMode::All->value])->save();

        DB::table('user_permission_denials')->where('user_id', $user->getKey())->delete();
        DB::table('user_target_access')->where('user_id', $user->getKey())->delete();
        DB::table('user_target_permission_denials')->where('user_id', $user->getKey())->delete();
        DB::table('target_group_users')->where('user_id', $user->getKey())->delete();
    }

    private function role(User $user): GatewayRole
    {
        $role = $user->getAttribute('role');

        return $role instanceof GatewayRole
            ? $role
            : GatewayRole::from((string) $role);
    }

    private function recordRequired(string $operation): void
    {
        $this->activity->recordRequired(
            CorrelationId::current(),
            $operation,
            'success',
        );
    }
}
