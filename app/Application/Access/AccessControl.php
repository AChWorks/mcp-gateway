<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Facades\DB;

final readonly class AccessControl
{
    public function allows(User $user, GatewayPermission $permission, ?Target $target = null): bool
    {
        $role = $this->role($user);

        if (! $this->globalAllows($user, $role, $permission)) {
            return false;
        }

        if ($target instanceof Target && ! $this->permissionMatchesTarget($permission, $target)) {
            return false;
        }

        if (! $target instanceof Target || $role === GatewayRole::Owner) {
            return true;
        }

        if (! $this->targetIsInScope($user, $target)) {
            return false;
        }

        if ($this->groupDenies($user, $target, $permission)) {
            return false;
        }

        return ! DB::table('user_target_permission_denials')
            ->where('user_id', $user->getKey())
            ->where('target_record_id', $target->getKey())
            ->where('permission', $permission->value)
            ->exists();
    }

    /**
     * Evaluate several Target-scoped rights from one bounded request-local
     * authorization snapshot. No cross-request cache or second policy engine:
     * the same role ceiling, explicit deny precedence and group rules as
     * allows() are applied to every requested permission.
     *
     * @param  list<GatewayPermission>  $permissions
     * @return array<string,bool> Permission values keyed to decisions.
     */
    public function allowsTargetPermissions(User $user, Target $target, array $permissions): array
    {
        $decisions = [];
        foreach ($permissions as $permission) {
            $decisions[$permission->value] = false;
        }
        if ($decisions === []) {
            return $decisions;
        }

        $role = $this->role($user);
        if (! (bool) $user->getAttribute('access_enabled') || ! $role instanceof GatewayRole) {
            return $decisions;
        }

        $eligible = [];
        foreach ($permissions as $permission) {
            if ($role->allows($permission) && $this->permissionMatchesTarget($permission, $target)
                && (! str_starts_with($permission->value, 'ssh.')
                    || $role === GatewayRole::Owner || $this->scopeMode($user) === TargetScopeMode::Selected)) {
                $eligible[$permission->value] = true;
            }
        }
        if ($eligible === []) {
            return $decisions;
        }
        if ($role === GatewayRole::Owner) {
            foreach (array_keys($eligible) as $name) {
                $decisions[$name] = true;
            }

            return $decisions;
        }

        $scope = $this->scopeMode($user);
        if (! $scope instanceof TargetScopeMode) {
            return $decisions;
        }

        $names = array_keys($eligible);
        $globalDenials = DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->whereIn('permission', $names)
            ->pluck('permission')->all();
        $direct = DB::table('user_target_access')
            ->where('user_id', $user->getKey())
            ->where('target_record_id', $target->getKey())
            ->value('allowed');
        if ($direct !== null && ! (bool) $direct) {
            return $decisions;
        }

        // Membership is loaded exactly once, reused for Selected scope AND
        // applicable group permission denials, regardless of permission count.
        $groups = DB::table('target_group_users')
            ->join('target_group_targets', 'target_group_targets.target_group_id', '=', 'target_group_users.target_group_id')
            ->where('target_group_users.user_id', $user->getKey())
            ->where('target_group_targets.target_record_id', $target->getKey())
            ->pluck('target_group_users.target_group_id')->all();
        if ($scope === TargetScopeMode::Selected && $direct === null && $groups === []) {
            return $decisions;
        }

        $groupDenials = $groups === [] ? [] : DB::table('target_group_permission_denials')
            ->whereIn('target_group_id', $groups)
            ->whereIn('permission', $names)
            ->pluck('permission')->all();
        $directDenials = DB::table('user_target_permission_denials')
            ->where('user_id', $user->getKey())
            ->where('target_record_id', $target->getKey())
            ->whereIn('permission', $names)
            ->pluck('permission')->all();

        foreach ($names as $name) {
            $decisions[$name] = ! in_array($name, $globalDenials, true)
                && ! in_array($name, $groupDenials, true)
                && ! in_array($name, $directDenials, true);
        }

        return $decisions;
    }

    /**
     * Applies principal target membership only. Functional permission is deliberately separate so
     * a selected target can be write-only, read-only, or otherwise narrowed by capability.
     *
     * Direct target deny always wins. For selected-scope users, a direct allow or membership in at
     * least one assigned target group supplies reachability. All-scope users remain all-target unless
     * a direct target deny excludes the target. Owners bypass every narrowing layer for recovery.
     *
     * @param  Builder<Target>  $query
     * @return Builder<Target>
     */
    public function scopePrincipalTargets(Builder $query, User $user): Builder
    {
        $role = $this->role($user);

        if (! (bool) $user->getAttribute('access_enabled') || ! $role instanceof GatewayRole) {
            return $query->whereRaw('1 = 0');
        }

        if ($role === GatewayRole::Owner) {
            return $query;
        }

        $scope = $this->scopeMode($user);
        if (! $scope instanceof TargetScopeMode) {
            return $query->whereRaw('1 = 0');
        }

        $query->whereNotExists(function (QueryBuilder $subquery) use ($user): void {
            $subquery
                ->selectRaw('1')
                ->from('user_target_access')
                ->whereColumn('user_target_access.target_record_id', 'targets.id')
                ->where('user_target_access.user_id', $user->getKey())
                ->where('user_target_access.allowed', false);
        });

        if ($scope === TargetScopeMode::All) {
            return $query;
        }

        return $query->where(function (Builder $membership) use ($user): void {
            $membership
                ->whereExists(function (QueryBuilder $subquery) use ($user): void {
                    $subquery
                        ->selectRaw('1')
                        ->from('user_target_access')
                        ->whereColumn('user_target_access.target_record_id', 'targets.id')
                        ->where('user_target_access.user_id', $user->getKey())
                        ->where('user_target_access.allowed', true);
                })
                ->orWhereExists(function (QueryBuilder $subquery) use ($user): void {
                    $subquery
                        ->selectRaw('1')
                        ->from('target_group_users')
                        ->join(
                            'target_group_targets',
                            'target_group_targets.target_group_id',
                            '=',
                            'target_group_users.target_group_id',
                        )
                        ->where('target_group_users.user_id', $user->getKey())
                        ->whereColumn('target_group_targets.target_record_id', 'targets.id');
                });
        });
    }

    /**
     * @param  Builder<Target>  $query
     * @return Builder<Target>
     */
    public function scopeTargets(
        Builder $query,
        User $user,
        GatewayPermission $permission = GatewayPermission::TargetsView,
    ): Builder {
        $role = $this->role($user);

        if (! $this->globalAllows($user, $role, $permission)) {
            return $query->whereRaw('1 = 0');
        }

        $connector = $this->connectorForPermission($permission);
        if ($connector !== null) {
            $query->where('connector_type', $connector);
        }

        $query = $this->scopePrincipalTargets($query, $user);

        if ($role === GatewayRole::Owner) {
            return $query;
        }

        $query->whereNotExists(function (QueryBuilder $subquery) use ($user, $permission): void {
            $subquery
                ->selectRaw('1')
                ->from('target_group_users')
                ->join(
                    'target_group_targets',
                    'target_group_targets.target_group_id',
                    '=',
                    'target_group_users.target_group_id',
                )
                ->join(
                    'target_group_permission_denials',
                    'target_group_permission_denials.target_group_id',
                    '=',
                    'target_group_users.target_group_id',
                )
                ->where('target_group_users.user_id', $user->getKey())
                ->whereColumn('target_group_targets.target_record_id', 'targets.id')
                ->where('target_group_permission_denials.permission', $permission->value);
        });

        return $query->whereNotExists(function (QueryBuilder $subquery) use ($user, $permission): void {
            $subquery
                ->selectRaw('1')
                ->from('user_target_permission_denials')
                ->whereColumn('user_target_permission_denials.target_record_id', 'targets.id')
                ->where('user_target_permission_denials.user_id', $user->getKey())
                ->where('user_target_permission_denials.permission', $permission->value);
        });
    }

    public function hasUnrestrictedTargetScope(User $user): bool
    {
        return (bool) $user->getAttribute('access_enabled')
            && $this->role($user) === GatewayRole::Owner;
    }

    public function hasAllTargetScope(User $user): bool
    {
        if (! (bool) $user->getAttribute('access_enabled')) {
            return false;
        }

        $role = $this->role($user);
        if ($role === GatewayRole::Owner) {
            return true;
        }

        return $role instanceof GatewayRole
            && $this->scopeMode($user) === TargetScopeMode::All;
    }

    public function includeCreatedTarget(User $user, Target $target): void
    {
        $role = $this->role($user);

        if ($role === GatewayRole::Owner || $this->scopeMode($user) === TargetScopeMode::All) {
            return;
        }

        if (! $role instanceof GatewayRole || $this->scopeMode($user) !== TargetScopeMode::Selected) {
            return;
        }

        DB::table('user_target_access')->updateOrInsert(
            [
                'user_id' => $user->getKey(),
                'target_record_id' => $target->getKey(),
            ],
            [
                'allowed' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        );
    }

    private function globalAllows(
        User $user,
        ?GatewayRole $role,
        GatewayPermission $permission,
    ): bool {
        if (! (bool) $user->getAttribute('access_enabled')
            || ! $role instanceof GatewayRole
            || ! $role->allows($permission)) {
            return false;
        }

        if ($role === GatewayRole::Owner) {
            return true;
        }

        // Remote shell/file capability must never escape explicitly selected Targets.
        if (str_starts_with($permission->value, 'ssh.')
            && $this->scopeMode($user) !== TargetScopeMode::Selected) {
            return false;
        }

        return ! DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->where('permission', $permission->value)
            ->exists();
    }

    private function targetIsInScope(User $user, Target $target): bool
    {
        $scope = $this->scopeMode($user);
        if (! $scope instanceof TargetScopeMode) {
            return false;
        }

        $explicit = DB::table('user_target_access')
            ->where('user_id', $user->getKey())
            ->where('target_record_id', $target->getKey())
            ->value('allowed');

        if ($explicit !== null && ! (bool) $explicit) {
            return false;
        }

        if ($scope === TargetScopeMode::All || $explicit !== null) {
            return true;
        }

        return DB::table('target_group_users')
            ->join(
                'target_group_targets',
                'target_group_targets.target_group_id',
                '=',
                'target_group_users.target_group_id',
            )
            ->where('target_group_users.user_id', $user->getKey())
            ->where('target_group_targets.target_record_id', $target->getKey())
            ->exists();
    }

    private function groupDenies(User $user, Target $target, GatewayPermission $permission): bool
    {
        return DB::table('target_group_users')
            ->join(
                'target_group_targets',
                'target_group_targets.target_group_id',
                '=',
                'target_group_users.target_group_id',
            )
            ->join(
                'target_group_permission_denials',
                'target_group_permission_denials.target_group_id',
                '=',
                'target_group_users.target_group_id',
            )
            ->where('target_group_users.user_id', $user->getKey())
            ->where('target_group_targets.target_record_id', $target->getKey())
            ->where('target_group_permission_denials.permission', $permission->value)
            ->exists();
    }

    private function permissionMatchesTarget(GatewayPermission $permission, Target $target): bool
    {
        $connector = $this->connectorForPermission($permission);

        return $connector === null || $target->connector_type === $connector;
    }

    private function connectorForPermission(GatewayPermission $permission): ?string
    {
        return match (true) {
            str_starts_with($permission->value, 'wordpress.') => 'wp_ai_bridge',
            str_starts_with($permission->value, 'agent.') => 'ai_server_agent',
            str_starts_with($permission->value, 'ssh.') => 'ssh_direct',
            default => null,
        };
    }

    private function role(User $user): ?GatewayRole
    {
        $role = $user->getAttribute('role');

        if ($role instanceof GatewayRole) {
            return $role;
        }

        return is_string($role) ? GatewayRole::tryFrom($role) : null;
    }

    private function scopeMode(User $user): ?TargetScopeMode
    {
        $scope = $user->getAttribute('target_scope_mode');

        if ($scope instanceof TargetScopeMode) {
            return $scope;
        }

        return is_string($scope) ? TargetScopeMode::tryFrom($scope) : null;
    }
}
