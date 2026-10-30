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
use Illuminate\Support\Facades\Gate;

final readonly class UserAccessManager
{
    public function __construct(private ActivityRecorder $activity) {}

    /**
     * @param  array{name:string,email:string,password:string,role:string,target_scope_mode:string,access_enabled:bool,ai_access_enabled?:bool}  $attributes
     * @param  list<string>  $deniedPermissions
     */
    public function create(array $attributes, array $deniedPermissions, bool $allowSshPermissionChanges = false): User
    {
        $role = GatewayRole::from((string) $attributes['role']);
        $scope = $role === GatewayRole::Owner
            ? TargetScopeMode::All
            : TargetScopeMode::from((string) $attributes['target_scope_mode']);

        // The absent confirmation path (including non-UI/API callers) remains
        // fail-closed. Only explicitly authorized Selected-scope account
        // creation can omit an SSH denial.
        $canGrantSsh = $allowSshPermissionChanges
            && $scope === TargetScopeMode::Selected;
        $defaults = array_filter(
            $this->defaultConnectorDenials($role),
            static fn (string $permission): bool => ! $canGrantSsh || ! str_starts_with($permission, 'ssh.'),
        );

        $user = DB::transaction(function () use ($attributes, $role, $scope, $deniedPermissions, $defaults): User {
            $user = User::query()->create([
                'name' => (string) $attributes['name'],
                'email' => (string) $attributes['email'],
                'password' => (string) $attributes['password'],
                'role' => $role->value,
                'target_scope_mode' => $scope->value,
                'access_enabled' => (bool) $attributes['access_enabled'],
                'ai_access_enabled' => (bool) ($attributes['ai_access_enabled'] ?? false),
            ]);

            $this->replaceGlobalDenials($user, $role, [
                ...$deniedPermissions,
                ...$defaults,
            ]);
            $this->normalizeOwnerState($user, $role);
            $this->recordRequired('user-access-create:'.$user->id);

            return $user->refresh();
        });

        return $user;
    }

    /**
     * @param  array{name:string,email:string,password?:string|null,role:string,target_scope_mode:string,access_enabled:bool,ai_access_enabled?:bool}  $attributes
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

            // Omitting the optional AI-control field preserves the current
            // decision; routine programmatic account updates cannot grant it.
            $priorAiAccess = (bool) $lockedUser->ai_access_enabled;
            if (array_key_exists('ai_access_enabled', $attributes)) {
                $values['ai_access_enabled'] = (bool) $attributes['ai_access_enabled'];
            }
            $lockedUser->fill($values)->save();
            if ($priorAiAccess && ! (bool) $lockedUser->ai_access_enabled) {
                // Revoking this channel is independent of Target/role grants.
                // Retire all prior OAuth consents in the same short locked
                // transaction, including issued access/refresh/code chains.
                // Re-enabling requires a fresh client consent rather than
                // silently resurrecting a dormant bearer token.
                DB::table('oauth_authorizations')
                    ->where('user_id', $lockedUser->getKey())
                    ->whereNull('revoked_at')
                    ->update(['revoked_at' => now(), 'updated_at' => now()]);
            }
            // Never retain a dormant positive publisher grant through a
            // role downgrade or account disable/re-enable cycle.
            if (! $role->allows(GatewayPermission::WordpressContentPublishCreate) || $role === GatewayRole::Owner || ! $enabled) {
                DB::table('wordpress_publish_group_grants')->where('user_id', $lockedUser->getKey())->delete();
            }
            // Editing ordinary user fields must not erase migration-seeded connector
            // denials merely because the form omitted newly introduced permissions.
            $this->replaceGlobalDenials($lockedUser, $role, [
                ...$deniedPermissions,
                // Historic, inactive permission keys remain intact in storage.
                // A confirmed Owner on Selected scope is the only path that
                // can alter live SSH denials.
                ...array_filter($this->existingSshDenials($lockedUser),
                    static fn (string $permission): bool => ! $allowSshPermissionChanges
                        || ! str_starts_with($permission, 'ssh.')),
                ...($currentRole !== $role ? array_filter(
                    $this->defaultConnectorDenials($role),
                    static fn (string $permission): bool => ! $allowSshPermissionChanges
                        || ! str_starts_with($permission, 'ssh.'),
                ) : []),
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
        bool $sshReviewed = false,
        ?string $expectedRevision = null,
    ): void {
        if (in_array($accessRule, ['inherit', 'allow', 'deny'], true) === false) {
            throw new DomainException('invalid_target_rule');
        }

        DB::transaction(function () use ($user, $target, $accessRule, $deniedPermissions, $sshReviewed, $expectedRevision): void {
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            if ($this->role($lockedUser) === GatewayRole::Owner) {
                throw new DomainException('owner_unrestricted');
            }

            // All writers of this user's Target rules serialize through the
            // locked User row. Check fresh persisted permissions after lock;
            // an old form must not erase a newer SSH-specific denial.
            $existing = $this->targetRule($lockedUser, $target);
            $permissions = $this->normalizedDenials(
                $this->role($lockedUser), $deniedPermissions, true,
            );
            $requestedDenials = [
                ...array_map(static fn (GatewayPermission $permission): string => $permission->value, $permissions),
                // Keep historical, unrecognized permission IDs in the revision
                // and database without admitting them into current policy.
                ...array_values(array_filter($existing['denied_permissions'],
                    static fn (string $value): bool => GatewayPermission::tryFrom($value) === null)),
            ];
            $existingRevision = AuthorizationRevision::targetRule($existing);
            $requestedRevision = AuthorizationRevision::targetRule([
                'access_rule' => $accessRule, 'denied_permissions' => $requestedDenials,
            ]);
            $sshTarget = $target->connector_type === 'ssh_direct';
            if ($sshTarget && $existingRevision !== $requestedRevision) {
                Gate::authorize(GatewayPermission::SecurityManage->value);
                if (! $sshReviewed) {
                    throw new DomainException('ssh_target_confirmation_required');
                }
                if ($expectedRevision === null || ! hash_equals($existingRevision, $expectedRevision)) {
                    throw new DomainException('target_rule_revision_stale');
                }
            }
            if ($sshTarget && $expectedRevision !== null && ! hash_equals($existingRevision, $expectedRevision)) {
                throw new DomainException('target_rule_revision_stale');
            }

            if ($existingRevision === $requestedRevision) {
                return; // True no-op: no permission replacement or audit mutation.
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

            DB::table('user_target_permission_denials')->where($identity)
                ->whereIn('permission', array_map(
                    static fn (GatewayPermission $permission): string => $permission->value,
                    GatewayPermission::cases(),
                ))->delete();

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

    /**
     * Change only the direct reachability rule; every active and historical
     * per-Target denial remains untouched. The workflow supplies a fresh
     * review-bound revision for each selected immutable Target.
     *
     * @param  list<string>  $targetIds
     * @param  array<string,string>  $expectedRevisions
     */
    public function updateTargetRules(
        User $actor,
        User $user,
        array $targetIds,
        string $rule,
        array $expectedRevisions,
        bool $sshReviewed,
        string $correlationId,
    ): int {
        $targetIds = AccessBatchContext::UserTargets->selection($targetIds);
        AccessBatchContext::UserTargets->intent($rule);
        $actor = AccessBatchGuard::actor($actor);

        return DB::transaction(function () use ($actor, $user, $targetIds, $rule, $expectedRevisions, $sshReviewed, $correlationId): int {
            $userIds = array_values(array_unique([(string) $actor->getKey(), (string) $user->getKey()]));
            $users = AccessBatchGuard::lockUsers($userIds);
            $actor = AccessBatchGuard::actor($users->get($actor->getKey()) ?? $actor);
            $user = $users->get($user->getKey()) ?? throw new DomainException('batch_selection_unavailable');
            if ($this->role($user) === GatewayRole::Owner) {
                throw new DomainException('owner_unrestricted');
            }
            $targets = Target::query()->whereIn('id', $targetIds)->orderBy('id')->lockForUpdate()->get()->keyBy('id');
            if ($targets->count() !== count($targetIds)) {
                throw new DomainException('batch_selection_unavailable');
            }
            $rules = DB::table('user_target_access')->where('user_id', $user->getKey())
                ->whereIn('target_record_id', $targetIds)->pluck('allowed', 'target_record_id');
            $denials = DB::table('user_target_permission_denials')->where('user_id', $user->getKey())
                ->whereIn('target_record_id', $targetIds)->orderBy('permission')->get()->groupBy('target_record_id');
            $changed = [];
            foreach ($targetIds as $id) {
                $allowed = $rules->get($id);
                $before = $allowed === null ? 'inherit' : ((bool) $allowed ? 'allow' : 'deny');
                $revision = AuthorizationRevision::targetRule([
                    'access_rule' => $before,
                    'denied_permissions' => $denials->get($id, collect())->pluck('permission')->all(),
                ]);
                if (! isset($expectedRevisions[$id]) || ! hash_equals($revision, $expectedRevisions[$id])) {
                    throw new DomainException('batch_review_stale');
                }
                if ($rule === 'allow' && $before === 'deny') {
                    throw new DomainException('batch_blocked');
                }
                if ($before !== $rule) {
                    $changed[] = $id;
                }
            }
            if ($changed === []) {
                return 0;
            }
            AccessBatchGuard::ssh($actor, $targets->only($changed)->contains(
                static fn (Target $target): bool => $target->connector_type === 'ssh_direct'), $sshReviewed);
            if ($rule === 'inherit') {
                DB::table('user_target_access')->where('user_id', $user->getKey())->whereIn('target_record_id', $changed)->delete();
            } else {
                $rows = array_map(static fn (string $id): array => [
                    'user_id' => $user->getKey(), 'target_record_id' => $id,
                    'allowed' => $rule === 'allow', 'created_at' => now(), 'updated_at' => now(),
                ], $changed);
                DB::table('user_target_access')->upsert($rows, ['user_id', 'target_record_id'], ['allowed', 'updated_at']);
            }
            foreach ($changed as $id) {
                $this->activity->recordRequired($correlationId, sprintf(
                    'user-target-access-update:%d:%s', $user->id, $targets->get($id)?->target_id,
                ), 'success');
            }

            return count($changed);
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

    public function targetRuleRevision(User $user, Target $target): string
    {
        return AuthorizationRevision::targetRule($this->targetRule($user, $target));
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

        return array_values(array_map(
            static fn (GatewayPermission $permission): string => $permission->value,
            array_filter($role->permissions(),
                static fn (GatewayPermission $permission): bool => str_starts_with($permission->value, 'ssh.')),
        ));
    }

    /** @return list<string> */
    private function existingSshDenials(User $user): array
    {
        return DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->where('permission', 'like', 'ssh.%')
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
        // Only replace active permissions; never erase inactive historical
        // denials merely because an editor omits unsupported permission keys.
        DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->whereIn('permission', array_map(
                static fn (GatewayPermission $permission): string => $permission->value,
                GatewayPermission::cases(),
            ))->delete();

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

        $activePermissions = array_map(
            static fn (GatewayPermission $permission): string => $permission->value,
            GatewayPermission::cases(),
        );
        DB::table('user_permission_denials')->where('user_id', $user->getKey())
            ->whereIn('permission', $activePermissions)->delete();
        DB::table('user_target_access')->where('user_id', $user->getKey())->delete();
        DB::table('user_target_permission_denials')->where('user_id', $user->getKey())
            ->whereIn('permission', $activePermissions)->delete();
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
