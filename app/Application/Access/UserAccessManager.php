<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use DomainException;
use Illuminate\Support\Facades\DB;

final readonly class UserAccessManager
{
    public function __construct(private ActivityRecorder $activity) {}

    /**
     * @param  array{name:string,email:string,password:string,role:string,site_scope_mode:string,access_enabled:bool}  $attributes
     * @param  list<string>  $deniedPermissions
     */
    public function create(array $attributes, array $deniedPermissions): User
    {
        $role = GatewayRole::from((string) $attributes['role']);
        $scope = $role === GatewayRole::Owner
            ? SiteScopeMode::All
            : SiteScopeMode::from((string) $attributes['site_scope_mode']);

        $user = DB::transaction(function () use ($attributes, $role, $scope, $deniedPermissions): User {
            $user = User::query()->create([
                'name' => (string) $attributes['name'],
                'email' => (string) $attributes['email'],
                'password' => (string) $attributes['password'],
                'role' => $role->value,
                'site_scope_mode' => $scope->value,
                'access_enabled' => (bool) $attributes['access_enabled'],
            ]);

            $this->replaceGlobalDenials($user, $role, $deniedPermissions);
            $this->normalizeOwnerState($user, $role);
            $this->recordRequired('user-access-create:'.$user->id);

            return $user->refresh();
        });

        return $user;
    }

    /**
     * @param  array{name:string,email:string,password?:string|null,role:string,site_scope_mode:string,access_enabled:bool}  $attributes
     * @param  list<string>  $deniedPermissions
     */
    public function update(User $user, array $attributes, array $deniedPermissions): User
    {
        $role = GatewayRole::from((string) $attributes['role']);
        $enabled = (bool) $attributes['access_enabled'];
        $scope = $role === GatewayRole::Owner
            ? SiteScopeMode::All
            : SiteScopeMode::from((string) $attributes['site_scope_mode']);

        DB::transaction(function () use ($user, $attributes, $role, $enabled, $scope, $deniedPermissions): void {
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
                'site_scope_mode' => $scope->value,
                'access_enabled' => $enabled,
            ];

            if (isset($attributes['password']) && $attributes['password'] !== '') {
                $values['password'] = $attributes['password'];
            }

            $lockedUser->fill($values)->save();
            $this->replaceGlobalDenials($lockedUser, $role, $deniedPermissions);
            $this->normalizeOwnerState($lockedUser, $role);
            $this->recordRequired('user-access-update:'.$lockedUser->id);
        });

        return $user->refresh();
    }

    /** @param list<string> $deniedPermissions */
    public function updateSiteRule(
        User $user,
        Site $site,
        string $accessRule,
        array $deniedPermissions,
    ): void {
        if (in_array($accessRule, ['inherit', 'allow', 'deny'], true) === false) {
            throw new DomainException('invalid_site_rule');
        }

        DB::transaction(function () use ($user, $site, $accessRule, $deniedPermissions): void {
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            if ($this->role($lockedUser) === GatewayRole::Owner) {
                throw new DomainException('owner_unrestricted');
            }

            $identity = [
                'user_id' => $lockedUser->getKey(),
                'site_record_id' => $site->getKey(),
            ];

            if ($accessRule === 'inherit') {
                DB::table('user_site_access')->where($identity)->delete();
            } else {
                DB::table('user_site_access')->updateOrInsert(
                    $identity,
                    [
                        'allowed' => $accessRule === 'allow',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ],
                );
            }

            DB::table('user_site_permission_denials')->where($identity)->delete();

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
                DB::table('user_site_permission_denials')->insert($rows);
            }

            $this->recordRequired(sprintf(
                'user-site-access-update:%d:%s',
                $lockedUser->id,
                $site->site_id,
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
    public function siteRule(User $user, Site $site): array
    {
        $allowed = DB::table('user_site_access')
            ->where('user_id', $user->getKey())
            ->where('site_record_id', $site->getKey())
            ->value('allowed');

        $accessRule = $allowed === null
            ? 'inherit'
            : ((bool) $allowed ? 'allow' : 'deny');

        return [
            'access_rule' => $accessRule,
            'denied_permissions' => DB::table('user_site_permission_denials')
                ->where('user_id', $user->getKey())
                ->where('site_record_id', $site->getKey())
                ->orderBy('permission')
                ->pluck('permission')
                ->map(static fn (mixed $value): string => (string) $value)
                ->all(),
        ];
    }

    /**
     * @param  list<Site>  $sites
     * @return array<string,array{access_rule:string,denied_count:int}>
     */
    public function siteRuleSummaries(User $user, array $sites): array
    {
        $ids = array_map(
            static fn (Site $site): string => (string) $site->getKey(),
            $sites,
        );

        if ($ids === []) {
            return [];
        }

        $access = DB::table('user_site_access')
            ->where('user_id', $user->getKey())
            ->whereIn('site_record_id', $ids)
            ->pluck('allowed', 'site_record_id');

        $deniedCounts = DB::table('user_site_permission_denials')
            ->selectRaw('site_record_id, COUNT(*) as aggregate')
            ->where('user_id', $user->getKey())
            ->whereIn('site_record_id', $ids)
            ->groupBy('site_record_id')
            ->pluck('aggregate', 'site_record_id');

        $result = [];
        foreach ($sites as $site) {
            $id = (string) $site->getKey();
            $allowed = $access->get($id);

            $result[$id] = [
                'access_rule' => $allowed === null ? 'inherit' : ((bool) $allowed ? 'allow' : 'deny'),
                'denied_count' => (int) ($deniedCounts->get($id) ?? 0),
            ];
        }

        return $result;
    }

    /** @return list<GatewayPermission> */
    public function sitePermissions(): array
    {
        return [
            GatewayPermission::SitesView,
            GatewayPermission::SitesUpdate,
            GatewayPermission::SitesRemove,
            GatewayPermission::ConnectionsConnect,
            GatewayPermission::ConnectionsReconnect,
            GatewayPermission::ConnectionsDisconnect,
            GatewayPermission::ConnectionsTest,
            GatewayPermission::AbilitiesInspect,
            GatewayPermission::AbilitiesExecuteReadonly,
            GatewayPermission::AbilitiesExecuteMutating,
            GatewayPermission::AbilitiesExecuteDestructive,
            GatewayPermission::AbilitiesExecuteUnclassified,
        ];
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
        bool $siteOnly = false,
    ): array {
        if ($role === GatewayRole::Owner) {
            return [];
        }

        $rolePermissions = $role->permissions();
        $sitePermissions = $siteOnly ? $this->sitePermissions() : null;
        $result = [];

        foreach (array_unique($values) as $value) {
            $permission = GatewayPermission::tryFrom($value);
            if ($permission === null
                || in_array($permission, $rolePermissions, true) === false
                || ($sitePermissions !== null && in_array($permission, $sitePermissions, true) === false)) {
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

        $user->forceFill(['site_scope_mode' => SiteScopeMode::All->value])->save();

        DB::table('user_permission_denials')->where('user_id', $user->getKey())->delete();
        DB::table('user_site_access')->where('user_id', $user->getKey())->delete();
        DB::table('user_site_permission_denials')->where('user_id', $user->getKey())->delete();
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
