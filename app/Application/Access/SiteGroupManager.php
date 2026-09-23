<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteGroup;
use App\Domain\Sites\Site;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use DomainException;
use Illuminate\Support\Facades\DB;

final readonly class SiteGroupManager
{
    public function __construct(private ActivityRecorder $activity) {}

    /** @param list<string> $deniedPermissions */
    public function create(string $name, array $deniedPermissions): SiteGroup
    {
        return DB::transaction(function () use ($name, $deniedPermissions): SiteGroup {
            $group = SiteGroup::query()->create(['name' => trim($name)]);
            $this->replacePermissionDenials($group, $deniedPermissions);
            $this->recordRequired('site-group-create:'.$group->id);

            return $group->refresh();
        });
    }

    /** @param list<string> $deniedPermissions */
    public function update(SiteGroup $group, string $name, array $deniedPermissions): SiteGroup
    {
        DB::transaction(function () use ($group, $name, $deniedPermissions): void {
            $locked = SiteGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $locked->fill(['name' => trim($name)])->save();
            $this->replacePermissionDenials($locked, $deniedPermissions);
            $this->recordRequired('site-group-update:'.$locked->id);
        });

        return $group->refresh();
    }

    public function delete(SiteGroup $group): void
    {
        DB::transaction(function () use ($group): void {
            $locked = SiteGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $groupId = (string) $locked->id;
            $locked->delete();
            $this->recordRequired('site-group-delete:'.$groupId);
        });
    }

    public function updateSiteMembership(SiteGroup $group, Site $site, bool $assigned): void
    {
        DB::transaction(function () use ($group, $site, $assigned): void {
            $lockedGroup = SiteGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $lockedSite = Site::query()->whereKey($site->getKey())->lockForUpdate()->firstOrFail();
            $identity = [
                'site_group_id' => $lockedGroup->getKey(),
                'site_record_id' => $lockedSite->getKey(),
            ];

            if ($assigned) {
                DB::table('site_group_sites')->updateOrInsert(
                    $identity,
                    ['created_at' => now(), 'updated_at' => now()],
                );
            } else {
                DB::table('site_group_sites')->where($identity)->delete();
            }

            $this->recordRequired(
                'site-group-site-update:'.$lockedGroup->id,
                $lockedSite->site_id,
            );
        });
    }

    public function updateUserAssignment(SiteGroup $group, User $user, bool $assigned): void
    {
        DB::transaction(function () use ($group, $user, $assigned): void {
            $lockedGroup = SiteGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();

            if ($this->role($lockedUser) === GatewayRole::Owner) {
                throw new DomainException('owner_unrestricted');
            }

            $identity = [
                'site_group_id' => $lockedGroup->getKey(),
                'user_id' => $lockedUser->getKey(),
            ];

            if ($assigned) {
                DB::table('site_group_users')->updateOrInsert(
                    $identity,
                    ['created_at' => now(), 'updated_at' => now()],
                );
            } else {
                DB::table('site_group_users')->where($identity)->delete();
            }

            $this->recordRequired('site-group-user-update:'.$lockedGroup->id.':'.$lockedUser->id);
        });
    }

    /** @return list<string> */
    public function permissionDenials(SiteGroup $group): array
    {
        return DB::table('site_group_permission_denials')
            ->where('site_group_id', $group->getKey())
            ->orderBy('permission')
            ->pluck('permission')
            ->map(static fn (mixed $permission): string => (string) $permission)
            ->all();
    }

    /** @return list<GatewayPermission> */
    public function sitePermissions(): array
    {
        return GatewayPermission::siteScoped();
    }

    /**
     * @param  list<Site>  $sites
     * @return array<string,bool>
     */
    public function siteMembershipSummaries(SiteGroup $group, array $sites): array
    {
        $ids = array_map(
            static fn (Site $site): string => (string) $site->getKey(),
            $sites,
        );
        if ($ids === []) {
            return [];
        }

        $assigned = DB::table('site_group_sites')
            ->where('site_group_id', $group->getKey())
            ->whereIn('site_record_id', $ids)
            ->pluck('site_record_id')
            ->mapWithKeys(static fn (mixed $id): array => [(string) $id => true]);

        $result = [];
        foreach ($ids as $id) {
            $result[$id] = (bool) $assigned->get($id, false);
        }

        return $result;
    }

    /**
     * @param  list<User>  $users
     * @return array<int,bool>
     */
    public function userAssignmentSummaries(SiteGroup $group, array $users): array
    {
        $ids = array_map(
            static fn (User $user): int => (int) $user->getKey(),
            $users,
        );
        if ($ids === []) {
            return [];
        }

        $assigned = DB::table('site_group_users')
            ->where('site_group_id', $group->getKey())
            ->whereIn('user_id', $ids)
            ->pluck('user_id')
            ->mapWithKeys(static fn (mixed $id): array => [(int) $id => true]);

        $result = [];
        foreach ($ids as $id) {
            $result[$id] = (bool) $assigned->get($id, false);
        }

        return $result;
    }

    public function siteIsAssigned(SiteGroup $group, Site $site): bool
    {
        return DB::table('site_group_sites')
            ->where('site_group_id', $group->getKey())
            ->where('site_record_id', $site->getKey())
            ->exists();
    }

    public function userIsAssigned(SiteGroup $group, User $user): bool
    {
        return DB::table('site_group_users')
            ->where('site_group_id', $group->getKey())
            ->where('user_id', $user->getKey())
            ->exists();
    }

    /** @param list<string> $values */
    private function replacePermissionDenials(SiteGroup $group, array $values): void
    {
        DB::table('site_group_permission_denials')
            ->where('site_group_id', $group->getKey())
            ->delete();

        $supported = GatewayPermission::siteScoped();
        $permissions = [];
        foreach (array_unique($values) as $value) {
            $permission = GatewayPermission::tryFrom($value);
            if ($permission !== null && in_array($permission, $supported, true)) {
                $permissions[] = $permission;
            }
        }

        if ($permissions === []) {
            return;
        }

        DB::table('site_group_permission_denials')->insert(array_map(
            static fn (GatewayPermission $permission): array => [
                'site_group_id' => $group->getKey(),
                'permission' => $permission->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            $permissions,
        ));
    }

    private function role(User $user): GatewayRole
    {
        $role = $user->getAttribute('role');

        return $role instanceof GatewayRole
            ? $role
            : GatewayRole::from((string) $role);
    }

    private function recordRequired(string $operation, ?string $siteId = null): void
    {
        $this->activity->recordRequired(
            CorrelationId::current(),
            $operation,
            'success',
            $siteId,
        );
    }
}
