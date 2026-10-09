<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use DomainException;
use Illuminate\Support\Facades\DB;

final readonly class TargetGroupManager
{
    public function __construct(private ActivityRecorder $activity) {}

    /** @param list<string> $deniedPermissions */
    public function create(string $name, array $deniedPermissions): TargetGroup
    {
        return DB::transaction(function () use ($name, $deniedPermissions): TargetGroup {
            $group = TargetGroup::query()->create(['name' => trim($name)]);
            $this->replacePermissionDenials($group, $deniedPermissions);
            $this->recordRequired('target-group-create:'.$group->id);

            return $group->refresh();
        });
    }

    /** @param list<string> $deniedPermissions */
    public function update(TargetGroup $group, string $name, array $deniedPermissions): TargetGroup
    {
        DB::transaction(function () use ($group, $name, $deniedPermissions): void {
            $locked = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $locked->fill(['name' => trim($name)])->save();
            $this->replacePermissionDenials($locked, $deniedPermissions);
            $this->recordRequired('target-group-update:'.$locked->id);
        });

        return $group->refresh();
    }

    public function delete(TargetGroup $group): void
    {
        DB::transaction(function () use ($group): void {
            $locked = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $groupId = (string) $locked->id;
            $locked->delete();
            $this->recordRequired('target-group-delete:'.$groupId);
        });
    }

    public function updateTargetMembership(TargetGroup $group, Target $target, bool $assigned): void
    {
        DB::transaction(function () use ($group, $target, $assigned): void {
            $lockedGroup = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $lockedTarget = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $identity = [
                'target_group_id' => $lockedGroup->getKey(),
                'target_record_id' => $lockedTarget->getKey(),
            ];

            if ($assigned) {
                DB::table('target_group_targets')->updateOrInsert(
                    $identity,
                    ['created_at' => now(), 'updated_at' => now()],
                );
            } else {
                DB::table('target_group_targets')->where($identity)->delete();
            }

            $this->recordRequired(
                'target-group-target-update:'.$lockedGroup->id,
                $lockedTarget->target_id,
            );
        });
    }

    public function updateUserAssignment(TargetGroup $group, User $user, bool $assigned): void
    {
        DB::transaction(function () use ($group, $user, $assigned): void {
            $lockedGroup = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();

            if ($this->role($lockedUser) === GatewayRole::Owner) {
                throw new DomainException('owner_unrestricted');
            }

            $identity = [
                'target_group_id' => $lockedGroup->getKey(),
                'user_id' => $lockedUser->getKey(),
            ];

            if ($assigned) {
                DB::table('target_group_users')->updateOrInsert(
                    $identity,
                    ['created_at' => now(), 'updated_at' => now()],
                );
            } else {
                DB::table('target_group_users')->where($identity)->delete();
            }

            $this->recordRequired('target-group-user-update:'.$lockedGroup->id.':'.$lockedUser->id);
        });
    }

    /** @return list<string> */
    public function permissionDenials(TargetGroup $group): array
    {
        return DB::table('target_group_permission_denials')
            ->where('target_group_id', $group->getKey())
            ->orderBy('permission')
            ->pluck('permission')
            ->map(static fn (mixed $permission): string => (string) $permission)
            ->all();
    }

    /** @return list<GatewayPermission> */
    public function targetPermissions(): array
    {
        return GatewayPermission::targetScoped();
    }

    /**
     * @param  list<Target>  $targets
     * @return array<string,bool>
     */
    public function targetMembershipSummaries(TargetGroup $group, array $targets): array
    {
        $ids = array_map(
            static fn (Target $target): string => (string) $target->getKey(),
            $targets,
        );
        if ($ids === []) {
            return [];
        }

        $assigned = DB::table('target_group_targets')
            ->where('target_group_id', $group->getKey())
            ->whereIn('target_record_id', $ids)
            ->pluck('target_record_id')
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
    public function userAssignmentSummaries(TargetGroup $group, array $users): array
    {
        $ids = array_map(
            static fn (User $user): int => (int) $user->getKey(),
            $users,
        );
        if ($ids === []) {
            return [];
        }

        $assigned = DB::table('target_group_users')
            ->where('target_group_id', $group->getKey())
            ->whereIn('user_id', $ids)
            ->pluck('user_id')
            ->mapWithKeys(static fn (mixed $id): array => [(int) $id => true]);

        $result = [];
        foreach ($ids as $id) {
            $result[$id] = (bool) $assigned->get($id, false);
        }

        return $result;
    }

    public function targetIsAssigned(TargetGroup $group, Target $target): bool
    {
        return DB::table('target_group_targets')
            ->where('target_group_id', $group->getKey())
            ->where('target_record_id', $target->getKey())
            ->exists();
    }

    public function userIsAssigned(TargetGroup $group, User $user): bool
    {
        return DB::table('target_group_users')
            ->where('target_group_id', $group->getKey())
            ->where('user_id', $user->getKey())
            ->exists();
    }

    /** @param list<string> $values */
    private function replacePermissionDenials(TargetGroup $group, array $values): void
    {
        DB::table('target_group_permission_denials')
            ->where('target_group_id', $group->getKey())
            ->delete();

        $supported = GatewayPermission::targetScoped();
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

        DB::table('target_group_permission_denials')->insert(array_map(
            static fn (GatewayPermission $permission): array => [
                'target_group_id' => $group->getKey(),
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

    private function recordRequired(string $operation, ?string $targetId = null): void
    {
        $this->activity->recordRequired(
            CorrelationId::current(),
            $operation,
            'success',
            $targetId,
        );
    }
}
