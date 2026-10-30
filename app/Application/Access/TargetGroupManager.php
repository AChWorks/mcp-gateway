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
use Illuminate\Support\Facades\Gate;

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
    public function update(TargetGroup $group, string $name, array $deniedPermissions, bool $sshReviewed = false, ?string $expectedRevision = null): TargetGroup
    {
        DB::transaction(function () use ($group, $name, $deniedPermissions, $sshReviewed, $expectedRevision): void {
            $locked = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            // The same group-row lock is acquired by membership mutation
            // paths. Compare the originally displayed denial snapshot here,
            // never against a pre-lock controller lookup or an old checkbox.
            $current = $this->permissionDenials($locked);
            $requestedSsh = $this->sshDenials($deniedPermissions);
            $currentSsh = $this->sshDenials($current);
            $sshChanged = $requestedSsh !== $currentSsh;
            $this->requireSshReview($sshChanged, $sshReviewed);
            $currentRevision = AuthorizationRevision::groupDenials($current);
            if ($expectedRevision !== null && ! hash_equals($currentRevision, $expectedRevision)
                || $sshChanged && $expectedRevision === null) {
                throw new DomainException('group_revision_stale');
            }
            $locked->fill(['name' => trim($name)])->save();
            $this->replacePermissionDenials($locked, $deniedPermissions);
            $this->recordRequired('target-group-update:'.$locked->id);
        });

        return $group->refresh();
    }

    public function delete(TargetGroup $group, bool $sshReviewed = false): void
    {
        DB::transaction(function () use ($group, $sshReviewed): void {
            $locked = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            // Deleting a group can drop its SSH denial while an overlapping
            // group/direct rule still supplies positive Target reachability.
            $this->requireSshReview($this->hasSshTargets($locked) || $this->hasSshDenials($locked), $sshReviewed);
            $groupId = (string) $locked->id;
            $locked->delete();
            $this->recordRequired('target-group-delete:'.$groupId);
        });
    }

    public function updateTargetMembership(TargetGroup $group, Target $target, bool $assigned, bool $sshReviewed = false): void
    {
        DB::transaction(function () use ($group, $target, $assigned, $sshReviewed): void {
            $lockedGroup = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $lockedTarget = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $identity = [
                'target_group_id' => $lockedGroup->getKey(),
                'target_record_id' => $lockedTarget->getKey(),
            ];
            if (DB::table('target_group_targets')->where($identity)->exists() === $assigned) {
                return; // No-op: no change to authorization and no audit mutation.
            }
            $this->requireSshReview((string) $lockedTarget->connector_type === 'ssh_direct', $sshReviewed);

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
                $lockedTarget,
            );
        });
    }

    public function updateUserAssignment(TargetGroup $group, User $user, bool $assigned, bool $sshReviewed = false): void
    {
        DB::transaction(function () use ($group, $user, $assigned, $sshReviewed): void {
            $lockedGroup = TargetGroup::query()->whereKey($group->getKey())->lockForUpdate()->firstOrFail();
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();

            if ($this->role($lockedUser) === GatewayRole::Owner) {
                throw new DomainException('owner_unrestricted');
            }

            $identity = [
                'target_group_id' => $lockedGroup->getKey(),
                'user_id' => $lockedUser->getKey(),
            ];
            if (DB::table('target_group_users')->where($identity)->exists() === $assigned) {
                return;
            }
            $this->requireSshReview(
                $this->hasSshTargets($lockedGroup) || $this->hasSshDenials($lockedGroup), $sshReviewed,
            );

            if ($assigned) {
                DB::table('target_group_users')->updateOrInsert(
                    $identity,
                    ['created_at' => now(), 'updated_at' => now()],
                );
            } else {
                DB::table('target_group_users')->where($identity)->delete();
                // Revoked membership must not silently recover an earlier
                // positive publisher grant on later re-assignment.
                DB::table('wordpress_publish_group_grants')
                    ->where('user_id', $lockedUser->getKey())
                    ->where('target_group_id', $lockedGroup->getKey())->delete();
            }

            $this->recordRequired('target-group-user-update:'.$lockedGroup->id.':'.$lockedUser->id);
        });
    }

    /**
     * Apply one bounded relationship delta, never replace a paginated collection.
     * The workflow holds its review snapshot locks before calling this method;
     * direct callers still receive fresh actor, identity, Owner and SSH checks.
     *
     * @param  list<string>  $ids
     */
    public function updateMemberships(
        User $actor,
        AccessBatchContext $context,
        string $subjectId,
        array $ids,
        bool $assigned,
        bool $sshReviewed,
        string $correlationId,
    ): int {
        if ($context === AccessBatchContext::UserTargets) {
            throw new DomainException('batch_invalid_context');
        }
        $subjectId = $context->subjectId($subjectId);
        $ids = $context->selection($ids);
        $actor = AccessBatchGuard::actor($actor);

        return DB::transaction(function () use ($actor, $context, $subjectId, $ids, $assigned, $sshReviewed, $correlationId): int {
            $groupIds = $context->subjectIsGroup() ? [$subjectId] : $ids;
            $groups = TargetGroup::query()->whereIn('id', $groupIds)->orderBy('id')->lockForUpdate()->get()->keyBy('id');
            if ($groups->count() !== count($groupIds)) {
                throw new DomainException('batch_selection_unavailable');
            }
            $userIds = match ($context) {
                AccessBatchContext::GroupUsers => $ids,
                AccessBatchContext::UserGroups => [$subjectId],
                default => [],
            };
            $lockUsers = array_values(array_unique([(string) $actor->getKey(), ...$userIds]));
            sort($lockUsers, SORT_STRING);
            $users = AccessBatchGuard::lockUsers($lockUsers);
            if ($users->count() !== count($lockUsers)) {
                throw new DomainException('batch_selection_unavailable');
            }
            $actor = AccessBatchGuard::actor($users->get($actor->getKey()) ?? $actor);
            foreach ($userIds as $id) {
                if (($selectedUser = $users->get($id)) instanceof User && AccessBatchGuard::isOwner($selectedUser)) {
                    throw new DomainException('owner_unrestricted');
                }
            }
            $targets = Target::query()->whereIn('id', $context === AccessBatchContext::GroupTargets ? $ids : [])
                ->orderBy('id')->lockForUpdate()->get()->keyBy('id');
            if ($context === AccessBatchContext::GroupTargets && $targets->count() !== count($ids)) {
                throw new DomainException('batch_selection_unavailable');
            }
            $table = $context === AccessBatchContext::GroupTargets ? 'target_group_targets' : 'target_group_users';
            $key = match ($context) {
                AccessBatchContext::GroupTargets => 'target_record_id',
                AccessBatchContext::GroupUsers => 'user_id',
                default => 'target_group_id',
            };
            $query = DB::table($table)->where(
                $context->subjectIsGroup() ? 'target_group_id' : 'user_id', $subjectId,
            )->whereIn($key, $ids);
            $existing = $query->pluck($key)->map(static fn ($id): string => (string) $id)->all();
            $changed = array_values(array_filter($ids, static fn (string $id): bool => in_array($id, $existing, true) !== $assigned));
            if ($changed === []) {
                return 0;
            }
            $impact = match ($context) {
                AccessBatchContext::GroupTargets => $targets->only($changed)->contains(
                    static fn (Target $target): bool => $target->connector_type === 'ssh_direct'),
                AccessBatchContext::GroupUsers => $this->hasSshAccessImpact($groups->get($subjectId) ?? throw new DomainException('batch_selection_unavailable')),
                default => $this->sshImpactGroupIds($changed) !== [],
            };
            AccessBatchGuard::ssh($actor, $impact, $sshReviewed);
            if ($assigned) {
                $rows = [];
                foreach ($changed as $id) {
                    $rows[] = [
                        'target_group_id' => $context->subjectIsGroup() ? $subjectId : $id,
                        $context === AccessBatchContext::GroupTargets ? 'target_record_id' : 'user_id' => $context->subjectIsGroup() ? $id : $subjectId,
                        'created_at' => now(), 'updated_at' => now(),
                    ];
                }
                DB::table($table)->insert($rows);
            } else {
                DB::table($table)->where(
                    $context->subjectIsGroup() ? 'target_group_id' : 'user_id', $subjectId,
                )->whereIn($key, $changed)->delete();
                if ($context !== AccessBatchContext::GroupTargets) {
                    // Both directions of the UI use the existing revocation rule.
                    DB::table('wordpress_publish_group_grants')->where(
                        $context->subjectIsGroup() ? 'target_group_id' : 'user_id', $subjectId,
                    )->whereIn($key, $changed)->delete();
                }
            }
            foreach ($changed as $id) {
                if ($context === AccessBatchContext::GroupTargets) {
                    $this->activity->recordRequired($correlationId, 'target-group-target-update:'.$subjectId, 'success', $targets->get($id));
                } else {
                    $groupId = $context->subjectIsGroup() ? $subjectId : $id;
                    $userId = $context->subjectIsGroup() ? $id : $subjectId;
                    $this->activity->recordRequired($correlationId, 'target-group-user-update:'.$groupId.':'.$userId, 'success');
                }
            }

            return count($changed);
        });
    }

    /** @param list<string> $ids
     * @return list<string>
     */
    public function sshImpactGroupIds(array $ids): array
    {
        if ($ids === []) {
            return [];
        }
        $targets = DB::table('target_group_targets as memberships')
            ->join('targets', 'targets.id', '=', 'memberships.target_record_id')
            ->whereIn('memberships.target_group_id', $ids)->where('targets.connector_type', 'ssh_direct')
            ->distinct()->pluck('memberships.target_group_id')->all();
        $denials = DB::table('target_group_permission_denials')->whereIn('target_group_id', $ids)
            ->where('permission', 'like', 'ssh.%')->distinct()->pluck('target_group_id')->all();

        return array_values(array_unique([...$targets, ...$denials]));
    }

    /** Optimistic revision bound to the full sorted denial set shown to the Owner. */
    public function denialRevision(TargetGroup $group): string
    {
        return AuthorizationRevision::groupDenials($this->permissionDenials($group));
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

    /** @param list<string> $denials
     * @return list<string>
     */
    private function sshDenials(array $denials): array
    {
        $ssh = array_values(array_unique(array_filter(
            $denials, static fn (string $value): bool => str_starts_with($value, 'ssh.'),
        )));
        sort($ssh);

        return $ssh;
    }

    /** Read-only UI snapshot; mutation paths independently recheck under the group lock. */
    public function hasSshAccessImpact(TargetGroup $group): bool
    {
        return $this->hasSshTargets($group) || $this->hasSshDenials($group);
    }

    private function hasSshTargets(TargetGroup $group): bool
    {
        return DB::table('target_group_targets')
            ->join('targets', 'targets.id', '=', 'target_group_targets.target_record_id')
            ->where('target_group_targets.target_group_id', $group->getKey())
            ->where('targets.connector_type', 'ssh_direct')
            ->exists();
    }

    private function hasSshDenials(TargetGroup $group): bool
    {
        return DB::table('target_group_permission_denials')
            ->where('target_group_id', $group->getKey())
            ->where('permission', 'like', 'ssh.%')
            ->exists();
    }

    private function requireSshReview(bool $sshImpact, bool $reviewed): void
    {
        if (! $sshImpact) {
            return;
        }
        // Check authority AND explicit acknowledgement under the same group
        // row lock as the mutation, never against a stale edit-page snapshot.
        Gate::authorize(GatewayPermission::SecurityManage->value);
        if (! $reviewed) {
            throw new DomainException('ssh_confirmation_required');
        }
    }

    /** @param list<string> $values */
    private function replacePermissionDenials(TargetGroup $group, array $values): void
    {
        // Historical unsupported denial IDs are retained as inert evidence.
        DB::table('target_group_permission_denials')
            ->where('target_group_id', $group->getKey())
            ->whereIn('permission', array_map(
                static fn (GatewayPermission $permission): string => $permission->value,
                GatewayPermission::cases(),
            ))->delete();

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

    private function recordRequired(string $operation, ?Target $target = null): void
    {
        $this->activity->recordRequired(
            CorrelationId::current(),
            $operation,
            'success',
            $target,
        );
    }
}
