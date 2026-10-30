<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use DomainException;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Facades\DB;

/** Bounded access-administration projections; these describe scope, not action grants. */
final readonly class AccessBatchCatalog
{
    public function __construct(private AccessControl $access) {}

    public function actor(User $actor): User
    {
        return AccessBatchGuard::actor($actor);
    }

    public function subject(AccessBatchContext $context, string $id): TargetGroup|User
    {
        return $context->subjectIsGroup()
            ? TargetGroup::query()->findOrFail($context->subjectId($id))
            : User::query()->findOrFail($context->subjectId($id));
    }

    /** @return array{id:string,name:string,detail:string,type:string,scope_mode:?string,unrestricted:bool,access_enabled:bool} */
    public function subjectData(TargetGroup|User $subject): array
    {
        if ($subject instanceof TargetGroup) {
            return [
                'id' => (string) $subject->getKey(), 'name' => (string) $subject->name,
                'detail' => __('Target group'), 'type' => 'group', 'scope_mode' => null,
                'unrestricted' => false, 'access_enabled' => true,
            ];
        }

        return [
            'id' => (string) $subject->getKey(), 'name' => (string) $subject->name,
            'detail' => (string) $subject->email, 'type' => 'user',
            'scope_mode' => (string) $subject->getRawOriginal('target_scope_mode'),
            'unrestricted' => AccessBatchGuard::isOwner($subject),
            'access_enabled' => (bool) $subject->access_enabled,
        ];
    }

    /** @param array<string,mixed> $filters
     * @param  array<mixed>  $selectedIds
     * @return array<string,mixed>
     */
    public function page(User $actor, string $contextValue, string $subjectId, array $filters = [], array $selectedIds = []): array
    {
        $actor = $this->actor($actor);
        $context = AccessBatchContext::parse($contextValue);
        $subject = $this->subject($context, $subjectId);
        $selected = $context->selection($selectedIds, true);
        $page = filter_var($filters['page'] ?? 1, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000000]]);
        $search = $filters['search'] ?? '';
        $membership = $filters['membership'] ?? 'members';
        $connector = $filters['connector_type'] ?? '';
        if ($page === false || ! is_string($search) || mb_strlen($search) > 160
            || ! is_string($connector) || strlen($connector) > 64
            || ! in_array($membership, ['members', 'available', 'all', 'selected'], true)) {
            throw new DomainException('batch_invalid_selection');
        }
        $search = trim($search);
        $connector = trim($connector);
        if ($context->itemsAreTargets()) {
            $query = $this->access->scopeTargets(Target::query(), $actor, GatewayPermission::TargetsView);
            if ($search !== '') {
                $query->where(static fn (Builder $q) => $q->where('display_name', 'like', '%'.$search.'%')
                    ->orWhere('target_id', 'like', '%'.$search.'%'));
            }
            if ($connector !== '') {
                $query->where('connector_type', $connector);
            }
            if ($membership === 'members' || $membership === 'available') {
                $this->targetMembershipFilter($query, $context, $subject, $membership === 'members');
            }
            if ($membership === 'selected') {
                $query->whereIn('targets.id', $selected);
            }
            $rows = $query->orderBy('display_name')->orderBy('target_id')
                ->offset(($page - 1) * AccessBatchContext::PAGE_SIZE)
                ->limit(AccessBatchContext::PAGE_SIZE + 1)
                ->get(['targets.id', 'targets.target_id', 'targets.display_name', 'targets.connector_type']);
            $hasMore = $rows->count() > AccessBatchContext::PAGE_SIZE;
            $models = $rows->take(AccessBatchContext::PAGE_SIZE)->values()->all();
            $items = $this->targetRows($context, $subject, $models);
        } elseif ($context === AccessBatchContext::GroupUsers) {
            $query = User::query();
            if ($search !== '') {
                $query->where(static fn (Builder $q) => $q->where('name', 'like', '%'.$search.'%')
                    ->orWhere('email', 'like', '%'.$search.'%'));
            }
            if ($membership === 'members' || $membership === 'available') {
                $query->whereExists(static fn (QueryBuilder $q) => $q->selectRaw('1')
                    ->from('target_group_users')->whereColumn('target_group_users.user_id', 'users.id')
                    ->where('target_group_id', $subject->getKey()), 'and', $membership === 'available');
            }
            if ($membership === 'selected') {
                $query->whereIn('id', $selected);
            }
            $rows = $query->orderBy('name')->orderBy('id')
                ->offset(($page - 1) * AccessBatchContext::PAGE_SIZE)
                ->limit(AccessBatchContext::PAGE_SIZE + 1)
                ->get(['id', 'name', 'email', 'role', 'access_enabled', 'target_scope_mode']);
            $hasMore = $rows->count() > AccessBatchContext::PAGE_SIZE;
            $models = $rows->take(AccessBatchContext::PAGE_SIZE)->values();
            $members = DB::table('target_group_users')->where('target_group_id', $subject->getKey())
                ->whereIn('user_id', $models->pluck('id'))->pluck('user_id')->map(static fn ($id): string => (string) $id)->all();
            $items = $models->map(fn (User $user): array => $this->memberRow(
                (string) $user->getKey(), (string) $user->name, (string) $user->email,
                in_array((string) $user->getKey(), $members, true),
                ! AccessBatchGuard::isOwner($user),
                AccessBatchGuard::isOwner($user) ? __('Owners remain unrestricted.') : null,
            ))->all();
        } else {
            $query = TargetGroup::query();
            if ($search !== '') {
                $query->where('name', 'like', '%'.$search.'%');
            }
            if ($membership === 'members' || $membership === 'available') {
                $query->whereExists(static fn (QueryBuilder $q) => $q->selectRaw('1')
                    ->from('target_group_users')->whereColumn('target_group_users.target_group_id', 'target_groups.id')
                    ->where('user_id', $subject->getKey()), 'and', $membership === 'available');
            }
            if ($membership === 'selected') {
                $query->whereIn('id', $selected);
            }
            $rows = $query->orderBy('name')->orderBy('id')
                ->offset(($page - 1) * AccessBatchContext::PAGE_SIZE)
                ->limit(AccessBatchContext::PAGE_SIZE + 1)->get(['id', 'name']);
            $hasMore = $rows->count() > AccessBatchContext::PAGE_SIZE;
            $models = $rows->take(AccessBatchContext::PAGE_SIZE)->values();
            $members = DB::table('target_group_users')->where('user_id', $subject->getKey())
                ->whereIn('target_group_id', $models->pluck('id'))->pluck('target_group_id')->all();
            $unrestricted = $subject instanceof User && AccessBatchGuard::isOwner($subject);
            $items = $models->map(fn (TargetGroup $group): array => $this->memberRow(
                (string) $group->getKey(), (string) $group->name, __('Target group'),
                in_array((string) $group->getKey(), $members, true), ! $unrestricted,
                $unrestricted ? __('Owners remain unrestricted.') : null,
            ))->all();
        }

        $unavailable = [];
        if ($membership === 'selected' && $selected !== []) {
            $existingIds = match (true) {
                $context->itemsAreTargets() => $this->access->scopeTargets(Target::query(), $actor, GatewayPermission::TargetsView)
                    ->whereIn('id', $selected)->pluck('id')->all(),
                $context === AccessBatchContext::GroupUsers => User::query()->whereIn('id', $selected)->pluck('id')
                    ->map(static fn ($id): string => (string) $id)->all(),
                default => TargetGroup::query()->whereIn('id', $selected)->pluck('id')->all(),
            };
            $unavailable = array_values(array_diff($selected, $existingIds));
        }

        return [
            'context' => $context->value, 'subject' => $this->subjectData($subject),
            'items' => $items, 'page' => $page, 'per_page' => AccessBatchContext::PAGE_SIZE,
            'has_more' => $hasMore, 'selected_count' => count($selected), 'unavailable_ids' => $unavailable,
        ];
    }

    /** @param Builder<Target> $query */
    private function targetMembershipFilter(Builder $query, AccessBatchContext $context, TargetGroup|User $subject, bool $members): void
    {
        if ($context === AccessBatchContext::GroupTargets) {
            $query->whereExists(static fn (QueryBuilder $q) => $q->selectRaw('1')->from('target_group_targets')
                ->whereColumn('target_group_targets.target_record_id', 'targets.id')
                ->where('target_group_id', $subject->getKey()), 'and', ! $members);

            return;
        }
        if (! $subject instanceof User) {
            throw new DomainException('batch_invalid_context');
        }
        if ($subject->getRawOriginal('target_scope_mode') === TargetScopeMode::All->value || AccessBatchGuard::isOwner($subject)) {
            if (! $members) {
                $query->whereRaw('1 = 0');
            }

            return;
        }
        $query->where(function (Builder $q) use ($subject, $members): void {
            if ($members) {
                $q->whereExists(fn (QueryBuilder $sub) => $this->directScopeSubquery($sub, $subject))
                    ->orWhereExists(fn (QueryBuilder $sub) => $this->groupScopeSubquery($sub, $subject));
            } else {
                $q->whereNotExists(fn (QueryBuilder $sub) => $this->directScopeSubquery($sub, $subject)->where('allowed', true))
                    ->whereNotExists(fn (QueryBuilder $sub) => $this->groupScopeSubquery($sub, $subject));
            }
        });
    }

    private function directScopeSubquery(QueryBuilder $query, User $user): QueryBuilder
    {
        return $query->selectRaw('1')->from('user_target_access')
            ->whereColumn('user_target_access.target_record_id', 'targets.id')->where('user_id', $user->getKey());
    }

    private function groupScopeSubquery(QueryBuilder $query, User $user): QueryBuilder
    {
        return $query->selectRaw('1')->from('target_group_targets as group_targets')
            ->join('target_group_users as group_users', 'group_users.target_group_id', '=', 'group_targets.target_group_id')
            ->whereColumn('group_targets.target_record_id', 'targets.id')->where('group_users.user_id', $user->getKey());
    }

    /** @param list<Target> $targets
     * @return list<array<string,mixed>>
     */
    private function targetRows(AccessBatchContext $context, TargetGroup|User $subject, array $targets): array
    {
        $ids = array_map(static fn (Target $target): string => (string) $target->getKey(), $targets);
        if ($context === AccessBatchContext::GroupTargets) {
            $members = DB::table('target_group_targets')->where('target_group_id', $subject->getKey())
                ->whereIn('target_record_id', $ids)->pluck('target_record_id')->all();

            return array_map(fn (Target $target): array => [
                ...$this->memberRow((string) $target->getKey(), (string) $target->display_name, (string) $target->target_id,
                    in_array((string) $target->getKey(), $members, true)),
                'connector_type' => (string) $target->connector_type, 'target_id' => (string) $target->target_id,
            ], $targets);
        }
        if (! $subject instanceof User) {
            throw new DomainException('batch_invalid_context');
        }
        $rules = DB::table('user_target_access')->where('user_id', $subject->getKey())
            ->whereIn('target_record_id', $ids)->pluck('allowed', 'target_record_id');
        $denials = DB::table('user_target_permission_denials')->where('user_id', $subject->getKey())
            ->whereIn('target_record_id', $ids)->selectRaw('target_record_id, COUNT(*) as aggregate')
            ->groupBy('target_record_id')->pluck('aggregate', 'target_record_id');
        $groups = DB::table('target_group_targets as gt')
            ->join('target_group_users as gu', 'gu.target_group_id', '=', 'gt.target_group_id')
            ->where('gu.user_id', $subject->getKey())->whereIn('gt.target_record_id', $ids)
            ->selectRaw('gt.target_record_id, COUNT(*) as aggregate')
            ->groupBy('gt.target_record_id')->pluck('aggregate', 'target_record_id');
        $unrestricted = AccessBatchGuard::isOwner($subject);
        $all = $subject->getRawOriginal('target_scope_mode') === TargetScopeMode::All->value || $unrestricted;

        return array_map(function (Target $target) use ($rules, $denials, $groups, $unrestricted, $all): array {
            $id = (string) $target->getKey();
            $allowed = $rules->get($id);
            $rule = $allowed === null ? 'inherit' : ((bool) $allowed ? 'allow' : 'deny');
            $groupCount = (int) $groups->get($id, 0);
            $path = match (true) {
                $unrestricted => __('Owner recovery scope'),
                $rule === 'deny' => __('Explicitly blocked'),
                $all => __('All Targets scope'),
                $rule === 'allow' => __('Direct rule'),
                $groupCount > 0 => __('Group membership (:count)', ['count' => $groupCount]),
                default => __('Not assigned'),
            };

            return [
                ...$this->memberRow($id, (string) $target->display_name, (string) $target->target_id,
                    $rule !== 'inherit' || $all || $groupCount > 0, ! $unrestricted,
                    $unrestricted ? __('Owners remain unrestricted.') : null),
                'target_id' => (string) $target->target_id, 'connector_type' => (string) $target->connector_type,
                'access_rule' => $rule, 'scope_path' => $path, 'restriction_count' => (int) $denials->get($id, 0),
            ];
        }, $targets);
    }

    /** @return array<string,mixed> */
    private function memberRow(string $id, string $label, string $detail, bool $member, bool $eligible = true, ?string $reason = null): array
    {
        return [
            'id' => $id, 'label' => $label, 'detail' => $detail, 'connector_type' => null,
            'member' => $member, 'access_rule' => null, 'scope_path' => null, 'restriction_count' => 0,
            'eligible' => $eligible, 'unavailable_reason' => $reason, 'target_id' => null,
        ];
    }
}
