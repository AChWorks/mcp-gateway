<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use DomainException;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use JsonException;

/** Four explicit access-management flows share one bounded review/apply boundary. */
final readonly class AccessBatchWorkflow
{
    private const REVIEW_SECONDS = 600;

    public function __construct(
        private AccessBatchCatalog $catalog,
        private TargetGroupManager $groups,
        private UserAccessManager $users,
    ) {}

    /** @param array<string,mixed> $filters
     * @param  array<mixed>  $selectedIds
     * @return array<string,mixed>
     */
    public function page(User $actor, string $context, string $subjectId, array $filters = [], array $selectedIds = []): array
    {
        return $this->catalog->page($actor, $context, $subjectId, $filters, $selectedIds);
    }

    /** @param array<mixed> $ids
     * @return array<string,mixed>
     */
    public function review(User $actor, string $context, string $subjectId, string $intent, array $ids): array
    {
        $actor = $this->catalog->actor($actor);
        $context = AccessBatchContext::parse($context);
        $subjectId = $context->subjectId($subjectId);
        $intent = $context->intent($intent);
        $ids = $context->selection($ids);
        $discoveredGroups = $this->discoverGroups($context, $subjectId, $ids);

        return DB::transaction(function () use ($actor, $context, $subjectId, $intent, $ids, $discoveredGroups): array {
            $state = $this->state($actor, $context, $subjectId, $ids, $discoveredGroups);
            $review = $this->presentation($context, $intent, $ids, $state);
            $expires = now()->addSeconds(self::REVIEW_SECONDS);
            $token = Crypt::encryptString(json_encode([
                'version' => 1, 'actor' => (string) $actor->getKey(),
                'context' => $context->value, 'subject' => $subjectId,
                'intent' => $intent, 'ids' => $ids, 'snapshot' => $this->digest($state),
                'expires' => $expires->getTimestamp(),
            ], JSON_THROW_ON_ERROR));

            return [...$review, 'token' => $token, 'expires_at' => $expires->toIso8601String()];
        });
    }

    /** @return array{changed_count:int,unchanged_count:int,correlation_id:string} */
    public function apply(User $actor, string $context, string $subjectId, string $token, bool $sshReviewed = false): array
    {
        $actor = $this->catalog->actor($actor);
        $context = AccessBatchContext::parse($context);
        $subjectId = $context->subjectId($subjectId);
        $payload = $this->payload($actor, $context, $subjectId, $token);
        $intent = $context->intent($payload['intent']);
        $ids = $context->selection($payload['ids']);
        $discoveredGroups = $this->discoverGroups($context, $subjectId, $ids);

        return DB::transaction(function () use ($actor, $context, $subjectId, $intent, $ids, $payload, $sshReviewed, $discoveredGroups): array {
            $state = $this->state($actor, $context, $subjectId, $ids, $discoveredGroups);
            if ($payload['expires'] <= now()->getTimestamp()) {
                throw new DomainException('batch_review_expired');
            }
            if (! hash_equals($payload['snapshot'], $this->digest($state))) {
                throw new DomainException('batch_review_stale');
            }
            $review = $this->presentation($context, $intent, $ids, $state);
            if (! $review['can_apply']) {
                throw new DomainException('batch_blocked');
            }
            AccessBatchGuard::ssh($state['actor'], $review['requires_ssh_confirmation'], $sshReviewed);
            $correlation = (string) Str::uuid();
            if ($context === AccessBatchContext::UserTargets) {
                $revisions = [];
                foreach ($state['edges'] as $id => $edge) {
                    $revisions[$id] = AuthorizationRevision::targetRule($edge);
                }
                $changed = $this->users->updateTargetRules(
                    $state['actor'], $state['subject'], $ids, $intent, $revisions, $sshReviewed, $correlation,
                );
            } else {
                $changed = $this->groups->updateMemberships(
                    $state['actor'], $context, $subjectId, $ids, $intent === 'add', $sshReviewed, $correlation,
                );
            }

            return ['changed_count' => $changed, 'unchanged_count' => count($ids) - $changed, 'correlation_id' => $correlation];
        });
    }

    /** Discovery precedes the transaction so MariaDB REPEATABLE READ cannot
     * anchor later snapshot reads before the authoritative locks are held.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function discoverGroups(AccessBatchContext $context, string $subjectId, array $ids): array
    {
        return $context === AccessBatchContext::UserTargets
            ? DB::table('target_group_users as members')
                ->join('target_group_targets as targets', 'targets.target_group_id', '=', 'members.target_group_id')
                ->where('members.user_id', $subjectId)->whereIn('targets.target_record_id', $ids)
                ->distinct()->orderBy('members.target_group_id')->pluck('members.target_group_id')->all()
            : [];
    }

    /** @param list<string> $ids
     * @param  list<string>  $discoveredGroups
     * @return array<string,mixed>
     */
    private function state(User $actor, AccessBatchContext $context, string $subjectId, array $ids, array $discoveredGroups): array
    {
        $groupIds = match (true) {
            $context->subjectIsGroup() => [$subjectId],
            $context === AccessBatchContext::UserGroups => $ids,
            default => $discoveredGroups,
        };
        sort($groupIds, SORT_STRING);
        $groups = TargetGroup::query()->whereIn('id', $groupIds)->orderBy('id')->lockForUpdate()->get()->keyBy('id');
        if ($groups->count() !== count($groupIds)) {
            throw new DomainException('batch_selection_unavailable');
        }
        $selectedUsers = match ($context) {
            AccessBatchContext::GroupUsers => $ids,
            AccessBatchContext::UserGroups, AccessBatchContext::UserTargets => [$subjectId],
            default => [],
        };
        $userIds = array_values(array_unique([(string) $actor->getKey(), ...$selectedUsers]));
        $users = AccessBatchGuard::lockUsers($userIds);
        if ($users->count() !== count($userIds)) {
            throw new DomainException('batch_selection_unavailable');
        }
        $targets = Target::query()->whereIn('id', $context->itemsAreTargets() ? $ids : [])
            ->orderBy('id')->lockForUpdate()->get(['id', 'target_id', 'display_name', 'connector_type'])->keyBy('id');
        if ($context->itemsAreTargets() && $targets->count() !== count($ids)) {
            throw new DomainException('batch_selection_unavailable');
        }

        // All subsequent ordinary reads begin after Group -> User -> Target
        // locks. Every existing access writer serializes through these parents.
        $actor = $this->catalog->actor($users->get($actor->getKey()) ?? $actor);
        if ($context === AccessBatchContext::UserTargets
            && $this->discoverGroups($context, $subjectId, $ids) !== $discoveredGroups) {
            throw new DomainException('batch_review_stale');
        }
        $subject = $context->subjectIsGroup() ? $groups->get($subjectId) : $users->get($subjectId);
        if (! $subject instanceof TargetGroup && ! $subject instanceof User) {
            throw new DomainException('batch_selection_unavailable');
        }
        $globalDenials = DB::table('user_permission_denials')->whereIn('user_id', $userIds)
            ->orderBy('permission')->get()->groupBy('user_id');
        $groupDenials = DB::table('target_group_permission_denials')->whereIn('target_group_id', $groupIds)
            ->orderBy('permission')->get()->groupBy('target_group_id');
        $impact = $this->groups->sshImpactGroupIds($groupIds);
        $grantGroups = DB::table('wordpress_publish_group_grants')->whereIn('target_group_id', $groupIds)
            ->distinct()->pluck('target_group_id')->all();
        $profiles = [];
        foreach ($users as $user) {
            $profiles[(string) $user->getKey()] = [
                'id' => (string) $user->getKey(), 'name' => (string) $user->name, 'email' => (string) $user->email,
                'role' => (string) $user->getRawOriginal('role'), 'scope' => (string) $user->getRawOriginal('target_scope_mode'),
                'enabled' => (bool) $user->access_enabled, 'ai_enabled' => (bool) $user->ai_access_enabled,
                'denials' => $globalDenials->get($user->getKey(), collect())->pluck('permission')->all(),
            ];
        }
        $groupProfiles = [];
        foreach ($groups as $group) {
            $groupProfiles[(string) $group->getKey()] = [
                'id' => (string) $group->getKey(), 'name' => (string) $group->name,
                'denials' => $groupDenials->get($group->getKey(), collect())->pluck('permission')->all(),
                'ssh_impact' => in_array((string) $group->getKey(), $impact, true),
                'publishing' => in_array((string) $group->getKey(), $grantGroups, true),
            ];
        }
        $targetProfiles = [];
        foreach ($targets as $target) {
            $targetProfiles[(string) $target->getKey()] = [
                'id' => (string) $target->getKey(), 'label' => (string) $target->display_name,
                'target_id' => (string) $target->target_id, 'connector_type' => (string) $target->connector_type,
            ];
        }
        $edges = [];
        $grants = [];
        if ($context === AccessBatchContext::UserTargets) {
            $rules = DB::table('user_target_access')->where('user_id', $subjectId)
                ->whereIn('target_record_id', $ids)->pluck('allowed', 'target_record_id');
            $denials = DB::table('user_target_permission_denials')->where('user_id', $subjectId)
                ->whereIn('target_record_id', $ids)->orderBy('permission')->get()->groupBy('target_record_id');
            foreach ($ids as $id) {
                $allowed = $rules->get($id);
                $edges[$id] = [
                    'access_rule' => $allowed === null ? 'inherit' : ((bool) $allowed ? 'allow' : 'deny'),
                    'denied_permissions' => $denials->get($id, collect())->pluck('permission')->all(),
                ];
            }
        } else {
            $table = $context === AccessBatchContext::GroupTargets ? 'target_group_targets' : 'target_group_users';
            $key = match ($context) {
                AccessBatchContext::GroupTargets => 'target_record_id',
                AccessBatchContext::GroupUsers => 'user_id',
                default => 'target_group_id',
            };
            $existing = DB::table($table)->where(
                $context->subjectIsGroup() ? 'target_group_id' : 'user_id', $subjectId,
            )->whereIn($key, $ids)->pluck($key)->map(static fn ($id): string => (string) $id)->all();
            foreach ($ids as $id) {
                $edges[$id] = in_array($id, $existing, true);
            }
            if ($context !== AccessBatchContext::GroupTargets) {
                $granted = DB::table('wordpress_publish_group_grants')->where(
                    $context->subjectIsGroup() ? 'target_group_id' : 'user_id', $subjectId,
                )->whereIn($key, $ids)->pluck($key)->map(static fn ($id): string => (string) $id)->all();
                foreach ($ids as $id) {
                    $grants[$id] = in_array($id, $granted, true);
                }
            }
        }

        return [
            'actor' => $actor, 'subject' => $subject,
            'users' => $profiles, 'groups' => $groupProfiles, 'targets' => $targetProfiles,
            'edges' => $edges, 'grants' => $grants,
        ];
    }

    /** @param array<string,mixed> $state */
    private function digest(array $state): string
    {
        return hash('sha256', json_encode([
            'actor' => (string) $state['actor']->getKey(), 'users' => $state['users'],
            'groups' => $state['groups'], 'targets' => $state['targets'],
            'edges' => $state['edges'], 'grants' => $state['grants'],
        ], JSON_THROW_ON_ERROR));
    }

    /** @param list<string> $ids
     * @param  array<string,mixed>  $state
     * @return array<string,mixed>
     */
    private function presentation(AccessBatchContext $context, string $intent, array $ids, array $state): array
    {
        $items = [];
        $ssh = false;
        $warnings = [];
        $subject = $state['subject'];
        $ownerSubject = $subject instanceof User && AccessBatchGuard::isOwner($subject);
        foreach ($ids as $id) {
            $profile = match ($context) {
                AccessBatchContext::GroupTargets, AccessBatchContext::UserTargets => $state['targets'][$id],
                AccessBatchContext::GroupUsers => $state['users'][$id],
                AccessBatchContext::UserGroups => $state['groups'][$id],
            };
            $before = $context === AccessBatchContext::UserTargets
                ? $state['edges'][$id]['access_rule']
                : ($state['edges'][$id] ? 'Member' : 'Not a member');
            $after = $context === AccessBatchContext::UserTargets ? $intent : ($intent === 'add' ? 'Member' : 'Not a member');
            $blocked = null;
            if ($ownerSubject || ($context === AccessBatchContext::GroupUsers && $profile['role'] === GatewayRole::Owner->value)) {
                $blocked = __('Owners remain unrestricted and cannot receive narrowing assignments.');
            } elseif ($context === AccessBatchContext::UserTargets && $intent === 'allow' && $before === 'deny') {
                $blocked = __('An explicit direct Deny must be reviewed in the individual Target editor.');
            }
            $changed = $before !== $after;
            if ($changed && $blocked === null) {
                $ssh = $ssh || match ($context) {
                    AccessBatchContext::GroupTargets, AccessBatchContext::UserTargets => $profile['connector_type'] === 'ssh_direct',
                    AccessBatchContext::GroupUsers => $state['groups'][(string) $subject->getKey()]['ssh_impact'],
                    AccessBatchContext::UserGroups => $profile['ssh_impact'],
                };
                if ($context === AccessBatchContext::GroupTargets && $intent === 'add'
                    && $profile['connector_type'] === 'wp_ai_bridge'
                    && $state['groups'][(string) $subject->getKey()]['publishing']) {
                    $warnings[] = __('Adding WordPress Targets expands the scope of existing publishing grants for this named group.');
                }
                if (($state['grants'][$id] ?? false) && $intent === 'remove') {
                    $warnings[] = __('Removing this user-group membership revokes its publishing grants. Rejoining does not restore them.');
                }
            }
            $items[] = [
                'id' => $id, 'label' => $profile['label'] ?? $profile['name'],
                'detail' => $profile['target_id'] ?? $profile['email'] ?? __('Target group'),
                'connector_type' => $profile['connector_type'] ?? null,
                'before' => $before, 'after' => $after, 'changed' => $changed, 'blocked' => $blocked,
            ];
        }
        if ($context !== AccessBatchContext::UserTargets) {
            $warnings[] = __('Group membership supplies scope only. Role and global limits, overlapping group denials and direct Target Deny remain authoritative.');
            $warnings[] = __('Named groups are dynamic: their Target membership may change later.');
            if ($intent === 'remove') {
                $warnings[] = __('Removing a group relationship does not guarantee loss of access and may lift a group restriction through another existing path.');
            }
        } else {
            $warnings[] = __('Only the direct scope rule changes. Every existing per-Target restriction is preserved.');
            if ($intent === 'inherit') {
                $warnings[] = __('Inherited reachability can come from groups or All Targets scope; this is not a guaranteed access revocation.');
            }
        }
        if ($subject instanceof User && ! $subject->access_enabled) {
            $warnings[] = __('This account is disabled. Membership changes do not enable it.');
        }
        if ($subject instanceof User && $subject->getRawOriginal('target_scope_mode') === 'all') {
            $warnings[] = __('This account already uses All Targets scope. Direct rules and group restrictions remain exceptions; its scope mode will not change.');
        }
        $blockedCount = count(array_filter($items, static fn (array $item): bool => $item['blocked'] !== null));
        $changedCount = count(array_filter($items, static fn (array $item): bool => $item['blocked'] === null && $item['changed']));

        return [
            'context' => $context->value, 'subject' => $this->catalog->subjectData($subject),
            'intent' => $intent, 'ids' => $ids, 'items' => $items, 'changed_count' => $changedCount,
            'unchanged_count' => count($items) - $changedCount - $blockedCount, 'blocked_count' => $blockedCount,
            'can_apply' => $blockedCount === 0, 'requires_ssh_confirmation' => $ssh,
            'warnings' => array_values(array_unique($warnings)),
        ];
    }

    /** @return array{intent:string,ids:array<mixed>,snapshot:string,expires:int} */
    private function payload(User $actor, AccessBatchContext $context, string $subjectId, string $token): array
    {
        if (strlen($token) > 32768) {
            throw new DomainException('batch_review_invalid');
        }
        try {
            $payload = json_decode(Crypt::decryptString($token), true, 32, JSON_THROW_ON_ERROR);
        } catch (DecryptException|JsonException) {
            throw new DomainException('batch_review_invalid');
        }
        if (! is_array($payload) || ($payload['version'] ?? null) !== 1
            || ($payload['actor'] ?? null) !== (string) $actor->getKey()
            || ($payload['context'] ?? null) !== $context->value
            || ($payload['subject'] ?? null) !== $subjectId
            || ! is_string($payload['intent'] ?? null) || ! is_array($payload['ids'] ?? null)
            || ! is_string($payload['snapshot'] ?? null) || strlen($payload['snapshot']) !== 64
            || ! is_int($payload['expires'] ?? null)) {
            throw new DomainException('batch_review_invalid');
        }
        if ($payload['expires'] <= now()->getTimestamp()) {
            throw new DomainException('batch_review_expired');
        }

        return ['intent' => $payload['intent'], 'ids' => $payload['ids'], 'snapshot' => $payload['snapshot'], 'expires' => $payload['expires']];
    }
}
