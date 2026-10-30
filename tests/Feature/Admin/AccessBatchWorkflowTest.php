<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessBatchContext;
use App\Application\Access\AccessBatchWorkflow;
use App\Application\Access\TargetGroupManager;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use DomainException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('database-access')]
final class AccessBatchWorkflowTest extends TestCase
{
    use RefreshDatabase;

    private User $owner;

    private AccessBatchWorkflow $workflow;

    protected function setUp(): void
    {
        parent::setUp();
        $this->owner = $this->user(GatewayRole::Owner);
        $this->actingAs($this->owner);
        $this->app['request']->setUserResolver(static fn () => Auth::user());
        $this->workflow = app(AccessBatchWorkflow::class);
    }

    public function test_member_and_available_filters_are_applied_before_bounded_pagination_and_empty_selected_is_empty(): void
    {
        $group = $this->group();
        $targets = $this->fleet(63);
        $this->memberTargets($group, array_slice($targets, 0, 60));
        $page = $this->workflow->page($this->owner, 'group-targets', $group->id);
        self::assertCount(50, $page['items']);
        self::assertTrue($page['has_more']);
        self::assertSame(50, $page['per_page']);
        self::assertTrue(collect($page['items'])->every(static fn (array $item): bool => $item['member']));
        $next = $this->workflow->page($this->owner, 'group-targets', $group->id, ['page' => 2]);
        self::assertCount(10, $next['items']);
        self::assertFalse($next['has_more']);
        $available = $this->workflow->page($this->owner, 'group-targets', $group->id, ['membership' => 'available']);
        self::assertCount(3, $available['items']);
        self::assertTrue(collect($available['items'])->every(static fn (array $item): bool => ! $item['member']));
        self::assertSame([], $this->workflow->page($this->owner, 'group-targets', $group->id, ['membership' => 'selected'])['items']);
        $missing = strtolower((string) Str::ulid());
        $selected = $this->workflow->page($this->owner, 'group-targets', $group->id, ['membership' => 'selected'], [$targets[1], $missing]);
        self::assertCount(1, $selected['items']);
        self::assertSame([$missing], $selected['unavailable_ids']);
        self::assertSame(2, $selected['selected_count']);
    }

    public function test_group_target_delta_changes_only_explicit_ids_and_true_noops_have_no_audit(): void
    {
        $group = $this->group();
        $ids = $this->fleet(4);
        $this->memberTargets($group, [$ids[0], $ids[3]]);
        $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', [$ids[0], $ids[1], $ids[2], $ids[1]]);
        self::assertSame(2, $review['changed_count']);
        self::assertSame(1, $review['unchanged_count']);
        self::assertFalse($review['requires_ssh_confirmation']);
        $result = $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']);
        self::assertSame(2, $result['changed_count']);
        self::assertSame(1, $result['unchanged_count']);
        self::assertSame(4, DB::table('target_group_targets')->where('target_group_id', $group->id)->count());
        self::assertSame(2, DB::table('activity_events')->where('correlation_id', $result['correlation_id'])->count());
        $this->assertDatabaseHas('activity_events', ['actor_id' => (string) $this->owner->id, 'correlation_id' => $result['correlation_id']]);
        $again = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', [$ids[0], $ids[1], $ids[2]]);
        $noop = $this->workflow->apply($this->owner, 'group-targets', $group->id, $again['token']);
        self::assertSame(0, $noop['changed_count']);
        self::assertSame(0, DB::table('activity_events')->where('correlation_id', $noop['correlation_id'])->count());
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']));
    }

    public function test_mixed_ssh_batch_requires_explicit_review_for_add_and_remove_without_partial_changes(): void
    {
        $group = $this->group();
        $wp = $this->target();
        $ssh = $this->target('ssh_direct');
        $ids = [$wp->id, $ssh->id];
        $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', $ids);
        self::assertTrue($review['requires_ssh_confirmation']);
        $this->fails('ssh_confirmation_required', fn () => $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']));
        self::assertSame(0, DB::table('target_group_targets')->count());
        $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token'], true);
        $remove = $this->workflow->review($this->owner, 'group-targets', $group->id, 'remove', $ids);
        $this->fails('ssh_confirmation_required', fn () => $this->workflow->apply($this->owner, 'group-targets', $group->id, $remove['token']));
        self::assertSame(2, DB::table('target_group_targets')->count());
        $this->workflow->apply($this->owner, 'group-targets', $group->id, $remove['token'], true);
        self::assertSame(0, DB::table('target_group_targets')->count());
    }

    public function test_user_centric_groups_honor_denial_only_ssh_impact_and_revoke_publishing_without_resurrection(): void
    {
        $user = $this->user();
        $groups = [$this->group(), $this->group()];
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $groups[1]->id, 'permission' => 'ssh.command.run',
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $ids = array_map(static fn (TargetGroup $group): string => $group->id, $groups);
        $review = $this->workflow->review($this->owner, 'user-groups', (string) $user->id, 'add', $ids);
        self::assertTrue($review['requires_ssh_confirmation']);
        $this->fails('ssh_confirmation_required', fn () => $this->workflow->apply($this->owner, 'user-groups', (string) $user->id, $review['token']));
        self::assertSame(0, DB::table('target_group_users')->count());
        $this->workflow->apply($this->owner, 'user-groups', (string) $user->id, $review['token'], true);
        DB::table('wordpress_publish_group_grants')->insert([
            'target_group_id' => $groups[0]->id, 'user_id' => $user->id, 'created_at' => now(), 'updated_at' => now(),
        ]);
        $remove = $this->workflow->review($this->owner, 'user-groups', (string) $user->id, 'remove', $ids);
        self::assertStringContainsString('publishing grants', implode(' ', $remove['warnings']));
        $this->workflow->apply($this->owner, 'user-groups', (string) $user->id, $remove['token'], true);
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());
        $again = $this->workflow->review($this->owner, 'user-groups', (string) $user->id, 'add', $ids);
        $this->workflow->apply($this->owner, 'user-groups', (string) $user->id, $again['token'], true);
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());
        self::assertSame('selected', $user->refresh()->getRawOriginal('target_scope_mode'));
        self::assertFalse((bool) $user->ai_access_enabled);
    }

    public function test_group_centric_users_preserve_other_members_and_block_owner_assignments(): void
    {
        $group = $this->group();
        $first = $this->user();
        $second = $this->user();
        $review = $this->workflow->review($this->owner, 'group-users', $group->id, 'add', [(string) $first->id, (string) $second->id]);
        $this->workflow->apply($this->owner, 'group-users', $group->id, $review['token']);
        $remove = $this->workflow->review($this->owner, 'group-users', $group->id, 'remove', [(string) $first->id]);
        $this->workflow->apply($this->owner, 'group-users', $group->id, $remove['token']);
        $this->assertDatabaseHas('target_group_users', ['target_group_id' => $group->id, 'user_id' => $second->id]);
        $blocked = $this->workflow->review($this->owner, 'group-users', $group->id, 'add', [(string) $this->owner->id]);
        self::assertFalse($blocked['can_apply']);
        self::assertSame(1, $blocked['blocked_count']);
        $this->fails('batch_blocked', fn () => $this->workflow->apply($this->owner, 'group-users', $group->id, $blocked['token']));
        self::assertSame(1, DB::table('target_group_users')->count());
    }

    public function test_direct_scope_batches_preserve_distinct_active_and_historical_denials_for_every_target(): void
    {
        $user = $this->user();
        $targets = [$this->target(), $this->target()];
        $denials = [
            ['user_id' => $user->id, 'target_record_id' => $targets[0]->id, 'permission' => 'wordpress.abilities.execute.mutating'],
            ['user_id' => $user->id, 'target_record_id' => $targets[0]->id, 'permission' => 'historical.permission.key'],
            ['user_id' => $user->id, 'target_record_id' => $targets[1]->id, 'permission' => 'ssh.file.write'],
        ];
        foreach ($denials as $denial) {
            DB::table('user_target_permission_denials')->insert([...$denial, 'created_at' => now(), 'updated_at' => now()]);
        }
        $before = DB::table('user_target_permission_denials')->orderBy('id')->get()->toArray();
        $ids = array_map(static fn (Target $target): string => $target->id, $targets);
        foreach (['allow', 'deny', 'inherit'] as $intent) {
            $review = $this->workflow->review($this->owner, 'user-targets', (string) $user->id, $intent, $ids);
            $this->workflow->apply($this->owner, 'user-targets', (string) $user->id, $review['token']);
            self::assertEquals($before, DB::table('user_target_permission_denials')->orderBy('id')->get()->toArray());
        }
        self::assertSame(0, DB::table('user_target_access')->count());
        self::assertSame('selected', $user->refresh()->getRawOriginal('target_scope_mode'));
    }

    public function test_normal_direct_allow_cannot_replace_a_deny_or_partially_apply_other_selected_targets(): void
    {
        $user = $this->user();
        $wp = $this->target();
        $blocked = $this->target();
        DB::table('user_target_access')->insert([
            'user_id' => $user->id, 'target_record_id' => $blocked->id, 'allowed' => false,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $review = $this->workflow->review($this->owner, 'user-targets', (string) $user->id, 'allow', [$wp->id, $blocked->id]);
        self::assertSame(1, $review['blocked_count']);
        self::assertSame(1, $review['changed_count']);
        $this->fails('batch_blocked', fn () => $this->workflow->apply($this->owner, 'user-targets', (string) $user->id, $review['token']));
        self::assertSame(1, DB::table('user_target_access')->count());
        $this->assertDatabaseMissing('user_target_access', ['user_id' => $user->id, 'target_record_id' => $wp->id]);
    }

    public function test_review_rejects_changed_edges_denials_and_subject_role_without_any_writes(): void
    {
        $group = $this->group();
        $target = $this->target();
        $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', [$target->id]);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->id, 'permission' => 'ssh.file.write', 'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token'], true));
        self::assertSame(0, DB::table('target_group_targets')->count());

        $user = $this->user();
        $direct = $this->workflow->review($this->owner, 'user-targets', (string) $user->id, 'allow', [$target->id]);
        $user->forceFill(['role' => GatewayRole::Owner->value])->save();
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'user-targets', (string) $user->id, $direct['token']));
        self::assertSame(0, DB::table('user_target_access')->count());
    }

    public function test_expired_wrong_context_actor_and_unavailable_identity_reviews_fail_closed(): void
    {
        $group = $this->group();
        $target = $this->target();
        $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', [$target->id]);
        $this->fails('batch_review_invalid', fn () => $this->workflow->apply($this->owner, 'group-users', $group->id, $review['token']));
        $this->travel(11)->minutes();
        $this->fails('batch_review_expired', fn () => $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']));
        $this->travelBack();
        $other = $this->user(GatewayRole::Owner);
        $this->actingAs($other);
        $this->fails('batch_review_invalid', fn () => $this->workflow->apply($other, 'group-targets', $group->id, $review['token']));
        $this->actingAs($this->owner);
        $publicId = $target->target_id;
        $target->delete();
        $replacement = Target::query()->create([
            'target_id' => $publicId, 'display_name' => 'Replacement', 'connector_type' => 'wp_ai_bridge', 'connection_state' => 'disconnected',
        ]);
        $this->fails('batch_selection_unavailable', fn () => $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']));
        $this->assertDatabaseMissing('target_group_targets', ['target_record_id' => $replacement->id]);
    }

    public function test_selection_bound_and_identity_validation_precede_queries_and_denied_actor_cannot_use_direct_manager(): void
    {
        $group = $this->group();
        $this->fails('batch_invalid_selection', fn () => $this->workflow->review(
            $this->owner, 'group-targets', $group->id, 'add', array_fill(0, 101, strtolower((string) Str::ulid())),
        ));
        $this->fails('batch_invalid_selection', fn () => $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', []));
        $this->fails('batch_invalid_selection', fn () => $this->workflow->review($this->owner, 'group-users', $group->id, 'add', ['01']));
        $viewer = $this->user(GatewayRole::Viewer);
        $this->actingAs($viewer);
        try {
            app(TargetGroupManager::class)->updateMemberships(
                $this->owner, AccessBatchContext::GroupTargets, $group->id, [$this->target()->id], true, true, (string) Str::uuid(),
            );
            self::fail('Mismatched authenticated actor was accepted.');
        } catch (AuthorizationException) {
            self::assertSame(0, DB::table('target_group_targets')->count());
        }
    }

    public function test_required_audit_failure_rolls_back_every_relationship(): void
    {
        $group = $this->group();
        $targets = $this->fleet(3);
        $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', $targets);
        $auditWrites = 0;
        DB::listen(static function (QueryExecuted $query) use (&$auditWrites): void {
            if (str_starts_with(strtolower($query->sql), 'insert') && str_contains($query->sql, 'activity_events') && ++$auditWrites === 2) {
                throw new RuntimeException('Injected required audit failure.');
            }
        });
        try {
            $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']);
            self::fail('Required audit failure was ignored.');
        } catch (RuntimeException $exception) {
            self::assertSame('Injected required audit failure.', $exception->getMessage());
        }
        self::assertSame(0, DB::table('target_group_targets')->count());
        self::assertSame(0, DB::table('activity_events')->count());
    }

    public function test_individual_writer_changes_and_new_ssh_impact_invalidate_review_before_any_batch_write(): void
    {
        $group = $this->group();
        $target = $this->target();
        $old = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', [$target->id]);
        app(TargetGroupManager::class)->updateTargetMembership($group, $target, true);
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'group-targets', $group->id, $old['token']));
        self::assertSame(1, DB::table('activity_events')->count());

        $user = $this->user();
        $membership = $this->workflow->review($this->owner, 'group-users', $group->id, 'add', [(string) $user->id]);
        $ssh = $this->target('ssh_direct');
        app(TargetGroupManager::class)->updateTargetMembership($group, $ssh, true, true);
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'group-users', $group->id, $membership['token'], true));
        self::assertSame(0, DB::table('target_group_users')->count());
        $fresh = $this->workflow->review($this->owner, 'group-users', $group->id, 'add', [(string) $user->id]);
        self::assertTrue($fresh['requires_ssh_confirmation']);
    }

    public function test_direct_review_detects_new_individual_and_applicable_group_restrictions(): void
    {
        $user = $this->user();
        $target = $this->target();
        $group = $this->group();
        $this->memberTargets($group, [$target->id]);
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id, 'user_id' => $user->id, 'created_at' => now(), 'updated_at' => now(),
        ]);
        $old = $this->workflow->review($this->owner, 'user-targets', (string) $user->id, 'allow', [$target->id]);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->id, 'permission' => 'wordpress.abilities.inspect', 'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'user-targets', (string) $user->id, $old['token']));
        $fresh = $this->workflow->review($this->owner, 'user-targets', (string) $user->id, 'allow', [$target->id]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $user->id, 'target_record_id' => $target->id, 'permission' => 'historical.denial',
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'user-targets', (string) $user->id, $fresh['token']));
        self::assertSame(0, DB::table('user_target_access')->count());
    }

    public function test_new_wordpress_member_review_discloses_existing_group_publish_scope_without_creating_grants(): void
    {
        $group = $this->group();
        $user = $this->user();
        $target = $this->target();
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id, 'user_id' => $user->id, 'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('wordpress_publish_group_grants')->insert([
            'target_group_id' => $group->id, 'user_id' => $user->id, 'created_at' => now(), 'updated_at' => now(),
        ]);
        $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', [$target->id]);
        self::assertStringContainsString('existing publishing grants', implode(' ', $review['warnings']));
        $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']);
        self::assertSame(1, DB::table('wordpress_publish_group_grants')->count());
    }

    public function test_all_scope_operator_remains_restrictable_without_scope_or_global_permission_changes(): void
    {
        $user = $this->user();
        $user->forceFill(['target_scope_mode' => 'all'])->save();
        $target = $this->target();
        $group = $this->group();
        DB::table('user_permission_denials')->insert([
            'user_id' => $user->id, 'permission' => 'ssh.command.run', 'created_at' => now(), 'updated_at' => now(),
        ]);
        $page = $this->workflow->page($this->owner, 'user-targets', (string) $user->id);
        self::assertFalse($page['subject']['unrestricted']);
        self::assertSame('all', $page['subject']['scope_mode']);
        self::assertTrue($page['items'][0]['eligible']);
        $direct = $this->workflow->review($this->owner, 'user-targets', (string) $user->id, 'deny', [$target->id]);
        $this->workflow->apply($this->owner, 'user-targets', (string) $user->id, $direct['token']);
        $membership = $this->workflow->review($this->owner, 'user-groups', (string) $user->id, 'add', [$group->id]);
        $this->workflow->apply($this->owner, 'user-groups', (string) $user->id, $membership['token']);
        self::assertSame('all', $user->refresh()->getRawOriginal('target_scope_mode'));
        $this->assertDatabaseHas('user_target_access', ['user_id' => $user->id, 'target_record_id' => $target->id, 'allowed' => false]);
        $this->assertDatabaseHas('user_permission_denials', ['user_id' => $user->id, 'permission' => 'ssh.command.run']);
    }

    public function test_disabled_subject_can_be_configured_without_enabling_it_and_scope_drift_requires_new_review(): void
    {
        $user = $this->user();
        $user->forceFill(['access_enabled' => false])->save();
        $group = $this->group();
        $target = $this->target();
        $review = $this->workflow->review($this->owner, 'user-groups', (string) $user->id, 'add', [$group->id]);
        self::assertStringContainsString('account is disabled', implode(' ', $review['warnings']));
        $this->workflow->apply($this->owner, 'user-groups', (string) $user->id, $review['token']);
        self::assertFalse((bool) $user->refresh()->access_enabled);
        $oldScope = $this->workflow->review($this->owner, 'user-targets', (string) $user->id, 'allow', [$target->id]);
        $user->forceFill(['target_scope_mode' => 'all'])->save();
        $this->fails('batch_review_stale', fn () => $this->workflow->apply($this->owner, 'user-targets', (string) $user->id, $oldScope['token']));
        self::assertSame(0, DB::table('user_target_access')->count());
        self::assertFalse((bool) $user->refresh()->access_enabled);
    }

    public function test_actor_must_match_request_attribution_and_withdrawn_actor_access_cannot_apply_old_review(): void
    {
        $group = $this->group();
        $target = $this->target();
        $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', [$target->id]);
        $this->app['request']->setUserResolver(static fn () => null);
        try {
            $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']);
            self::fail('A request without the audit principal was accepted.');
        } catch (AuthorizationException) {
            self::assertSame(0, DB::table('target_group_targets')->count());
        }
        $this->app['request']->setUserResolver(static fn () => Auth::user());
        $this->owner->forceFill(['access_enabled' => false])->save();
        try {
            $this->workflow->apply($this->owner, 'group-targets', $group->id, $review['token']);
            self::fail('A disabled actor applied an old review.');
        } catch (AuthorizationException) {
            self::assertSame(0, DB::table('target_group_targets')->count());
        }
    }

    public function test_page_and_hundred_identity_review_queries_are_independent_of_fleet_size(): void
    {
        $group = $this->group();
        $counts = [];
        $selects = 0;
        $counting = false;
        DB::listen(static function (QueryExecuted $query) use (&$selects, &$counting): void {
            if ($counting && str_starts_with(strtolower($query->sql), 'select')) {
                $selects++;
            }
        });
        $ids = [];
        foreach ([100, 500, 3000] as $size) {
            $ids = [...$ids, ...$this->fleet($size - count($ids), count($ids))];
            $selects = 0;
            $counting = true;
            $page = $this->workflow->page($this->owner, 'group-targets', $group->id, ['membership' => 'available']);
            $review = $this->workflow->review($this->owner, 'group-targets', $group->id, 'add', array_slice($ids, 0, 100));
            $counting = false;
            self::assertCount(50, $page['items']);
            self::assertCount(100, $review['items']);
            self::assertTrue($review['can_apply']);
            $counts[] = $selects;
        }
        self::assertSame([$counts[0], $counts[0], $counts[0]], $counts);
        self::assertLessThan(30, $counts[0]);
    }

    /** @param callable():mixed $callback */
    private function fails(string $message, callable $callback): void
    {
        try {
            $callback();
            self::fail('Expected '.$message);
        } catch (DomainException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    private function user(GatewayRole $role = GatewayRole::Operator): User
    {
        return User::query()->create([
            'name' => 'Fixture user '.Str::random(8), 'email' => Str::random(12).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => $role->value,
            'target_scope_mode' => $role === GatewayRole::Owner ? 'all' : 'selected',
            'access_enabled' => true, 'ai_access_enabled' => false,
        ]);
    }

    private function group(): TargetGroup
    {
        return TargetGroup::query()->create(['name' => 'Fixture group '.Str::random(12)]);
    }

    private function target(string $connector = 'wp_ai_bridge'): Target
    {
        return Target::query()->create([
            'target_id' => 'fixture-'.strtolower(Str::random(16)),
            'display_name' => 'Fixture Target '.Str::random(8), 'connector_type' => $connector,
            'connection_state' => 'disconnected',
        ]);
    }

    /** @return list<string> */
    private function fleet(int $count, int $offset = 0): array
    {
        $rows = [];
        for ($i = $offset; $i < $offset + $count; $i++) {
            $rows[] = [
                'id' => strtolower((string) Str::ulid()), 'target_id' => sprintf('fleet-%05d', $i),
                'display_name' => sprintf('Fleet %05d', $i), 'connector_type' => 'wp_ai_bridge',
                'connection_state' => 'disconnected', 'created_at' => now(), 'updated_at' => now(),
            ];
        }
        foreach (array_chunk($rows, 500) as $chunk) {
            DB::table('targets')->insert($chunk);
        }

        return array_column($rows, 'id');
    }

    /** @param list<string> $ids */
    private function memberTargets(TargetGroup $group, array $ids): void
    {
        DB::table('target_group_targets')->insert(array_map(static fn (string $id): array => [
            'target_group_id' => $group->id, 'target_record_id' => $id, 'created_at' => now(), 'updated_at' => now(),
        ], $ids));
    }
}
