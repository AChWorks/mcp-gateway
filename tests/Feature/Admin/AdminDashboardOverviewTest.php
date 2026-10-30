<?php

namespace Tests\Feature\Admin;

use App\Application\Admin\TargetDashboardOverview;
use App\Application\Targets\TargetInventory;
use App\Application\Targets\TargetReview;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class AdminDashboardOverviewTest extends TestCase
{
    use RefreshDatabase;

    public function test_overview_keeps_complete_lifecycle_and_independent_overlapping_counts(): void
    {
        Http::preventStrayRequests();
        $owner = $this->user();
        $this->target('connected-wp', TargetConnectionState::Connected);
        $paused = $this->target('connected-ssh', TargetConnectionState::Connected, 'ssh_direct');
        $paused->forceFill(['operations_paused' => true])->save();
        $pending = $this->target('pending-setup', TargetConnectionState::Pending);
        $this->target('disconnected', TargetConnectionState::Disconnected);
        $this->target('reassigning', TargetConnectionState::Reassigning);
        $this->target('reconnect', TargetConnectionState::ReconnectRequired);
        $failure = $this->target('failed', TargetConnectionState::Error);
        $blocked = $this->target('blocked-refresh', TargetConnectionState::Connected);

        // Multiple local blockers still represent one Target in the queue.
        $this->refreshIntent($failure);
        $this->revocationIntent($failure);
        $this->refreshIntent($blocked);
        // Ordinary pending OAuth enrollment is not a recovery blocker.
        DB::table('wp_ai_bridge_oauth_flows')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $pending->getKey(),
            'state_hash' => hash('sha256', 'synthetic-pending-state'),
            'encrypted_context' => 'opaque-test-only',
            'expires_at' => now()->addMinutes(10),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $summary = app(TargetDashboardOverview::class)->forUser($owner);
        self::assertSame(8, $summary['targetCount']);
        self::assertSame(3, $summary['connectedCount']);
        self::assertSame(4, $summary['attentionCount']);
        self::assertSame(1, $summary['pausedCount']);
        self::assertSame([
            'disconnected' => 1, 'pending' => 1, 'connected' => 3,
            'reassigning' => 1, 'reconnect_required' => 1, 'error' => 1,
        ], array_column($summary['lifecycle'], 'count', 'state'));
        self::assertSame(8, array_sum(array_column($summary['lifecycle'], 'count')));
        self::assertSame(['ssh_direct' => 1, 'wp_ai_bridge' => 7],
            array_column($summary['connectorBreakdown'], 'count', 'type'));

        $reviewIds = array_map(static fn (Target $target): string => $target->target_id, $summary['reviewTargets']);
        self::assertSame(['blocked-refresh', 'failed', 'reassigning', 'reconnect'], $reviewIds);
        $filtered = app(TargetInventory::class)->adminPage($owner, needsReview: true);
        self::assertSame($reviewIds, array_map(static fn (Target $target): string => $target->target_id, $filtered['items']));
        Http::assertNothingSent();
    }

    public function test_scoped_counts_list_and_breakdown_exclude_direct_group_and_unassigned_denials(): void
    {
        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $visible = $this->target('visible', TargetConnectionState::Error);
        $directDenied = $this->target('direct-denied', TargetConnectionState::Error, 'ssh_direct');
        $groupDenied = $this->target('group-denied', TargetConnectionState::Error);
        $this->target('unassigned', TargetConnectionState::Error);

        foreach ([$visible, $directDenied, $groupDenied] as $target) {
            $this->allow($operator, $target);
        }
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $directDenied->getKey(),
            'permission' => 'targets.view',
        ]);
        $group = TargetGroup::query()->create(['name' => 'Denied group']);
        $group->users()->attach($operator);
        $group->targets()->attach($groupDenied);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->getKey(), 'permission' => 'targets.view',
        ]);

        $summary = app(TargetDashboardOverview::class)->forUser($operator);
        self::assertSame(1, $summary['targetCount']);
        self::assertSame(1, $summary['attentionCount']);
        self::assertSame(['visible'], array_map(static fn (Target $target): string => $target->target_id, $summary['reviewTargets']));
        self::assertSame(['wp_ai_bridge' => 1], array_column($summary['connectorBreakdown'], 'count', 'type'));

        $html = $this->actingAs($operator)->get('/admin')->assertOk();
        $html->assertSee('visible')->assertDontSee('direct-denied')
            ->assertDontSee('group-denied')->assertDontSee('unassigned');

        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'permission' => 'targets.view',
        ]);
        $denied = app(TargetDashboardOverview::class)->forUser($operator);
        self::assertSame(0, $denied['targetCount']);
        self::assertSame(0, $denied['attentionCount']);
        self::assertSame([], $denied['reviewTargets']);
        self::assertSame([], $denied['connectorBreakdown']);
    }

    #[DataProvider('roles')]
    public function test_dashboard_renders_for_existing_roles_with_scoped_target_evidence(GatewayRole $role): void
    {
        $user = $this->user($role);
        $target = $this->target('role-target', TargetConnectionState::Error);
        if ($role !== GatewayRole::Owner) {
            $this->allow($user, $target);
        }
        $this->actingAs($user)->get('/admin')->assertOk()
            ->assertSee('role-target')->assertSee('Recorded connected')
            ->assertSee('No recorded verification')
            ->assertSee('needs_review=1', false)
            ->assertSee('View connection information');
    }

    /** @return array<string,array{GatewayRole}> */
    public static function roles(): array
    {
        return [
            'owner' => [GatewayRole::Owner],
            'administrator' => [GatewayRole::Administrator],
            'operator' => [GatewayRole::Operator],
            'viewer' => [GatewayRole::Viewer],
        ];
    }

    public function test_activity_uses_its_own_permissions_and_preserves_unknown_outcome(): void
    {
        $owner = $this->user();
        $target = $this->target('activity-target', TargetConnectionState::Connected);
        app(ActivityRecorder::class)->record((string) Str::uuid(), 'sample-operation', 'unknown', $target);
        $this->actingAs($owner)->get('/admin')->assertOk()
            ->assertSee('Outcome unknown')->assertSee('badge badge-warning', false);

        $viewer = $this->user(GatewayRole::Viewer);
        $this->allow($viewer, $target);
        DB::table('user_permission_denials')->insert([
            'user_id' => $viewer->getKey(), 'permission' => 'activity.view',
        ]);
        $this->actingAs($viewer)->get('/admin')->assertOk()
            ->assertDontSee('sample-operation')->assertDontSee('recent-activity-title', false);
    }

    public function test_recent_activity_shows_the_ten_newest_permitted_entries_without_out_of_scope_rows_consuming_the_limit(): void
    {
        $viewer = $this->user(GatewayRole::Viewer);
        $visible = $this->target('activity-visible', TargetConnectionState::Connected);
        $hidden = $this->target('activity-hidden', TargetConnectionState::Connected);
        $activityDenied = $this->target('activity-denied', TargetConnectionState::Connected);
        $this->allow($viewer, $visible);
        $this->allow($viewer, $activityDenied);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $viewer->getKey(),
            'target_record_id' => $activityDenied->getKey(),
            'permission' => 'activity.view',
        ]);

        $recordedAt = now()->startOfSecond();
        $recorder = app(ActivityRecorder::class);
        for ($i = 0; $i < 13; $i++) {
            $reference = (string) Str::uuid();
            $recorder->recordRequired(
                $reference,
                sprintf('visible-activity-%02d', $i),
                $i === 12 ? 'unknown' : 'success',
                $visible,
            );
            DB::table('activity_events')->where('correlation_id', $reference)
                ->update(['created_at' => $recordedAt->copy()->addSeconds($i)]);
        }
        foreach ([$hidden, $activityDenied] as $i => $target) {
            $reference = (string) Str::uuid();
            $recorder->recordRequired($reference, 'hidden-newer-activity-'.$i, 'success', $target);
            DB::table('activity_events')->where('correlation_id', $reference)
                ->update(['created_at' => $recordedAt->copy()->addMinutes($i + 1)]);
        }

        $response = $this->actingAs($viewer)->get('/admin')->assertOk();
        $operations = array_column($response->viewData('recentActivity'), 'operation');
        self::assertSame(array_map(
            static fn (int $i): string => sprintf('visible-activity-%02d', $i),
            range(12, 3),
        ), $operations);
        $response->assertSeeInOrder($operations)
            ->assertDontSee('visible-activity-02')
            ->assertDontSee('hidden-newer-activity')
            ->assertSee('Outcome unknown');
    }

    public function test_overview_has_constant_query_count_and_bounded_review_list_at_large_fleet_sizes(): void
    {
        Http::preventStrayRequests();
        $owner = $this->user();
        $overview = app(TargetDashboardOverview::class);
        $previous = 0;

        foreach ([10, 100, 1000] as $size) {
            $rows = [];
            for ($i = $previous; $i < $size; $i++) {
                $rows[] = [
                    'id' => (string) Str::ulid(), 'target_id' => sprintf('fleet-%04d', $i),
                    'display_name' => sprintf('Fleet %04d', $i), 'connector_type' => 'wp_ai_bridge',
                    'connection_state' => 'error', 'operations_paused' => false,
                    'created_at' => now(), 'updated_at' => now(),
                ];
            }
            foreach (array_chunk($rows, 100) as $chunk) {
                DB::table('targets')->insert($chunk);
            }
            $previous = $size;
            DB::flushQueryLog();
            DB::enableQueryLog();
            $result = $overview->forUser($owner);
            $queries = DB::getQueryLog();
            DB::disableQueryLog();

            self::assertSame($size, $result['targetCount']);
            self::assertSame($size, $result['attentionCount']);
            self::assertCount(5, $result['reviewTargets']);
            self::assertCount(3, $queries);
            self::assertSame('fleet-0000', $result['reviewTargets'][0]->target_id);
        }
        Http::assertNothingSent();
    }

    public function test_unavailable_historical_type_is_included_without_assuming_ssh_or_oauth(): void
    {
        $owner = $this->user();
        DB::table('targets')->insert([
            'id' => (string) Str::ulid(), 'target_id' => 'historical-api',
            'display_name' => 'Historical API', 'connector_type' => 'unavailable_api',
            'connection_state' => 'error', 'created_at' => now(), 'updated_at' => now(),
        ]);
        $summary = app(TargetDashboardOverview::class)->forUser($owner);
        self::assertSame(1, $summary['targetCount']);
        self::assertSame('unavailable_api', $summary['connectorBreakdown'][0]['type']);
        self::assertSame('Unsupported connector', $summary['connectorBreakdown'][0]['label']);
        self::assertSame(1, $summary['attentionCount']);
        self::assertSame(['historical-api'],
            app(TargetReview::class)->apply(Target::query())->pluck('target_id')->all());
    }

    public function test_empty_overview_explains_missing_evidence_without_claiming_live_health(): void
    {
        $owner = $this->user();
        $this->actingAs($owner)->get('/admin')->assertOk()
            ->assertViewHas('targetCount', 0)
            ->assertViewHas('lifecycle', static fn (array $items): bool => count($items) === 6
                && array_sum(array_column($items, 'count')) === 0)
            ->assertSee('No permitted Targets currently match the review criteria.')
            ->assertSee('This does not verify live remote health.')
            ->assertSee('No permitted Targets are registered.');
    }

    private function target(string $id, TargetConnectionState $state, string $type = 'wp_ai_bridge'): Target
    {
        return Target::query()->create([
            'target_id' => $id, 'display_name' => $id, 'connector_type' => $type,
            'connection_state' => $state,
        ]);
    }

    private function user(GatewayRole $role = GatewayRole::Owner, TargetScopeMode $scope = TargetScopeMode::Selected): User
    {
        return User::query()->create([
            'name' => 'Overview '.$role->value, 'email' => (string) Str::uuid().'@example.test',
            'password' => 'SyntheticTestPassword!234', 'role' => $role->value,
            'target_scope_mode' => $role === GatewayRole::Owner ? TargetScopeMode::All->value : $scope->value,
            'access_enabled' => true,
        ]);
    }

    private function allow(User $user, Target $target): void
    {
        DB::table('user_target_access')->insert([
            'user_id' => $user->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
    }

    private function refreshIntent(Target $target): void
    {
        $credential = TargetCredential::query()->create([
            'target_record_id' => $target->getKey(), 'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth', 'encrypted_payload' => 'opaque-test-only',
        ]);
        DB::table('wp_ai_bridge_refresh_intents')->insert([
            'id' => (string) Str::ulid(), 'target_record_id' => $target->getKey(),
            'credential_id' => $credential->getKey(), 'generation' => 1, 'attempts' => 1,
            'created_at' => now(), 'updated_at' => now(),
        ]);
    }

    private function revocationIntent(Target $target): void
    {
        DB::table('wp_ai_bridge_revocation_intents')->insert([
            'id' => (string) Str::ulid(), 'target_record_id' => $target->getKey(),
            'kind' => 'disconnect', 'phase' => 'unknown', 'created_at' => now(), 'updated_at' => now(),
        ]);
    }
}
