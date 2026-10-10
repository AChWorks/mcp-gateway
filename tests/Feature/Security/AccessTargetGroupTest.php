<?php

namespace Tests\Feature\Security;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class AccessTargetGroupTest extends TestCase
{
    use RefreshDatabase;

    public function test_group_membership_extends_selected_scope_but_direct_site_deny_remains_authoritative(): void
    {
        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $group = $this->group('Production');
        $this->assign($group, $operator);
        $this->includeSite($group, $alpha);
        $this->includeSite($group, $beta);

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($operator, GatewayPermission::TargetsView, $alpha));
        self::assertTrue($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteMutating, $beta));
        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeTargets(Target::query(), $operator)->orderBy('target_id')->pluck('target_id')->all(),
        );

        DB::table('user_target_access')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $alpha->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        self::assertFalse($access->allows($operator, GatewayPermission::TargetsView, $alpha));
        self::assertSame(
            ['beta'],
            $access->scopeTargets(Target::query(), $operator)->orderBy('target_id')->pluck('target_id')->all(),
        );
    }

    public function test_overlapping_group_denials_accumulate_and_direct_permission_denials_remain_final(): void
    {
        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $site = $this->site('alpha');
        $readGroup = $this->group('Read restrictions');
        $writeGroup = $this->group('Write restrictions');

        foreach ([$readGroup, $writeGroup] as $group) {
            $this->assign($group, $operator);
            $this->includeSite($group, $site);
        }
        $this->deny($readGroup, GatewayPermission::WordpressAbilitiesExecuteReadonly);
        $this->deny($writeGroup, GatewayPermission::WordpressAbilitiesExecuteMutating);

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($operator, GatewayPermission::TargetsView, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteReadonly, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteMutating, $site));

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'permission' => GatewayPermission::WordpressAbilitiesInspect->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        self::assertFalse($access->allows($operator, GatewayPermission::WordpressAbilitiesInspect, $site));
        self::assertSame(
            [],
            $access->scopeTargets(Target::query(), $operator, GatewayPermission::WordpressAbilitiesInspect)
                ->pluck('target_id')->all(),
        );
    }

    public function test_group_never_bypasses_role_or_global_permission_ceiling(): void
    {
        $viewer = $this->user(GatewayRole::Viewer, TargetScopeMode::Selected);
        $site = $this->site('alpha');
        $group = $this->group('Viewer sites');
        $this->assign($group, $viewer);
        $this->includeSite($group, $site);

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($viewer, GatewayPermission::TargetsView, $site));
        self::assertFalse($access->allows($viewer, GatewayPermission::WordpressAbilitiesExecuteMutating, $site));

        DB::table('user_permission_denials')->insert([
            'user_id' => $viewer->id,
            'permission' => GatewayPermission::TargetsView->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        self::assertFalse($access->allows($viewer, GatewayPermission::TargetsView, $site));
        self::assertSame(0, $access->scopeTargets(Target::query(), $viewer)->count());
    }

    public function test_all_scope_group_denials_narrow_matching_sites_and_owner_recovery_stays_unrestricted(): void
    {
        $administrator = $this->user(GatewayRole::Administrator, TargetScopeMode::All);
        $owner = $this->user(GatewayRole::Owner, TargetScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $group = $this->group('Restricted');

        $this->assign($group, $administrator);
        $this->includeSite($group, $alpha);
        $this->deny($group, GatewayPermission::TargetsView);

        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id,
            'user_id' => $owner->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);
        self::assertFalse($access->allows($administrator, GatewayPermission::TargetsView, $alpha));
        self::assertTrue($access->allows($administrator, GatewayPermission::TargetsView, $beta));
        self::assertTrue($access->allows($owner, GatewayPermission::TargetsView, $alpha));
        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeTargets(Target::query(), $owner)->orderBy('target_id')->pluck('target_id')->all(),
        );
    }

    public function test_group_derived_scope_is_enforced_by_admin_inventory_and_direct_routes(): void
    {
        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $group = $this->group('Admin scope');
        $this->assign($group, $operator);
        $this->includeSite($group, $alpha);

        $this->actingAs($operator)
            ->get('/admin/targets')
            ->assertOk()
            ->assertSee('Alpha')
            ->assertDontSee('Beta');

        $this->actingAs($operator)
            ->get(route('admin.targets.show', ['target' => $alpha->target_id], false))
            ->assertOk();

        $this->actingAs($operator)
            ->get(route('admin.targets.show', ['target' => $beta->target_id], false))
            ->assertForbidden();
    }

    private function user(GatewayRole $role, TargetScopeMode $scope): User
    {
        return User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'target_scope_mode' => $scope->value,
            'access_enabled' => true,
        ]);
    }

    private function site(string $siteId): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => 'disconnected',
        ]);
    }

    private function group(string $name): TargetGroup
    {
        return TargetGroup::query()->create(['name' => $name]);
    }

    private function assign(TargetGroup $group, User $user): void
    {
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id,
            'user_id' => $user->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function includeSite(TargetGroup $group, Target $site): void
    {
        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->id,
            'target_record_id' => $site->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function deny(TargetGroup $group, GatewayPermission $permission): void
    {
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->id,
            'permission' => $permission->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
