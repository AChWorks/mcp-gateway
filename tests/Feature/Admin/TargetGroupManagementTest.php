<?php

namespace Tests\Feature\Admin;

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
final class TargetGroupManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_can_create_and_update_group_with_denials_and_required_audit(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)->post('/admin/target-groups', [
            'name' => 'Production',
            'denied_permissions' => [GatewayPermission::WordpressAbilitiesExecuteDestructive->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $group = TargetGroup::query()->where('name', 'Production')->firstOrFail();

        $this->actingAs($owner)
            ->get('/admin/target-groups')
            ->assertOk()
            ->assertSee('Production');
        $this->actingAs($owner)
            ->get('/admin/target-groups/'.$group->id.'/edit')
            ->assertOk()
            ->assertSee('Production');

        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteDestructive->value,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'actor_type' => 'administrator',
            'actor_id' => (string) $owner->id,
            'operation' => 'target-group-create:'.$group->id,
            'outcome' => 'success',
        ]);

        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id, [
            'name' => 'Production sites',
            'denied_permissions' => [GatewayPermission::WordpressAbilitiesExecuteMutating->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        self::assertSame('Production sites', $group->refresh()->name);
        $this->assertDatabaseMissing('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteDestructive->value,
        ]);
        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
        ]);
    }

    public function test_wrong_password_or_non_owner_cannot_manage_site_groups(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)->post('/admin/target-groups', [
            'name' => 'Blocked',
            'current_password' => 'WrongHorse!234',
        ])->assertSessionHasErrors('current_password');
        self::assertSame(0, TargetGroup::query()->count());

        $administrator = User::query()->create([
            'name' => 'Administrator',
            'email' => 'administrator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Administrator->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);
        $this->actingAs($administrator)->get('/admin/target-groups')->assertForbidden();
    }

    public function test_owner_can_manage_group_site_and_user_membership_and_owner_assignment_is_rejected(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');
        $group = TargetGroup::query()->create(['name' => 'Operations']);

        $this->actingAs($owner)->put(route('admin.target-groups.targets.update', [
            'targetGroup' => $group->id,
            'target' => $site->target_id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $this->actingAs($owner)->put(route('admin.target-groups.users.update', [
            'targetGroup' => $group->id,
            'user' => $operator->id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $this->assertDatabaseHas('target_group_targets', [
            'target_group_id' => $group->id,
            'target_record_id' => $site->id,
        ]);
        $this->assertDatabaseHas('target_group_users', [
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'target-group-target-update:'.$group->id,
            'target_id' => 'alpha',
            'outcome' => 'success',
        ]);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'target-group-user-update:'.$group->id.':'.$operator->id,
            'outcome' => 'success',
        ]);

        $this->actingAs($owner)->put(route('admin.target-groups.targets.update', [
            'targetGroup' => $group->id,
            'target' => $site->target_id,
        ], false), [
            'assigned' => '0',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $this->assertDatabaseMissing('target_group_targets', [
            'target_group_id' => $group->id,
            'target_record_id' => $site->id,
        ]);

        $this->actingAs($owner)->put(route('admin.target-groups.users.update', [
            'targetGroup' => $group->id,
            'user' => $operator->id,
        ], false), [
            'assigned' => '0',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $this->assertDatabaseMissing('target_group_users', [
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
        ]);

        $this->actingAs($owner)->put(route('admin.target-groups.users.update', [
            'targetGroup' => $group->id,
            'user' => $owner->id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('assigned');
        $this->assertDatabaseMissing('target_group_users', [
            'target_group_id' => $group->id,
            'user_id' => $owner->id,
        ]);
    }

    public function test_deleting_group_preserves_users_sites_and_direct_site_rules(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');
        $group = TargetGroup::query()->create(['name' => 'Disposable']);

        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->id,
            'target_record_id' => $site->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'permission' => GatewayPermission::TargetsView->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($owner)->delete('/admin/target-groups/'.$group->id, [
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect('/admin/target-groups');

        self::assertTrue(User::query()->whereKey($operator->id)->exists());
        self::assertTrue(Target::query()->whereKey($site->id)->exists());
        $this->assertDatabaseHas('user_target_access', [
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'allowed' => false,
        ]);
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'permission' => GatewayPermission::TargetsView->value,
        ]);
        self::assertSame(0, DB::table('target_group_targets')->where('target_group_id', $group->id)->count());
        self::assertSame(0, DB::table('target_group_users')->where('target_group_id', $group->id)->count());
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'Gateway Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
        ]);
    }

    private function site(string $siteId): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
        ]);
    }
}
