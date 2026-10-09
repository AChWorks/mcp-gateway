<?php

namespace Tests\Feature\Admin;

use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class TargetAccessAdminSmokeTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_user_and_group_pages_render_on_target_schema(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);

        $this->get('/admin/users')->assertOk();
        $this->get('/admin/users/create')->assertOk();
        $this->get('/admin/target-groups')->assertOk();
        $this->get('/admin/target-groups/create')->assertOk();
        $this->get('/admin/activity')->assertOk();

        $user = app(UserAccessManager::class)->create([
            'name' => 'Operator',
            'email' => 'operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        $target = $this->target();
        $group = TargetGroup::query()->create(['name' => 'Managed targets']);

        $this->get('/admin/users/'.$user->id.'/edit')->assertOk();
        $this->get('/admin/users/'.$user->id.'/targets')->assertOk();
        $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/edit')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/users')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/targets')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/targets/'.$target->target_id.'/edit')->assertOk();
    }

    public function test_owner_can_create_user_then_assign_direct_target_and_group_membership(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);
        $this->post('/admin/users', [
            'name' => 'Limited',
            'email' => 'limited@example.test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $user = User::query()->where('email', 'limited@example.test')->firstOrFail();
        self::assertSame('selected', $user->getRawOriginal('target_scope_mode'));
        self::assertSame('ssh.command.run', DB::table('user_permission_denials')
            ->where('user_id', $user->id)
            ->where('permission', 'ssh.command.run')->value('permission'));

        $target = $this->target();
        $this->put('/admin/users/'.$user->id.'/targets/'.$target->target_id, [
            'access_rule' => 'allow',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $this->assertDatabaseHas('user_target_access', [
            'target_record_id' => $target->getKey(),
            'user_id' => $user->id,
            'allowed' => true,
        ]);

        $this->post('/admin/target-groups', [
            'name' => 'Operations',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $group = TargetGroup::query()->where('name', 'Operations')->firstOrFail();
        $this->put('/admin/target-groups/'.$group->getKey().'/targets/'.$target->target_id, [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        self::assertTrue($group->targets()->whereKey($target->getKey())->exists());
    }

    public function test_nonowner_cannot_administer_target_groups(): void
    {
        $owner = $this->owner();
        $operator = app(UserAccessManager::class)->create([
            'name' => 'Operator',
            'email' => 'operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        $this->actingAs($operator)
            ->get('/admin/target-groups')
            ->assertForbidden();
        $this->actingAs($owner)->get('/admin/target-groups')->assertOk();
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway owner',
            'email' => 'owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }

    private function target(): Target
    {
        return Target::query()->create([
            'target_id' => 'demo-server',
            'display_name' => 'Demo server',
            'connector_type' => 'ssh_direct',
        ]);
    }
}
