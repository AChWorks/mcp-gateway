<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessControl;
use App\Application\Access\TargetGroupManager;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class ArvanPermissionAdminTest extends TestCase
{
    use RefreshDatabase;

    public function test_arvan_capabilities_are_editable_in_user_group_and_matching_target_forms(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $group = TargetGroup::query()->create(['name' => 'Arvan ACL group']);
        $target = $this->target('arvancloud', 'arvan-acl-ui');

        $this->actingAs($owner);
        foreach (['/admin/users/create', '/admin/users/'.$user->id.'/edit',
            '/admin/target-groups/create', '/admin/target-groups/'.$group->id.'/edit'] as $url) {
            $page = $this->get($url)->assertOk()->assertSee('ArvanCloud API');
            foreach ($this->arvanPermissions() as $permission) {
                // In User forms role-ineligible permissions are read-only,
                // but every supported capability must be discoverable.
                $page->assertSee($permission->value);
            }
        }

        // Adding an enum permission without exposing it on the shared
        // User/Group page must fail the test on future connector releases.
        $groupCatalog = $this->get('/admin/target-groups/create')->assertOk();
        foreach (GatewayPermission::targetScoped() as $permission) {
            $groupCatalog->assertSee('value="'.$permission->value.'"', false);
        }

        $page = $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()->assertSee('ArvanCloud API')->assertSee('Shared Target management');
        foreach ($this->arvanPermissions() as $permission) {
            $page->assertSee('value="'.$permission->value.'"', false);
        }
        $page->assertDontSee('value="wordpress.abilities.inspect"', false)
            ->assertDontSee('value="ssh.command.run"', false)
            ->assertDontSee('Direct SSH')
            ->assertDontSee('WordPress (WP AI Bridge)');
    }

    public function test_new_viewer_can_be_created_with_explicit_arvan_read_deny(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner)->post('/admin/users', [
            'name' => 'Arvan read limited',
            'email' => 'arvan-viewer@example.test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => 'viewer',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'denied_permissions' => [GatewayPermission::ArvanApiRead->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        $user = User::query()->where('email', 'arvan-viewer@example.test')->sole();
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
        ]);
        $this->actingAs($owner)->get('/admin/users/'.$user->id.'/edit')
            ->assertOk()->assertSee('ArvanCloud API')
            ->assertSee('value="arvan.api.read"', false);
    }

    public function test_global_and_direct_target_arvan_denials_are_saved_and_enforced(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $target = $this->target('arvancloud', 'arvan-direct-acl');
        $access = app(AccessControl::class);
        $manager = app(UserAccessManager::class);

        $this->actingAs($owner)->put('/admin/users/'.$user->id, [
            'name' => $user->name,
            'email' => $user->email,
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'denied_permissions' => [GatewayPermission::ArvanApiRead->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
        ]);

        // Existing cross-connector denials are historical/inapplicable on
        // this Arvan Target, but saving its real Arvan checkbox must not
        // erase their stored evidence or display them as editable controls.
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $user->id,
            'target_record_id' => $target->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()
            ->assertSee('name="denied_permissions[]" value="wordpress.abilities.execute.readonly"', false)
            ->assertDontSee('WordPress (WP AI Bridge)');

        $this->actingAs($owner)->put('/admin/users/'.$user->id.'/targets/'.$target->target_id, [
            'access_rule' => 'allow',
            'denied_permissions' => [
                GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
                GatewayPermission::ArvanApiWrite->value,
            ],
            'target_revision' => $manager->targetRuleRevision($user, $target),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
            'permission' => GatewayPermission::ArvanApiWrite->value,
        ]);
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
        ]);
        self::assertTrue($access->allows($user, GatewayPermission::ArvanApiInspect, $target));
        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiRead, $target));
        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiWrite, $target));

        $this->actingAs($owner)->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()->assertSee('value="arvan.api.write"', false);
    }

    public function test_group_arvan_denials_apply_and_other_connector_denials_survive_target_edit(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $arvan = $this->target('arvancloud', 'arvan-group-acl');
        $wordpress = $this->target('wp_ai_bridge', 'wp-acl-preservation');
        $access = app(AccessControl::class);
        $manager = app(UserAccessManager::class);

        $this->actingAs($owner)->post('/admin/target-groups', [
            'name' => 'Read-only Arvan',
            'denied_permissions' => [GatewayPermission::ArvanApiWrite->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $group = TargetGroup::query()->where('name', 'Read-only Arvan')->sole();
        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::ArvanApiWrite->value,
        ]);

        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id.'/users/'.$user->id, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id.'/targets/'.$arvan->target_id, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        self::assertTrue($access->allows($user, GatewayPermission::ArvanApiRead, $arvan));
        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiWrite, $arvan));

        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id, [
            'name' => $group->name,
            'denied_permissions' => [GatewayPermission::ArvanApiRead->value],
            'denial_revision' => app(TargetGroupManager::class)->denialRevision($group),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiRead, $arvan));
        self::assertTrue($access->allows($user, GatewayPermission::ArvanApiWrite, $arvan));

        // Older cross-connector denial rows must remain intact when a
        // WordPress Target rule is edited through its filtered UI.
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $user->id,
            'target_record_id' => $wordpress->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $page = $this->get('/admin/users/'.$user->id.'/targets/'.$wordpress->target_id.'/edit')
            ->assertOk()->assertSee('WordPress (WP AI Bridge)')
            ->assertSee('name="denied_permissions[]" value="arvan.api.read"', false)
            ->assertDontSee('value="arvan.api.write"', false)
            ->assertDontSee('ArvanCloud API');

        $this->put('/admin/users/'.$user->id.'/targets/'.$wordpress->target_id, [
            'access_rule' => 'allow',
            'denied_permissions' => [
                GatewayPermission::ArvanApiRead->value,
                GatewayPermission::WordpressAbilitiesExecuteMutating->value,
            ],
            'target_revision' => $manager->targetRuleRevision($user, $wordpress),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $wordpress->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
        ]);
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $wordpress->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
        ]);
    }

    /** @return list<GatewayPermission> */
    private function arvanPermissions(): array
    {
        return [
            GatewayPermission::ArvanApiInspect,
            GatewayPermission::ArvanApiRead,
            GatewayPermission::ArvanApiWrite,
            GatewayPermission::ArvanApiDestructive,
            GatewayPermission::ArvanApiUnclassified,
        ];
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'acl-owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'ACL Operator',
            'email' => 'acl-operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
    }

    private function target(string $connector, string $id): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => 'ACL '.$id,
            'connector_type' => $connector,
        ]);
    }
}
