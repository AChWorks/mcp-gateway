<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteGroup;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class SiteGroupManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_can_create_and_update_group_with_denials_and_required_audit(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)->post('/admin/site-groups', [
            'name' => 'Production',
            'denied_permissions' => [GatewayPermission::AbilitiesExecuteDestructive->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $group = SiteGroup::query()->where('name', 'Production')->firstOrFail();

        $this->actingAs($owner)
            ->get('/admin/site-groups')
            ->assertOk()
            ->assertSee('Production');
        $this->actingAs($owner)
            ->get('/admin/site-groups/'.$group->id.'/edit')
            ->assertOk()
            ->assertSee('Production');

        $this->assertDatabaseHas('site_group_permission_denials', [
            'site_group_id' => $group->id,
            'permission' => GatewayPermission::AbilitiesExecuteDestructive->value,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'actor_type' => 'administrator',
            'actor_id' => (string) $owner->id,
            'operation' => 'site-group-create:'.$group->id,
            'outcome' => 'success',
        ]);

        $this->actingAs($owner)->put('/admin/site-groups/'.$group->id, [
            'name' => 'Production sites',
            'denied_permissions' => [GatewayPermission::AbilitiesExecuteMutating->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        self::assertSame('Production sites', $group->refresh()->name);
        $this->assertDatabaseMissing('site_group_permission_denials', [
            'site_group_id' => $group->id,
            'permission' => GatewayPermission::AbilitiesExecuteDestructive->value,
        ]);
        $this->assertDatabaseHas('site_group_permission_denials', [
            'site_group_id' => $group->id,
            'permission' => GatewayPermission::AbilitiesExecuteMutating->value,
        ]);
    }

    public function test_wrong_password_or_non_owner_cannot_manage_site_groups(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)->post('/admin/site-groups', [
            'name' => 'Blocked',
            'current_password' => 'WrongHorse!234',
        ])->assertSessionHasErrors('current_password');
        self::assertSame(0, SiteGroup::query()->count());

        $administrator = User::query()->create([
            'name' => 'Administrator',
            'email' => 'administrator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Administrator->value,
            'site_scope_mode' => SiteScopeMode::All->value,
        ]);
        $this->actingAs($administrator)->get('/admin/site-groups')->assertForbidden();
    }

    public function test_owner_can_manage_group_site_and_user_membership_and_owner_assignment_is_rejected(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');
        $group = SiteGroup::query()->create(['name' => 'Operations']);

        $this->actingAs($owner)->put(route('admin.site-groups.sites.update', [
            'siteGroup' => $group->id,
            'site' => $site->site_id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $this->actingAs($owner)->put(route('admin.site-groups.users.update', [
            'siteGroup' => $group->id,
            'user' => $operator->id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $this->assertDatabaseHas('site_group_sites', [
            'site_group_id' => $group->id,
            'site_record_id' => $site->id,
        ]);
        $this->assertDatabaseHas('site_group_users', [
            'site_group_id' => $group->id,
            'user_id' => $operator->id,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'site-group-site-update:'.$group->id,
            'site_id' => 'alpha',
            'outcome' => 'success',
        ]);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'site-group-user-update:'.$group->id.':'.$operator->id,
            'outcome' => 'success',
        ]);

        $this->actingAs($owner)->put(route('admin.site-groups.sites.update', [
            'siteGroup' => $group->id,
            'site' => $site->site_id,
        ], false), [
            'assigned' => '0',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $this->assertDatabaseMissing('site_group_sites', [
            'site_group_id' => $group->id,
            'site_record_id' => $site->id,
        ]);

        $this->actingAs($owner)->put(route('admin.site-groups.users.update', [
            'siteGroup' => $group->id,
            'user' => $operator->id,
        ], false), [
            'assigned' => '0',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $this->assertDatabaseMissing('site_group_users', [
            'site_group_id' => $group->id,
            'user_id' => $operator->id,
        ]);

        $this->actingAs($owner)->put(route('admin.site-groups.users.update', [
            'siteGroup' => $group->id,
            'user' => $owner->id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('assigned');
        $this->assertDatabaseMissing('site_group_users', [
            'site_group_id' => $group->id,
            'user_id' => $owner->id,
        ]);
    }

    public function test_deleting_group_preserves_users_sites_and_direct_site_rules(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');
        $group = SiteGroup::query()->create(['name' => 'Disposable']);

        DB::table('site_group_sites')->insert([
            'site_group_id' => $group->id,
            'site_record_id' => $site->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('site_group_users')->insert([
            'site_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_site_access')->insert([
            'user_id' => $operator->id,
            'site_record_id' => $site->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_site_permission_denials')->insert([
            'user_id' => $operator->id,
            'site_record_id' => $site->id,
            'permission' => GatewayPermission::SitesView->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($owner)->delete('/admin/site-groups/'.$group->id, [
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect('/admin/site-groups');

        self::assertTrue(User::query()->whereKey($operator->id)->exists());
        self::assertTrue(Site::query()->whereKey($site->id)->exists());
        $this->assertDatabaseHas('user_site_access', [
            'user_id' => $operator->id,
            'site_record_id' => $site->id,
            'allowed' => false,
        ]);
        $this->assertDatabaseHas('user_site_permission_denials', [
            'user_id' => $operator->id,
            'site_record_id' => $site->id,
            'permission' => GatewayPermission::SitesView->value,
        ]);
        self::assertSame(0, DB::table('site_group_sites')->where('site_group_id', $group->id)->count());
        self::assertSame(0, DB::table('site_group_users')->where('site_group_id', $group->id)->count());
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'site_scope_mode' => SiteScopeMode::All->value,
        ]);
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'Gateway Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'site_scope_mode' => SiteScopeMode::Selected->value,
        ]);
    }

    private function site(string $siteId): Site
    {
        $base = 'https://'.$siteId.'.example.test';

        return Site::query()->create([
            'site_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => 'disconnected',
        ]);
    }
}
