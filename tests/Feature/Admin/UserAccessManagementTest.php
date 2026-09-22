<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class UserAccessManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_can_create_a_scoped_operator_with_global_narrowing(): void
    {
        $owner = $this->owner();

        $response = $this->actingAs($owner)->post('/admin/users', [
            'name' => 'Scoped Operator',
            'email' => 'OPERATOR@Example.Test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'site_scope_mode' => SiteScopeMode::Selected->value,
            'access_enabled' => '1',
            'denied_permissions' => [
                GatewayPermission::ConnectionsTest->value,
            ],
            'current_password' => 'CorrectHorse!234',
        ]);

        $user = User::query()->where('email', 'operator@example.test')->firstOrFail();

        $response->assertRedirect(route('admin.users.edit', ['user' => $user->id], false));
        self::assertSame(GatewayRole::Operator, $user->role);
        self::assertSame(SiteScopeMode::Selected, $user->site_scope_mode);
        self::assertTrue($user->access_enabled);
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id,
            'permission' => GatewayPermission::ConnectionsTest->value,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'actor_type' => 'administrator',
            'actor_id' => (string) $owner->id,
            'operation' => 'user-access-create:'.$user->id,
            'outcome' => 'success',
        ]);
    }

    public function test_non_owner_cannot_manage_users(): void
    {
        $administrator = User::query()->create([
            'name' => 'Administrator',
            'email' => 'administrator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Administrator->value,
            'site_scope_mode' => SiteScopeMode::All->value,
        ]);

        $this->actingAs($administrator)
            ->get('/admin/users')
            ->assertForbidden();
    }

    public function test_last_recoverable_owner_cannot_be_disabled_or_demoted(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)
            ->put('/admin/users/'.$owner->id, [
                'name' => $owner->name,
                'email' => $owner->email,
                'role' => GatewayRole::Administrator->value,
                'site_scope_mode' => SiteScopeMode::All->value,
                'access_enabled' => '0',
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertSessionHasErrors('access_enabled');

        $owner->refresh();
        self::assertSame(GatewayRole::Owner, $owner->role);
        self::assertTrue($owner->access_enabled);
    }

    public function test_wrong_current_password_cannot_change_user_access(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();

        $this->actingAs($owner)
            ->put('/admin/users/'.$operator->id, [
                'name' => $operator->name,
                'email' => $operator->email,
                'role' => GatewayRole::Viewer->value,
                'site_scope_mode' => SiteScopeMode::Selected->value,
                'access_enabled' => '1',
                'current_password' => 'WrongHorse!234',
            ])
            ->assertSessionHasErrors('current_password');

        self::assertSame(GatewayRole::Operator, $operator->refresh()->role);
    }

    public function test_site_rule_can_make_one_operator_site_write_only_without_elevation(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');

        $this->actingAs($owner)
            ->put(route('admin.users.sites.update', [
                'user' => $operator->id,
                'site' => $site->site_id,
            ], false), [
                'access_rule' => 'allow',
                'denied_permissions' => [
                    GatewayPermission::SitesView->value,
                    GatewayPermission::AbilitiesExecuteReadonly->value,
                ],
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertRedirect();

        $access = app(AccessControl::class);

        self::assertFalse($access->allows($operator, GatewayPermission::SitesView, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::AbilitiesExecuteReadonly, $site));
        self::assertTrue($access->allows($operator, GatewayPermission::AbilitiesExecuteMutating, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::AbilitiesExecuteDestructive, $site));

        $this->assertDatabaseHas('user_site_access', [
            'user_id' => $operator->id,
            'site_record_id' => $site->id,
            'allowed' => true,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'actor_type' => 'administrator',
            'actor_id' => (string) $owner->id,
            'operation' => 'user-site-access-update:'.$operator->id.':alpha',
            'outcome' => 'success',
        ]);
    }

    public function test_all_sites_user_can_explicitly_exclude_one_site(): void
    {
        $owner = $this->owner();
        $administrator = User::query()->create([
            'name' => 'All Sites Admin',
            'email' => 'all-sites@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Administrator->value,
            'site_scope_mode' => SiteScopeMode::All->value,
        ]);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        $this->actingAs($owner)
            ->put(route('admin.users.sites.update', [
                'user' => $administrator->id,
                'site' => $beta->site_id,
            ], false), [
                'access_rule' => 'deny',
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertRedirect();

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($administrator, GatewayPermission::SitesView, $alpha));
        self::assertFalse($access->allows($administrator, GatewayPermission::SitesView, $beta));
    }

    public function test_owner_site_overrides_are_rejected_and_owner_remains_unrestricted(): void
    {
        $owner = $this->owner();
        $site = $this->site('alpha');

        $this->actingAs($owner)
            ->put(route('admin.users.sites.update', [
                'user' => $owner->id,
                'site' => $site->site_id,
            ], false), [
                'access_rule' => 'deny',
                'denied_permissions' => [GatewayPermission::SitesView->value],
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertSessionHasErrors('access_rule');

        self::assertTrue(app(AccessControl::class)->allows(
            $owner,
            GatewayPermission::SitesRemove,
            $site,
        ));
        self::assertSame(0, DB::table('user_site_access')->where('user_id', $owner->id)->count());
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'site_scope_mode' => SiteScopeMode::All->value,
            'access_enabled' => true,
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
            'access_enabled' => true,
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
