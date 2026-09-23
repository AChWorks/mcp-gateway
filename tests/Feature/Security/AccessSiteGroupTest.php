<?php

namespace Tests\Feature\Security;

use App\Application\Access\AccessControl;
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
final class AccessSiteGroupTest extends TestCase
{
    use RefreshDatabase;

    public function test_group_membership_extends_selected_scope_but_direct_site_deny_remains_authoritative(): void
    {
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $group = $this->group('Production');
        $this->assign($group, $operator);
        $this->includeSite($group, $alpha);
        $this->includeSite($group, $beta);

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($operator, GatewayPermission::SitesView, $alpha));
        self::assertTrue($access->allows($operator, GatewayPermission::AbilitiesExecuteMutating, $beta));
        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeSites(Site::query(), $operator)->orderBy('site_id')->pluck('site_id')->all(),
        );

        DB::table('user_site_access')->insert([
            'user_id' => $operator->id,
            'site_record_id' => $alpha->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        self::assertFalse($access->allows($operator, GatewayPermission::SitesView, $alpha));
        self::assertSame(
            ['beta'],
            $access->scopeSites(Site::query(), $operator)->orderBy('site_id')->pluck('site_id')->all(),
        );
    }

    public function test_overlapping_group_denials_accumulate_and_direct_permission_denials_remain_final(): void
    {
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $site = $this->site('alpha');
        $readGroup = $this->group('Read restrictions');
        $writeGroup = $this->group('Write restrictions');

        foreach ([$readGroup, $writeGroup] as $group) {
            $this->assign($group, $operator);
            $this->includeSite($group, $site);
        }
        $this->deny($readGroup, GatewayPermission::AbilitiesExecuteReadonly);
        $this->deny($writeGroup, GatewayPermission::AbilitiesExecuteMutating);

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($operator, GatewayPermission::SitesView, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::AbilitiesExecuteReadonly, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::AbilitiesExecuteMutating, $site));

        DB::table('user_site_permission_denials')->insert([
            'user_id' => $operator->id,
            'site_record_id' => $site->id,
            'permission' => GatewayPermission::AbilitiesInspect->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        self::assertFalse($access->allows($operator, GatewayPermission::AbilitiesInspect, $site));
        self::assertSame(
            [],
            $access->scopeSites(Site::query(), $operator, GatewayPermission::AbilitiesInspect)
                ->pluck('site_id')->all(),
        );
    }

    public function test_group_never_bypasses_role_or_global_permission_ceiling(): void
    {
        $viewer = $this->user(GatewayRole::Viewer, SiteScopeMode::Selected);
        $site = $this->site('alpha');
        $group = $this->group('Viewer sites');
        $this->assign($group, $viewer);
        $this->includeSite($group, $site);

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($viewer, GatewayPermission::SitesView, $site));
        self::assertFalse($access->allows($viewer, GatewayPermission::AbilitiesExecuteMutating, $site));

        DB::table('user_permission_denials')->insert([
            'user_id' => $viewer->id,
            'permission' => GatewayPermission::SitesView->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        self::assertFalse($access->allows($viewer, GatewayPermission::SitesView, $site));
        self::assertSame(0, $access->scopeSites(Site::query(), $viewer)->count());
    }

    public function test_all_scope_group_denials_narrow_matching_sites_and_owner_recovery_stays_unrestricted(): void
    {
        $administrator = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $owner = $this->user(GatewayRole::Owner, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $group = $this->group('Restricted');

        $this->assign($group, $administrator);
        $this->includeSite($group, $alpha);
        $this->deny($group, GatewayPermission::SitesView);

        DB::table('site_group_users')->insert([
            'site_group_id' => $group->id,
            'user_id' => $owner->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);
        self::assertFalse($access->allows($administrator, GatewayPermission::SitesView, $alpha));
        self::assertTrue($access->allows($administrator, GatewayPermission::SitesView, $beta));
        self::assertTrue($access->allows($owner, GatewayPermission::SitesView, $alpha));
        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeSites(Site::query(), $owner)->orderBy('site_id')->pluck('site_id')->all(),
        );
    }

    public function test_group_derived_scope_is_enforced_by_admin_inventory_and_direct_routes(): void
    {
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $group = $this->group('Admin scope');
        $this->assign($group, $operator);
        $this->includeSite($group, $alpha);

        $this->actingAs($operator)
            ->get('/admin/sites')
            ->assertOk()
            ->assertSee('Alpha')
            ->assertDontSee('Beta');

        $this->actingAs($operator)
            ->get(route('admin.sites.show', ['site' => $alpha->site_id], false))
            ->assertOk();

        $this->actingAs($operator)
            ->get(route('admin.sites.show', ['site' => $beta->site_id], false))
            ->assertForbidden();
    }

    private function user(GatewayRole $role, SiteScopeMode $scope): User
    {
        return User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'site_scope_mode' => $scope->value,
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

    private function group(string $name): SiteGroup
    {
        return SiteGroup::query()->create(['name' => $name]);
    }

    private function assign(SiteGroup $group, User $user): void
    {
        DB::table('site_group_users')->insert([
            'site_group_id' => $group->id,
            'user_id' => $user->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function includeSite(SiteGroup $group, Site $site): void
    {
        DB::table('site_group_sites')->insert([
            'site_group_id' => $group->id,
            'site_record_id' => $site->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function deny(SiteGroup $group, GatewayPermission $permission): void
    {
        DB::table('site_group_permission_denials')->insert([
            'site_group_id' => $group->id,
            'permission' => $permission->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
