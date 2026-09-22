<?php

namespace Tests\Feature\Security;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class AccessControlTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_has_recoverable_full_access_to_every_site(): void
    {
        $owner = $this->user(GatewayRole::Owner, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        DB::table('user_permission_denials')->insert([
            'user_id' => $owner->id,
            'permission' => GatewayPermission::SitesRemove->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_site_access')->insert([
            'user_id' => $owner->id,
            'site_record_id' => $alpha->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);

        self::assertTrue($access->allows($owner, GatewayPermission::SitesRemove, $alpha));
        self::assertTrue($access->allows($owner, GatewayPermission::SecurityManage, $beta));
        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeSites(Site::query(), $owner)->orderBy('site_id')->pluck('site_id')->all(),
        );
    }

    public function test_selected_operator_scope_and_per_site_denials_only_narrow_authority(): void
    {
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $gamma = $this->site('gamma');

        foreach ([$alpha, $beta] as $site) {
            DB::table('user_site_access')->insert([
                'user_id' => $operator->id,
                'site_record_id' => $site->id,
                'allowed' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        DB::table('user_site_permission_denials')->insert([
            'user_id' => $operator->id,
            'site_record_id' => $alpha->id,
            'permission' => GatewayPermission::AbilitiesExecuteMutating->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);

        self::assertTrue($access->allows($operator, GatewayPermission::SitesView, $alpha));
        self::assertTrue($access->allows($operator, GatewayPermission::AbilitiesExecuteReadonly, $alpha));
        self::assertFalse($access->allows($operator, GatewayPermission::AbilitiesExecuteMutating, $alpha));
        self::assertTrue($access->allows($operator, GatewayPermission::AbilitiesExecuteMutating, $beta));
        self::assertFalse($access->allows($operator, GatewayPermission::SitesRemove, $beta));
        self::assertFalse($access->allows($operator, GatewayPermission::SitesView, $gamma));

        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeSites(Site::query(), $operator)->orderBy('site_id')->pluck('site_id')->all(),
        );
    }

    public function test_all_site_scope_can_exclude_one_site_and_global_denials_apply_everywhere(): void
    {
        $administrator = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        DB::table('user_site_access')->insert([
            'user_id' => $administrator->id,
            'site_record_id' => $beta->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_permission_denials')->insert([
            'user_id' => $administrator->id,
            'permission' => GatewayPermission::ConnectionsDisconnect->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);

        self::assertTrue($access->allows($administrator, GatewayPermission::SitesView, $alpha));
        self::assertFalse($access->allows($administrator, GatewayPermission::SitesView, $beta));
        self::assertFalse($access->allows($administrator, GatewayPermission::ConnectionsDisconnect, $alpha));
        self::assertSame(
            ['alpha'],
            $access->scopeSites(Site::query(), $administrator)->pluck('site_id')->all(),
        );
    }

    public function test_disabled_user_is_denied_even_when_role_and_scope_would_allow_access(): void
    {
        $viewer = $this->user(GatewayRole::Viewer, SiteScopeMode::All, false);
        $site = $this->site('alpha');

        $access = app(AccessControl::class);

        self::assertFalse($access->allows($viewer, GatewayPermission::SitesView, $site));
        self::assertSame(0, $access->scopeSites(Site::query(), $viewer)->count());
    }

    private function user(
        GatewayRole $role,
        SiteScopeMode $scope,
        bool $enabled = true,
    ): User {
        return User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'site_scope_mode' => $scope->value,
            'access_enabled' => $enabled,
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
            'connection_state' => 'connected',
            'connected_at' => now(),
        ]);
    }
}
