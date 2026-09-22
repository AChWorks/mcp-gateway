<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class AdminAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    public function test_selected_operator_sees_only_authorized_sites_and_direct_url_cannot_bypass_scope(): void
    {
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        $this->allowSite($operator, $alpha);

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

        $this->actingAs($operator)
            ->put(route('admin.sites.update', ['site' => $alpha->site_id], false), [
                'display_name' => 'Changed',
                'base_url' => $alpha->base_url,
            ])
            ->assertForbidden();
    }

    public function test_per_site_denial_narrows_administrator_without_affecting_other_site(): void
    {
        $administrator = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        DB::table('user_site_permission_denials')->insert([
            'user_id' => $administrator->id,
            'site_record_id' => $alpha->id,
            'permission' => GatewayPermission::SitesUpdate->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($administrator)
            ->put(route('admin.sites.update', ['site' => $alpha->site_id], false), [
                'display_name' => 'Alpha changed',
                'base_url' => $alpha->base_url,
            ])
            ->assertForbidden();

        $this->actingAs($administrator)
            ->put(route('admin.sites.update', ['site' => $beta->site_id], false), [
                'display_name' => 'Beta changed',
                'base_url' => $beta->base_url,
            ])
            ->assertRedirect();

        self::assertSame('Alpha', $alpha->refresh()->display_name);
        self::assertSame('Beta changed', $beta->refresh()->display_name);
    }

    public function test_disabled_user_cannot_start_a_new_admin_session(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All, false);

        $this->post('/admin/login', [
            'email' => $user->email,
            'password' => 'CorrectHorse!234',
        ])
            ->assertSessionHasErrors([
                'email' => 'The provided credentials are invalid.',
            ]);

        $this->assertGuest();
    }

    public function test_disabled_user_existing_browser_session_is_terminated_for_admin_and_oauth(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All);

        $this->actingAs($user)
            ->get('/admin')
            ->assertOk();

        $user->forceFill(['access_enabled' => false])->save();

        $this->actingAs($user)
            ->get('/admin')
            ->assertRedirect('/admin/login');
        $this->assertGuest();

        $this->actingAs($user)
            ->get('/oauth/authorize')
            ->assertUnauthorized()
            ->assertSee('Administrator sign-in required');
        $this->assertGuest();
    }

    public function test_selected_scope_activity_excludes_other_sites_and_gateway_global_events(): void
    {
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $alpha = $this->site('alpha');
        $this->site('beta');
        $this->allowSite($operator, $alpha);

        $this->activity('alpha', 'alpha-visible');
        $this->activity('beta', 'beta-hidden');
        $this->activity(null, 'gateway-hidden');

        $this->actingAs($operator)
            ->get('/admin/activity')
            ->assertOk()
            ->assertSee('alpha-visible')
            ->assertDontSee('beta-hidden')
            ->assertDontSee('gateway-hidden');
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
            'connection_state' => 'disconnected',
        ]);
    }

    private function allowSite(User $user, Site $site): void
    {
        DB::table('user_site_access')->insert([
            'user_id' => $user->id,
            'site_record_id' => $site->id,
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function activity(?string $siteId, string $operation): void
    {
        DB::table('activity_events')->insert([
            'id' => (string) Str::ulid(),
            'correlation_id' => (string) Str::uuid(),
            'actor_type' => 'system',
            'actor_id' => null,
            'client_id_hash' => null,
            'site_id' => $siteId,
            'operation' => $operation,
            'outcome' => 'success',
            'error_code' => null,
            'created_at' => now(),
        ]);
    }
}
