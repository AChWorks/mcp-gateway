<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

final class SiteHealthPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_dashboard_inventory_and_detail_use_stored_evidence_without_remote_fan_out(): void
    {
        Http::preventStrayRequests();
        config()->set('bridge.health.stale_after_hours', 24);

        $owner = $this->user(GatewayRole::Owner, SiteScopeMode::All);
        $healthy = $this->site('healthy', SiteConnectionState::Connected, [
            'connected_at' => now(),
            'last_success_at' => now(),
        ]);
        $this->site('stale', SiteConnectionState::Connected, [
            'connected_at' => now()->subDays(3),
            'last_success_at' => now()->subDays(3),
        ]);
        $this->site('unreachable', SiteConnectionState::Error, [
            'last_error_code' => 'network_failure',
            'last_failure_at' => now(),
            'last_failure_code' => 'network_failure',
        ]);

        $this->actingAs($owner);

        $this->get('/admin')
            ->assertOk()
            ->assertSee('Stale or unknown evidence');

        $this->get('/admin/sites')
            ->assertOk()
            ->assertSee('Healthy')
            ->assertSee('Stale')
            ->assertSee('Unreachable')
            ->assertSee('Latest evidence');

        $this->get(route('admin.sites.show', ['site' => $healthy->site_id], false))
            ->assertOk()
            ->assertSee('Last successful operation')
            ->assertSee('Last explicit check')
            ->assertSee('Latest failure');

        Http::assertNothingSent();
    }

    public function test_health_rendering_honors_site_scope_before_pagination_and_serialization(): void
    {
        Http::preventStrayRequests();

        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $visible = $this->site('visible', SiteConnectionState::Connected, [
            'connected_at' => now(),
            'last_success_at' => now(),
        ]);
        $this->site('hidden', SiteConnectionState::Error, [
            'last_error_code' => 'network_failure',
            'last_failure_at' => now(),
            'last_failure_code' => 'network_failure',
        ]);

        DB::table('user_site_access')->insert([
            'user_id' => $operator->id,
            'site_record_id' => $visible->id,
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($operator)
            ->get('/admin/sites')
            ->assertOk()
            ->assertSee('Visible')
            ->assertSee('Healthy')
            ->assertDontSee('Hidden')
            ->assertDontSee('network_failure');

        Http::assertNothingSent();
    }

    /** @param array<string,mixed> $evidence */
    private function site(string $siteId, SiteConnectionState $state, array $evidence): Site
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
            'connection_state' => $state,
            ...$evidence,
        ]);
    }

    private function user(GatewayRole $role, SiteScopeMode $scope): User
    {
        return User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-health-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'site_scope_mode' => $scope->value,
            'access_enabled' => true,
        ]);
    }
}
