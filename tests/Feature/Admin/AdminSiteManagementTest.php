<?php

namespace Tests\Feature\Admin;

use App\Application\Sites\SiteConnectionService;
use App\Application\Sites\SiteRegistry;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Tests\TestCase;

final class AdminSiteManagementTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.name', 'MCP Gateway Test');
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/sites/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');
        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });

        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->bridgeResponse($request));
    }

    public function test_admin_site_and_activity_routes_require_authentication_and_state_changes_stay_in_web_boundary(): void
    {
        foreach (['/admin/sites', '/admin/sites/create', '/admin/activity'] as $path) {
            $this->get($path)->assertRedirect('/admin/login');
        }

        foreach ([
            'admin.sites.store',
            'admin.sites.update',
            'admin.sites.destroy',
            'admin.sites.connect',
            'admin.sites.reconnect',
            'admin.sites.disconnect',
            'admin.sites.test',
        ] as $name) {
            $route = Route::getRoutes()->getByName($name);
            self::assertNotNull($route, $name);
            self::assertContains('web', $route->middleware(), $name);
            self::assertContains('auth', $route->middleware(), $name);
        }
    }

    public function test_operator_can_open_create_site_form(): void
    {
        $this->actingAs($this->administrator());

        $this->get('/admin/sites/create')
            ->assertOk()
            ->assertSee('Add WordPress site')
            ->assertSee('Discover and add site');
    }

    public function test_operator_can_create_edit_test_and_view_site_through_real_registry(): void
    {
        $this->actingAs($this->administrator());

        $response = $this->post('/admin/sites', [
            'display_name' => 'Alpha WordPress',
            'base_url' => 'https://alpha.example.test/',
        ]);

        $site = Site::query()->sole();
        self::assertStringStartsWith('site-', $site->site_id);
        self::assertSame('Alpha WordPress', $site->display_name);
        self::assertSame('https://alpha.example.test', $site->base_url);
        self::assertSame(SiteConnectionState::Disconnected, $site->connection_state);
        $response->assertRedirect(route('admin.sites.show', ['site' => $site->site_id], false));

        $this->get(route('admin.sites.show', ['site' => $site->site_id], false))
            ->assertOk()
            ->assertSee('Alpha WordPress')
            ->assertSee($site->site_id)
            ->assertSee('Configured')
            ->assertDontSee('access_token')
            ->assertDontSee('refresh_token');

        $this->put(route('admin.sites.update', ['site' => $site->site_id], false), [
            'display_name' => 'Alpha Production Mirror',
            'base_url' => 'https://beta.example.test',
        ])->assertRedirect(route('admin.sites.show', ['site' => $site->site_id], false));

        $site->refresh();
        self::assertSame('Alpha Production Mirror', $site->display_name);
        self::assertSame('https://beta.example.test', $site->base_url);

        $this->post(route('admin.sites.test', ['site' => $site->site_id], false))
            ->assertRedirect(route('admin.sites.show', ['site' => $site->site_id], false))
            ->assertSessionHas('status');

        $site->refresh();
        self::assertNotNull($site->last_tested_at);
        self::assertNull($site->last_error_code);
        self::assertNull($site->last_success_at);
        self::assertNull($site->last_failure_at);

        $this->get('/admin/sites')
            ->assertOk()
            ->assertSee('Alpha Production Mirror')
            ->assertSee('Never connected');
    }

    public function test_connect_reconnect_disconnect_and_remove_use_real_site_lifecycle(): void
    {
        $this->actingAs($this->administrator());
        $site = app(SiteRegistry::class)->create('alpha', 'Alpha', 'https://alpha.example.test');

        $connect = $this->post(route('admin.sites.connect', ['site' => $site->site_id], false));
        $authorizationUrl = (string) $connect->headers->get('Location');
        self::assertStringStartsWith('https://alpha.example.test/wp-ai-bridge/oauth/authorize?', $authorizationUrl);
        self::assertSame(SiteConnectionState::Pending, $site->refresh()->connection_state);

        $this->completeAuthorization($site, $authorizationUrl);
        self::assertSame(SiteConnectionState::Connected, $site->refresh()->connection_state);
        self::assertTrue($site->credential()->exists());
        $this->get(route('admin.sites.show', ['site' => $site->site_id], false))
            ->assertOk()
            ->assertDontSee('alpha-access')
            ->assertDontSee('alpha-refresh');

        $this->post(route('admin.sites.disconnect', ['site' => $site->site_id], false))
            ->assertRedirect(route('admin.sites.show', ['site' => $site->site_id], false));
        self::assertSame(SiteConnectionState::Disconnected, $site->refresh()->connection_state);
        self::assertFalse($site->credential()->exists());

        $authorizationUrl = app(SiteConnectionService::class)->begin($site);
        $this->completeAuthorization($site, $authorizationUrl);
        self::assertTrue($site->credential()->exists());

        $reconnect = $this->post(route('admin.sites.reconnect', ['site' => $site->site_id], false));
        $reconnectUrl = (string) $reconnect->headers->get('Location');
        self::assertStringStartsWith('https://alpha.example.test/wp-ai-bridge/oauth/authorize?', $reconnectUrl);
        self::assertSame(SiteConnectionState::Pending, $site->refresh()->connection_state);
        self::assertFalse($site->credential()->exists());

        $this->completeAuthorization($site, $reconnectUrl);
        self::assertTrue($site->credential()->exists());

        $this->delete(route('admin.sites.destroy', ['site' => $site->site_id], false), [
            'confirm_site_id' => 'wrong-site-id',
        ])->assertSessionHasErrors('confirm_site_id');
        self::assertTrue(Site::query()->whereKey($site->getKey())->exists());

        $this->delete(route('admin.sites.destroy', ['site' => $site->site_id], false), [
            'confirm_site_id' => $site->site_id,
        ])->assertRedirect(route('admin.sites.index', [], false));
        self::assertFalse(Site::query()->whereKey($site->getKey())->exists());
    }

    public function test_dashboard_activity_and_site_status_views_are_bounded_and_secret_safe(): void
    {
        $this->actingAs($this->administrator());
        $registry = app(SiteRegistry::class);
        $connected = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');
        $unreachable = $registry->create('beta', 'Beta', 'https://beta.example.test');
        $incompatible = $registry->create('gamma', 'Gamma', 'https://gamma.example.test');

        $connected->forceFill([
            'connection_state' => SiteConnectionState::Connected,
            'connected_at' => now(),
            'last_success_at' => now(),
        ])->save();
        $unreachable->forceFill([
            'connection_state' => SiteConnectionState::Error,
            'last_error_code' => 'network_failure',
        ])->save();
        $incompatible->forceFill([
            'connection_state' => SiteConnectionState::Error,
            'last_error_code' => 'incompatible_metadata',
        ])->save();

        $privateClientHash = str_repeat('a', 64);
        for ($index = 0; $index < 30; $index++) {
            DB::table('activity_events')->insert([
                'id' => (string) Str::ulid(),
                'correlation_id' => (string) Str::uuid(),
                'actor_type' => 'oauth_client',
                'actor_id' => 'operator-'.$index,
                'client_id_hash' => $privateClientHash,
                'site_id' => $connected->site_id,
                'operation' => 'site-ability-execute-'.$index,
                'outcome' => $index % 2 === 0 ? 'success' : 'failure',
                'error_code' => $index % 2 === 0 ? null : 'downstream_rejected',
                'created_at' => now()->subSeconds(30 - $index),
            ]);
        }

        $this->get('/admin')
            ->assertOk()
            ->assertSee('3')
            ->assertSee('1')
            ->assertSee('2')
            ->assertSee('Stale or unknown evidence')
            ->assertDontSee($privateClientHash)
            ->assertDontSee('operator-29');

        $this->get('/admin/sites')
            ->assertOk()
            ->assertSee('Connected')
            ->assertSee('Unreachable')
            ->assertSee('Incompatible');

        $activity = $this->get('/admin/activity');
        $activity->assertOk()
            ->assertSee('site-ability-execute-29')
            ->assertSee('Next')
            ->assertDontSee('site-ability-execute-0')
            ->assertDontSee($privateClientHash)
            ->assertDontSee('operator-29');

        $this->get('/admin/activity?page=999999')
            ->assertOk()
            ->assertDontSee($privateClientHash);
    }

    public function test_invalid_public_site_target_is_reported_without_exposing_internal_details(): void
    {
        $this->actingAs($this->administrator());

        $this->from('/admin/sites/create')
            ->post('/admin/sites', [
                'display_name' => 'Unsafe',
                'base_url' => 'http://127.0.0.1/private',
            ])
            ->assertRedirect('/admin/sites/create')
            ->assertSessionHasErrors([
                'site' => 'Use a public HTTPS WordPress URL that is reachable from the Gateway.',
            ]);

        self::assertSame(0, Site::query()->count());
    }

    private function administrator(): User
    {
        return User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'admin@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Administrator->value,
            'site_scope_mode' => SiteScopeMode::All->value,
        ]);
    }

    private function completeAuthorization(Site $site, string $authorizationUrl): void
    {
        parse_str((string) parse_url($authorizationUrl, PHP_URL_QUERY), $query);
        $state = $query['state'] ?? null;
        self::assertIsString($state);

        app(SiteConnectionService::class)->completeCallback(
            $state,
            $site->site_id.'-code',
            $site->base_url,
            null,
        );
    }

    private function bridgeResponse(Request $request)
    {
        $host = (string) parse_url($request->url(), PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($request->url(), PHP_URL_PATH);

        if ($path === '/.well-known/oauth-protected-resource') {
            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
                'resource_name' => 'WP AI Bridge',
            ], 200);
        }

        if ($path === '/.well-known/oauth-authorization-server') {
            return Http::response([
                'issuer' => $base,
                'authorization_endpoint' => $base.'/wp-ai-bridge/oauth/authorize',
                'token_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
                'revocation_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
                'client_id_metadata_document_supported' => true,
                'authorization_response_iss_parameter_supported' => true,
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'response_types_supported' => ['code'],
                'code_challenge_methods_supported' => ['S256'],
                'scopes_supported' => ['mcp:use', 'offline_access'],
            ], 200);
        }

        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/token') {
            $prefix = str_starts_with($host, 'alpha.') ? 'alpha' : 'site';

            return Http::response([
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'access_token' => $prefix.'-access',
                'refresh_token' => $prefix.'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }

        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/revoke') {
            return Http::response([], 200);
        }

        return Http::response([], 404);
    }
}
