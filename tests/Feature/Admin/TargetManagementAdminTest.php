<?php

namespace Tests\Feature\Admin;

use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

final class TargetManagementAdminTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });

        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->metadata($request));
    }

    public function test_owner_can_browse_generic_targets_and_register_valid_wordpress_without_creating_credentials(): void
    {
        $owner = $this->user('owner', 'all');
        $ssh = $this->target('ssh-demo', 'ssh_direct', '<script>alert(1)</script>');

        $this->actingAs($owner)->get('/admin/')->assertOk()
            ->assertSee('Registered Targets');
        $this->get('/admin/targets')->assertOk()
            ->assertSee('ssh-demo')->assertDontSee('<script>alert(1)</script>', false)
            ->assertSee('ssh_direct');
        $this->get('/admin/targets/'.$ssh->target_id)->assertOk()
            ->assertSee('ssh-demo');
        $this->get('/admin/targets/create')->assertOk()
            ->assertSee('Stable Target ID')->assertSee('wp_ai_bridge');

        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'wp-blog',
            'display_name' => 'WordPress blog',
            'base_url' => 'https://wordpress.example.test/',
        ])->assertRedirect('/admin/targets/wp-blog');

        $wp = Target::query()->where('target_id', 'wp-blog')->firstOrFail();
        self::assertSame('wp_ai_bridge', $wp->connector_type);
        self::assertSame('https://wordpress.example.test', WpAiBridgeTargetConfig::query()
            ->where('target_record_id', $wp->getKey())->value('base_url'));
        self::assertSame(0, DB::table('target_credentials')->count());
        $this->get('/admin/targets/wp-blog')->assertOk()
            ->assertSee('WordPress blog')
            ->assertSee('https://wordpress.example.test')
            ->assertSee('Authorize this Target to connect WordPress securely');
    }

    public function test_selected_scope_operator_cannot_discover_other_target_or_enroll_new_connector(): void
    {
        $visible = $this->target('visible', 'wp_ai_bridge');
        $hidden = $this->target('hidden', 'ssh_direct');
        $operator = $this->user('operator', 'selected');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $visible->getKey(),
            'allowed' => true,
        ]);

        $this->actingAs($operator)->get('/admin/targets')->assertOk()
            ->assertSee('visible')->assertDontSee('admin/targets/hidden');
        $this->get('/admin/')->assertOk()->assertSee('Registered Targets');
        $this->get('/admin/targets/'.$visible->target_id)->assertOk();
        $this->get('/admin/targets/'.$hidden->target_id)->assertForbidden();
        $this->get('/admin/targets/create')->assertForbidden();
        $this->post('/admin/targets', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'unexpected',
            'display_name' => 'SSH',
            'base_url' => 'https://wordpress.example.test',
        ])->assertForbidden();

        Http::assertNothingSent();
        self::assertSame(2, Target::query()->count());
    }

    public function test_admin_registration_rejects_unreviewed_connector_and_non_https_or_unsafe_target(): void
    {
        $this->actingAs($this->user('owner', 'all'));

        $this->post('/admin/targets', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'unauthorized',
            'display_name' => 'Unreviewed',
            'base_url' => 'https://wordpress.example.test',
        ])->assertSessionHasErrors('connector_type');

        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'bad-http',
            'display_name' => 'Unreviewed',
            'base_url' => 'http://wordpress.example.test',
        ])->assertSessionHasErrors('base_url');

        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'bad-target',
            'display_name' => 'Private network',
            'base_url' => 'https://127.0.0.1',
        ])->assertSessionHasErrors('base_url');

        self::assertSame(0, Target::query()->count());
        self::assertSame(0, WpAiBridgeTargetConfig::query()->count());
    }

    public function test_owner_can_edit_label_without_mutating_immutable_target_identity_or_connector(): void
    {
        $owner = $this->user('owner', 'all');
        $viewer = $this->user('viewer', 'all');
        $target = $this->target('permanent-id', 'wp_ai_bridge');
        $recordId = (string) $target->getKey();

        $this->actingAs($viewer)->get('/admin/targets/permanent-id/edit')->assertForbidden();
        $this->put('/admin/targets/permanent-id', ['display_name' => 'Unauthorized'])->assertForbidden();

        $this->actingAs($owner)->get('/admin/targets/permanent-id/edit')->assertOk()
            ->assertSee('Only the display name can be changed')
            ->assertSee('permanent-id');
        $this->put('/admin/targets/permanent-id', [
            'display_name' => 'Updated safe label',
            'target_id' => 'hijack',
            'connector_type' => 'ssh_direct',
            'base_url' => 'https://attacker.example.test',
        ])->assertRedirect('/admin/targets/permanent-id');

        $target->refresh();
        self::assertSame($recordId, (string) $target->getKey());
        self::assertSame('permanent-id', $target->target_id);
        self::assertSame('wp_ai_bridge', $target->connector_type);
        self::assertSame('Updated safe label', $target->display_name);
        $this->get('/admin/targets/permanent-id')->assertOk()
            ->assertSee('Edit Target');
    }

    public function test_remove_requires_confirmation_and_refuses_active_or_pending_connection_state(): void
    {
        $owner = $this->user('owner', 'all');
        $viewer = $this->user('viewer', 'all');
        $target = $this->target('to-remove', 'wp_ai_bridge');
        DB::table('user_target_access')->insert([
            'user_id' => $viewer->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);

        $this->actingAs($viewer)->delete('/admin/targets/to-remove', ['confirm_remove' => 'yes'])->assertForbidden();
        $this->actingAs($owner)->delete('/admin/targets/to-remove')->assertSessionHasErrors('confirm_remove');
        self::assertSame(1, Target::query()->where('target_id', 'to-remove')->count());

        $target->forceFill(['connection_state' => 'connected'])->save();
        $this->delete('/admin/targets/to-remove', ['confirm_remove' => 'yes'])->assertSessionHasErrors('target');
        self::assertSame(1, Target::query()->where('target_id', 'to-remove')->count());
        $target->forceFill(['connection_state' => 'disconnected'])->save();

        $this->delete('/admin/targets/to-remove', ['confirm_remove' => 'yes'])
            ->assertRedirect('/admin/targets');
        self::assertSame(0, Target::query()->where('target_id', 'to-remove')->count());
        self::assertSame(0, DB::table('user_target_access')
            ->where('target_record_id', $target->getKey())->count());
        self::assertSame(1, DB::table('activity_events')
            ->where('target_id', 'to-remove')->where('operation', 'target-remove')->count());
        $this->get('/admin/sites')->assertNotFound();
        $this->get('/admin/site-checks')->assertNotFound();
    }

    public function test_target_admin_lifecycle_routes_remain_authenticated_and_web_csrf_guarded(): void
    {
        foreach (['/admin/targets', '/admin/targets/create', '/admin/activity'] as $path) {
            $this->get($path)->assertRedirect('/admin/login');
        }

        foreach ([
            'admin.targets.store',
            'admin.targets.update',
            'admin.targets.destroy',
            'admin.targets.connect',
            'admin.targets.reconnect',
            'admin.targets.disconnect',
            'admin.targets.test',
        ] as $name) {
            $route = Route::getRoutes()->getByName($name);
            self::assertNotNull($route, $name);
            self::assertContains('web', $route->middleware(), $name);
            self::assertContains('auth', $route->middleware(), $name);
        }

        foreach (['admin.sites.store', 'admin.site-checks.store', 'bridge.site.callback'] as $old) {
            self::assertNull(Route::getRoutes()->getByName($old), $old);
        }
    }

    public function test_target_explicit_metadata_check_stores_bounded_failure_without_network_on_read(): void
    {
        $owner = $this->user('owner', 'all');
        $this->actingAs($owner);
        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'metadata-fail',
            'display_name' => 'Metadata check',
            'base_url' => 'https://wordpress.example.test/',
        ])->assertRedirect('/admin/targets/metadata-fail');

        $target = Target::query()->where('target_id', 'metadata-fail')->sole();
        Http::assertSentCount(2);
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(static fn (Request $request) => Http::response(['error' => 'not_found'], 404));

        $this->get('/admin/targets/'.$target->target_id)->assertOk();
        Http::assertNothingSent();

        $this->post(route('admin.targets.test', ['target' => $target->target_id], false))
            ->assertRedirect('/admin/targets/'.$target->target_id)
            ->assertSessionHasErrors('target');
        $target->refresh();
        self::assertNotNull($target->last_tested_at);
        self::assertSame('missing_bridge', $target->last_error_code);
        self::assertSame('missing_bridge', $target->last_failure_code);
        self::assertNotNull($target->last_failure_at);
        $this->get('/admin/targets/'.$target->target_id)
            ->assertOk()->assertSee('missing_bridge');
    }

    private function user(string $role, string $scope): User
    {
        return User::query()->create([
            'name' => 'Test '.$role,
            'email' => uniqid('account-', true).'@example.test',
            'password' => 'ThisIsATestSecret!234',
            'role' => $role,
            'target_scope_mode' => $scope,
            'access_enabled' => true,
        ]);
    }

    private function target(string $id, string $connector, ?string $name = null): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => $name ?? 'Target '.$id,
            'connector_type' => $connector,
        ]);
    }

    private function metadata(Request $request): PromiseInterface
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
            ]);
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
            ]);
        }

        return Http::response([], 404);
    }
}
