<?php

namespace Tests\Feature\Security;

use App\Application\Mcp\PendingGatewayToolHandlers;
use App\Application\Sites\SiteConnectionService;
use App\Application\Sites\SiteRegistry;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteCredential;
use App\Http\Middleware\EnsureCorrelationId;
use App\Http\Middleware\ObserveOAuthTokenRequest;
use App\Infrastructure\Activity\ActivityFeed;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\OAuth\SiteCredentialVault;
use App\Models\User;
use App\Support\BoundedLogDefaults;
use App\Support\CorrelationId;
use DateTimeImmutable;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

final class IntegratedSafeguardsTest extends TestCase
{
    use RefreshDatabase;

    public function test_mcp_correlation_id_is_shared_with_safe_activity_and_response_header(): void
    {
        $request = Request::create('/mcp', 'POST', [
            'access_token' => 'must-not-be-recorded',
            'password' => 'must-not-be-recorded-either',
        ]);
        $request->attributes->set('oauth_client_id', 'https://chatgpt.com/oauth/client.json');
        $request->attributes->set('oauth_user_id', '42');
        $this->app->instance('request', $request);

        $response = app(EnsureCorrelationId::class)->handle(
            $request,
            function (): Response {
                return response()->json(app(PendingGatewayToolHandlers::class)->sitesList());
            },
        );

        $payload = json_decode((string) $response->getContent(), true, 32, JSON_THROW_ON_ERROR);
        $correlationId = (string) $payload['correlation_id'];

        self::assertTrue(Str::isUuid($correlationId));
        self::assertSame($correlationId, $response->headers->get(CorrelationId::HEADER));

        $activity = DB::table('activity_events')->first();
        self::assertNotNull($activity);
        self::assertSame($correlationId, $activity->correlation_id);
        self::assertSame('oauth_user', $activity->actor_type);
        self::assertSame('42', $activity->actor_id);
        self::assertSame(hash('sha256', 'https://chatgpt.com/oauth/client.json'), $activity->client_id_hash);
        self::assertSame('sites-list', $activity->operation);
        self::assertSame('success', $activity->outcome);

        $serialized = json_encode($activity, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('must-not-be-recorded', $serialized);
        self::assertStringNotContainsString('password', $serialized);
    }

    public function test_activity_storage_scheduled_retention_and_feed_are_bounded_and_metadata_only(): void
    {
        config()->set('activity.max_rows', 3);
        config()->set('activity.page_size_max', 2);

        $recorder = app(ActivityRecorder::class);
        for ($index = 1; $index <= 5; $index++) {
            $recorder->record((string) Str::uuid(), 'site-ability-execute', 'success', 'site-'.$index);
        }

        self::assertSame(5, DB::table('activity_events')->count());
        $this->artisan('activity:prune')->assertSuccessful();
        self::assertSame(3, DB::table('activity_events')->count());

        $user = User::query()->create([
            'name' => 'Activity Owner',
            'email' => 'activity-owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'site_scope_mode' => SiteScopeMode::All->value,
        ]);
        $page = app(ActivityFeed::class)->page($user, 1, 50);
        self::assertSame(2, $page['per_page']);
        self::assertCount(2, $page['items']);
        self::assertTrue($page['has_more']);

        $encoded = json_encode($page, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('payload', $encoded);
        self::assertStringNotContainsString('authorization', strtolower($encoded));
        self::assertStringNotContainsString('client_id_hash', $encoded);
    }

    public function test_default_application_logging_is_bounded_daily_rotation(): void
    {
        $example = file_get_contents(base_path('.env.example'));
        self::assertIsString($example);
        self::assertStringContainsString("LOG_CHANNEL=daily\n", $example);
        self::assertStringContainsString("LOG_STACK=daily\n", $example);
        self::assertStringContainsString("LOG_DAILY_DAYS=14\n", $example);
        self::assertSame(14, (int) config('logging.channels.daily.max_files'));
        self::assertSame(['daily', 'daily'], BoundedLogDefaults::normalize('stack', 'single'));
        self::assertSame(['stack', 'daily,stderr'], BoundedLogDefaults::normalize('stack', 'daily,stderr'));
        self::assertSame(['single', 'single'], BoundedLogDefaults::normalize('single', 'single'));
    }

    public function test_wrong_application_key_fails_closed_without_losing_encrypted_credential(): void
    {
        $site = $this->rawSite('recovery');
        $vault = app(SiteCredentialVault::class);
        $secretAccess = 'recovery-access-secret';
        $secretRefresh = 'recovery-refresh-secret';
        $resource = $site->mcp_resource_url;
        $clientId = 'https://gateway.example.test/oauth/client.json';
        $encrypted = $vault->seal(
            $site,
            $clientId,
            $resource,
            $secretAccess,
            $secretRefresh,
            new DateTimeImmutable('+1 hour'),
            ['mcp:use', 'offline_access'],
        );

        $credential = SiteCredential::query()->create([
            'site_record_id' => (string) $site->getKey(),
            'client_id' => $clientId,
            'resource_url' => $resource,
            'binding_hash' => SiteCredentialVault::bindingHash($site, $clientId, $resource),
            'encrypted_payload' => $encrypted,
            'access_expires_at' => now()->addHour(),
        ]);

        $originalEncrypter = app('encrypter');
        Crypt::swap(new Encrypter(random_bytes(32), 'AES-256-CBC'));
        Http::preventStrayRequests();

        try {
            $result = app(PendingGatewayToolHandlers::class)
                ->siteAbilityExecute('recovery', 'demo/read', []);
        } finally {
            Crypt::swap($originalEncrypter);
        }

        self::assertFalse($result['ok']);
        self::assertSame('credential_unavailable', $result['error']['code']);
        self::assertStringNotContainsString($secretAccess, $result['error']['message']);
        self::assertStringNotContainsString($secretRefresh, $result['error']['message']);
        self::assertDatabaseHas('activity_events', [
            'site_id' => 'recovery',
            'operation' => 'site-ability-execute',
            'outcome' => 'failure',
            'error_code' => 'credential_unavailable',
        ]);
        self::assertDatabaseHas('site_credentials', [
            'id' => $credential->id,
            'site_record_id' => $site->id,
            'encrypted_payload' => $encrypted,
        ]);
        self::assertDatabaseHas('sites', ['id' => $site->id, 'site_id' => 'recovery']);
    }

    public function test_downstream_echo_of_site_bearer_is_redacted_from_mcp_error_and_activity(): void
    {
        $this->prepareBridgeEnvironment();
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);

        $this->resetHttp();
        Http::fake(function (ClientRequest $request) {
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
                return Http::response(['error' => 'unexpected'], 500);
            }
            if ($request->method() === 'DELETE') {
                return Http::response('', 200);
            }

            $payload = $request->data();
            if (($payload['method'] ?? null) === 'initialize') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25'],
                ], 200, ['Mcp-Session-Id' => 'session-alpha']);
            }

            return Http::response([
                'jsonrpc' => '2.0',
                'id' => 2,
                'result' => [
                    'isError' => true,
                    'content' => [[
                        'type' => 'text',
                        'text' => 'Denied while processing Bearer alpha-access / alpha-access.',
                    ]],
                ],
            ], 200);
        });

        $result = app(PendingGatewayToolHandlers::class)->siteAbilityExecute('alpha', 'demo/denied', []);

        self::assertFalse($result['ok']);
        self::assertSame('downstream_rejected', $result['error']['code']);
        self::assertStringContainsString('[redacted]', $result['error']['message']);

        $encoded = json_encode([
            'result' => $result,
            'activity' => DB::table('activity_events')->get()->all(),
        ], JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('alpha-access', $encoded);
        self::assertStringNotContainsString('alpha-refresh', $encoded);
    }

    public function test_interleaved_site_a_and_site_b_requests_never_share_target_or_bearer(): void
    {
        $this->prepareBridgeEnvironment();
        $alpha = $this->createSite('alpha');
        $beta = $this->createSite('beta');
        $this->pair($alpha);
        $this->pair($beta);

        $this->resetHttp();
        $seen = [];
        $triggered = false;
        $handlers = app(PendingGatewayToolHandlers::class);

        Http::fake(function (ClientRequest $request) use (&$seen, &$triggered, $handlers) {
            $host = (string) parse_url($request->url(), PHP_URL_HOST);
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
                return Http::response(['error' => 'unexpected'], 500);
            }

            $seen[] = [
                'host' => $host,
                'authorization' => $this->requestHeader($request, 'Authorization'),
                'method' => $request->method(),
            ];

            if ($request->method() === 'DELETE') {
                return Http::response('', 200);
            }

            $siteId = (string) strtok($host, '.');
            $payload = $request->data();
            if (($payload['method'] ?? null) === 'initialize') {
                if ($siteId === 'alpha' && ! $triggered) {
                    $triggered = true;
                    $beta = $handlers->siteAbilityExecute('beta', 'demo/read', []);
                    self::assertTrue($beta['ok']);
                    self::assertSame('beta', $beta['result']['site']);
                }

                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25'],
                ], 200, ['Mcp-Session-Id' => 'session-'.$siteId]);
            }

            return Http::response([
                'jsonrpc' => '2.0',
                'id' => 2,
                'result' => [
                    'isError' => false,
                    'structuredContent' => ['success' => true, 'data' => ['site' => $siteId]],
                ],
            ], 200);
        });

        $alphaResult = $handlers->siteAbilityExecute('alpha', 'demo/read', []);
        self::assertTrue($alphaResult['ok']);
        self::assertSame('alpha', $alphaResult['result']['site']);
        self::assertTrue($triggered);

        $hosts = array_column($seen, 'host');
        self::assertContains('alpha.example.test', $hosts);
        self::assertContains('beta.example.test', $hosts);

        foreach ($seen as $request) {
            $expected = str_starts_with($request['host'], 'alpha.') ? 'Bearer alpha-access' : 'Bearer beta-access';
            self::assertSame($expected, $request['authorization']);
        }
    }

    public function test_sensitive_routes_keep_current_rate_limit_boundaries(): void
    {
        $routes = collect(Route::getRoutes()->getRoutes());

        $mcp = $routes->first(fn ($route) => $route->uri() === 'mcp' && in_array('POST', $route->methods(), true));
        self::assertNotNull($mcp);
        self::assertContains(EnsureCorrelationId::class, $mcp->middleware());
        self::assertContains('throttle:mcp-edge', $mcp->middleware());
        self::assertContains('throttle:mcp', $mcp->middleware());

        $token = $routes->first(fn ($route) => $route->uri() === 'oauth/token' && in_array('POST', $route->methods(), true));
        self::assertNotNull($token);
        self::assertContains(EnsureCorrelationId::class, $token->middleware());
        self::assertContains(ObserveOAuthTokenRequest::class, $token->middleware());
        self::assertContains('throttle:oauth-token', $token->middleware());

        $login = Route::getRoutes()->getByName('admin.login.store');
        self::assertNotNull($login);
        self::assertContains('throttle:admin-login', $login->middleware());
    }

    private function prepareBridgeEnvironment(): void
    {
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

        $this->resetHttp();
        Http::fake(fn (ClientRequest $request) => $this->bridgeResponse($request));
    }

    private function createSite(string $siteId): Site
    {
        return app(SiteRegistry::class)->create($siteId, ucfirst($siteId), 'https://'.$siteId.'.example.test');
    }

    private function pair(Site $site): void
    {
        $connections = app(SiteConnectionService::class);
        $authorizeUrl = $connections->begin($site);
        parse_str((string) parse_url($authorizeUrl, PHP_URL_QUERY), $query);
        self::assertIsString($query['state'] ?? null);
        $connections->completeCallback((string) $query['state'], $site->site_id.'-code', $site->base_url, null);
    }

    private function rawSite(string $siteId): Site
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

    private function resetHttp(): void
    {
        Http::swap(new Factory);
        Http::preventStrayRequests();
    }

    private function bridgeResponse(ClientRequest $request)
    {
        $url = $request->url();
        $host = (string) parse_url($url, PHP_URL_HOST);
        $siteId = (string) strtok($host, '.');
        $base = 'https://'.$host;
        $path = (string) parse_url($url, PHP_URL_PATH);

        if ($path === '/.well-known/oauth-protected-resource') {
            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
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
            return Http::response([
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'access_token' => $siteId.'-access',
                'refresh_token' => $siteId.'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }

        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/revoke') {
            return Http::response('', 200);
        }

        return Http::response(['error' => 'unexpected'], 500);
    }

    private function requestHeader(ClientRequest $request, string $name): string
    {
        $value = $request->header($name);
        if (is_array($value)) {
            return (string) ($value[0] ?? '');
        }

        return (string) $value;
    }
}
