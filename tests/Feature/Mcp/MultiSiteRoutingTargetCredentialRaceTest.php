<?php

namespace Tests\Feature\Mcp;

use App\Application\Sites\SiteConnectionService;
use App\Application\Sites\SiteRegistry;
use App\Domain\Sites\Site;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpClient;
use App\Infrastructure\Http\DnsResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

final class MultiSiteRoutingTargetCredentialRaceTest extends TestCase
{
    use RefreshDatabase;

    /** @var list<array{host:string,authorization:string,method:string}> */
    private array $mcpRequests = [];

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

        $this->fakeBridge();
    }

    public function test_stale_site_snapshot_never_pairs_new_target_credential_with_old_target(): void
    {
        $site = $this->createSite();
        $this->pair($site);
        $stale = Site::query()->whereKey($site->getKey())->firstOrFail();

        $updated = app(SiteRegistry::class)->update(
            $site->fresh(),
            'Alpha',
            'https://beta.example.test',
        );
        $this->pair($updated);
        $this->mcpRequests = [];

        $result = app(WpAiBridgeMcpClient::class)->executeAbility(
            $stale,
            'demo/read',
            [],
            'stale-snapshot-regression',
        );

        self::assertSame(['site' => 'beta'], $result);
        self::assertNotEmpty($this->mcpRequests);
        foreach ($this->mcpRequests as $request) {
            self::assertSame('beta.example.test', $request['host']);
            self::assertSame('Bearer beta-access', $request['authorization']);
        }
    }

    public function test_reassignment_after_context_capture_keeps_old_target_and_old_token_paired(): void
    {
        $site = $this->createSite();
        $this->pair($site);
        $this->mcpRequests = [];
        $reassignmentTriggered = false;
        $triggerOnInitialize = true;

        $this->fakeBridge(function (Request $request) use ($site, &$reassignmentTriggered, &$triggerOnInitialize) {
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            $payload = $request->data();

            if ($triggerOnInitialize
                && $path === '/wp-json/wp-ai-bridge/v1/mcp'
                && $request->method() === 'POST'
                && ($payload['method'] ?? null) === 'initialize') {
                $triggerOnInitialize = false;
                $updated = app(SiteRegistry::class)->update(
                    $site->fresh(),
                    'Alpha',
                    'https://beta.example.test',
                );
                $this->pair($updated);
                $reassignmentTriggered = true;
            }

            return $this->bridgeResponse($request);
        });

        $result = app(WpAiBridgeMcpClient::class)->executeAbility(
            $site,
            'demo/write',
            ['value' => 'captured-before-reassignment'],
            'captured-context-regression',
        );

        self::assertTrue($reassignmentTriggered);
        self::assertSame(['site' => 'alpha'], $result);
        self::assertNotEmpty($this->mcpRequests);
        foreach ($this->mcpRequests as $request) {
            self::assertSame('alpha.example.test', $request['host']);
            self::assertSame('Bearer alpha-access', $request['authorization']);
        }

        $current = $site->fresh();
        self::assertSame(
            'https://beta.example.test/wp-json/wp-ai-bridge/v1/mcp',
            $current->mcp_resource_url,
        );
        self::assertSame(
            'https://beta.example.test/wp-json/wp-ai-bridge/v1/mcp',
            $current->credential()->firstOrFail()->resource_url,
        );
    }

    private function createSite(): Site
    {
        return app(SiteRegistry::class)->create(
            'alpha',
            'Alpha',
            'https://alpha.example.test',
        );
    }

    private function pair(Site $site): void
    {
        $connections = app(SiteConnectionService::class);
        $authorizeUrl = $connections->begin($site);
        parse_str((string) parse_url($authorizeUrl, PHP_URL_QUERY), $query);
        self::assertIsString($query['state'] ?? null);
        $connections->completeCallback(
            (string) $query['state'],
            $site->site_id.'-code',
            $site->base_url,
            null,
        );
    }

    private function fakeBridge(?callable $override = null): void
    {
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $override !== null
            ? $override($request)
            : $this->bridgeResponse($request));
    }

    private function bridgeResponse(Request $request)
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

        if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
            return Http::response(['error' => 'not_found'], 404);
        }

        $this->mcpRequests[] = [
            'host' => $host,
            'authorization' => $this->requestHeader($request, 'Authorization'),
            'method' => $request->method(),
        ];

        if ($request->method() === 'DELETE') {
            return Http::response('', 200);
        }

        $payload = $request->data();
        if (($payload['method'] ?? null) === 'initialize') {
            return Http::response([
                'jsonrpc' => '2.0',
                'id' => 1,
                'result' => [
                    'protocolVersion' => '2025-11-25',
                    'serverInfo' => ['name' => 'wp-ai-bridge', 'version' => 'test'],
                    'capabilities' => ['tools' => (object) []],
                ],
            ], 200, ['Mcp-Session-Id' => 'session-'.$siteId]);
        }

        if (($payload['method'] ?? null) === 'tools/call') {
            return Http::response([
                'jsonrpc' => '2.0',
                'id' => 2,
                'result' => [
                    'content' => [[
                        'type' => 'text',
                        'text' => json_encode(['success' => true, 'data' => ['site' => $siteId]], JSON_THROW_ON_ERROR),
                    ]],
                    'structuredContent' => [
                        'success' => true,
                        'data' => ['site' => $siteId],
                    ],
                    'isError' => false,
                ],
            ], 200);
        }

        return Http::response([
            'jsonrpc' => '2.0',
            'id' => $payload['id'] ?? null,
            'error' => ['code' => -32601, 'message' => 'Method not found'],
        ], 200);
    }

    private function requestHeader(Request $request, string $name): string
    {
        $value = $request->header($name);
        if (is_array($value)) {
            $value = $value[0] ?? '';
        }

        return is_string($value) ? $value : '';
    }
}
