<?php

namespace Tests\Feature\Sites;

use App\Application\Sites\SiteConnectionException;
use App\Application\Sites\SiteConnectionService;
use App\Application\Sites\SiteRegistry;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\OAuth\SiteCredentialVault;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Tests\TestCase;

final class SiteRegistryAndPairingTest extends TestCase
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

    public function test_site_registry_discovers_and_persists_only_canonical_bridge_targets(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        $site = $registry->create('alpha', 'Alpha WordPress', 'https://alpha.example.test/');

        self::assertSame('alpha', $site->site_id);
        self::assertSame('https://alpha.example.test', $site->base_url);
        self::assertSame('https://alpha.example.test/wp-json/wp-ai-bridge/v1/mcp', $site->mcp_resource_url);
        self::assertSame('https://alpha.example.test/wp-ai-bridge/oauth/authorize', $site->oauth_authorization_url);
        self::assertSame(SiteConnectionState::Disconnected, $site->connection_state);
        self::assertSame(hash('sha256', $site->base_url), $site->base_url_hash);
    }

    public function test_two_sites_have_cryptographically_bound_isolated_credentials_refresh_and_disconnect(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        /** @var SiteConnectionService $connections */
        $connections = app(SiteConnectionService::class);
        /** @var SiteCredentialVault $vault */
        $vault = app(SiteCredentialVault::class);

        $alpha = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');
        $beta = $registry->create('beta', 'Beta', 'https://beta.example.test');

        $this->pair($connections, $alpha);
        $this->pair($connections, $beta);

        $alphaCredential = $alpha->credential()->firstOrFail();
        $betaCredential = $beta->credential()->firstOrFail();
        $alphaSecret = $vault->open($alphaCredential);
        $betaSecret = $vault->open($betaCredential);

        self::assertSame('alpha-access', $alphaSecret->accessToken);
        self::assertSame('alpha-refresh', $alphaSecret->refreshToken);
        self::assertSame('beta-access', $betaSecret->accessToken);
        self::assertSame('beta-refresh', $betaSecret->refreshToken);

        $rawAlpha = DB::table('site_credentials')->where('site_record_id', $alpha->getKey())->first();
        self::assertNotNull($rawAlpha);
        self::assertStringNotContainsString('alpha-access', (string) $rawAlpha->encrypted_payload);
        self::assertStringNotContainsString('alpha-refresh', (string) $rawAlpha->encrypted_payload);

        DB::table('site_credentials')
            ->where('site_record_id', $alpha->getKey())
            ->update(['encrypted_payload' => $betaCredential->encrypted_payload]);
        $alphaCredential = $alpha->credential()->firstOrFail();
        try {
            $vault->open($alphaCredential);
            self::fail('Cross-site credential payload swap was accepted.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('binding', $exception->getMessage());
        }

        DB::table('site_credentials')
            ->where('site_record_id', $alpha->getKey())
            ->update(['encrypted_payload' => $rawAlpha->encrypted_payload]);
        $alpha->unsetRelation('credential');

        $this->travel(2)->seconds();
        self::assertSame('alpha-refreshed-access', $connections->accessToken($alpha));
        self::assertSame('beta-access', $vault->open($beta->credential()->firstOrFail())->accessToken);

        $connections->disconnect($alpha);
        self::assertFalse($alpha->credential()->exists());
        self::assertTrue($beta->credential()->exists());
        self::assertSame(SiteConnectionState::Disconnected, $alpha->refresh()->connection_state);
        self::assertSame(SiteConnectionState::Connected, $beta->refresh()->connection_state);
    }

    public function test_oauth_callback_state_is_one_time_and_wrong_issuer_fails_closed(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        /** @var SiteConnectionService $connections */
        $connections = app(SiteConnectionService::class);
        $site = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');

        $authorizeUrl = $connections->begin($site);
        $state = $this->queryValue($authorizeUrl, 'state');

        try {
            $connections->completeCallback($state, 'alpha-code', 'https://attacker.example.test', null);
            self::fail('Mismatched issuer was accepted.');
        } catch (SiteConnectionException $exception) {
            self::assertSame('issuer_mismatch', $exception->reason);
        }
        self::assertSame(SiteConnectionState::ReconnectRequired, $site->refresh()->connection_state);

        try {
            $connections->completeCallback($state, 'alpha-code', 'https://alpha.example.test', null);
            self::fail('Consumed callback state was replayed.');
        } catch (SiteConnectionException $exception) {
            self::assertSame('invalid_state', $exception->reason);
        }
    }

    public function test_private_dns_answer_is_rejected_before_any_outbound_request(): void
    {
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                return ['169.254.169.254'];
            }
        });

        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);

        $this->expectException(SiteConnectionException::class);
        $this->expectExceptionMessage('safe public HTTPS');
        $registry->create('metadata', 'Metadata', 'https://metadata.example.test');
    }

    public function test_site_removal_revokes_before_deleting_local_record(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        /** @var SiteConnectionService $connections */
        $connections = app(SiteConnectionService::class);
        $site = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');
        $this->pair($connections, $site);
        $id = $site->getKey();

        $registry->remove($site);

        self::assertNull(Site::query()->find($id));
        self::assertSame(0, DB::table('site_credentials')->where('site_record_id', $id)->count());
    }

    public function test_discovery_distinguishes_missing_bridge_from_incompatible_metadata(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);

        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => Http::response(['error' => 'not_found'], 404));
        try {
            $registry->create('missing', 'Missing', 'https://missing.example.test');
            self::fail('Missing Bridge metadata was accepted.');
        } catch (SiteConnectionException $exception) {
            self::assertSame('missing_bridge', $exception->reason);
        }

        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(function (Request $request) {
            if ((string) parse_url($request->url(), PHP_URL_PATH) === '/.well-known/oauth-protected-resource') {
                return Http::response([
                    'resource' => 'https://incompatible.example.test/wp-json/wp-ai-bridge/v1/mcp',
                    'authorization_servers' => ['https://incompatible.example.test'],
                    'scopes_supported' => ['mcp:use'],
                    'bearer_methods_supported' => ['header'],
                ], 200);
            }

            return Http::response(['error' => 'not_found'], 404);
        });

        try {
            $registry->create('incompatible', 'Incompatible', 'https://incompatible.example.test');
            self::fail('Incompatible Bridge metadata was accepted.');
        } catch (SiteConnectionException $exception) {
            self::assertSame('incompatible_metadata', $exception->reason);
        }
    }

    public function test_same_target_display_name_update_preserves_connected_state_and_credential(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        /** @var SiteConnectionService $connections */
        $connections = app(SiteConnectionService::class);
        $site = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');
        $this->pair($connections, $site);

        $updated = $registry->update($site, 'Alpha Renamed', 'https://alpha.example.test/');

        self::assertSame('Alpha Renamed', $updated->display_name);
        self::assertSame(SiteConnectionState::Connected, $updated->connection_state);
        self::assertTrue($updated->credential()->exists());
    }

    public function test_refresh_remote_failure_preserves_existing_credential_for_later_retry(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        /** @var SiteConnectionService $connections */
        $connections = app(SiteConnectionService::class);
        $site = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');
        $this->pair($connections, $site);
        $before = $site->credential()->firstOrFail()->encrypted_payload;

        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(function (Request $request) {
            if ((string) parse_url($request->url(), PHP_URL_PATH) === '/wp-json/wp-ai-bridge/v1/oauth/token'
                && (string) ($request->data()['grant_type'] ?? '') === 'refresh_token') {
                return Http::response(['error' => 'temporarily_unavailable'], 503);
            }

            return $this->bridgeResponse($request);
        });

        $this->travel(2)->seconds();
        try {
            $connections->accessToken($site);
            self::fail('Temporary refresh failure was treated as success.');
        } catch (SiteConnectionException $exception) {
            self::assertSame('remote_failure', $exception->reason);
        }

        $site->refresh();
        self::assertSame(SiteConnectionState::Error, $site->connection_state);
        self::assertTrue($site->credential()->exists());
        self::assertSame($before, $site->credential()->firstOrFail()->encrypted_payload);
    }

    public function test_malformed_refresh_success_preserves_existing_credential_for_recovery(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        /** @var SiteConnectionService $connections */
        $connections = app(SiteConnectionService::class);
        $site = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');
        $this->pair($connections, $site);
        $before = $site->credential()->firstOrFail()->encrypted_payload;

        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(function (Request $request) {
            if ((string) parse_url($request->url(), PHP_URL_PATH) === '/wp-json/wp-ai-bridge/v1/oauth/token'
                && (string) ($request->data()['grant_type'] ?? '') === 'refresh_token') {
                return Http::response([
                    'access_token' => 'unexpected-access',
                    'token_type' => 'Bearer',
                    'expires_in' => 3600,
                    'scope' => 'mcp:use offline_access',
                ], 200);
            }

            return $this->bridgeResponse($request);
        });

        $this->travel(2)->seconds();
        try {
            $connections->accessToken($site);
            self::fail('Malformed refresh response was treated as success.');
        } catch (SiteConnectionException $exception) {
            self::assertSame('invalid_token_response', $exception->reason);
        }

        $site->refresh();
        self::assertSame(SiteConnectionState::Error, $site->connection_state);
        self::assertTrue($site->credential()->exists());
        self::assertSame($before, $site->credential()->firstOrFail()->encrypted_payload);
    }

    public function test_flow_expiry_database_extension_does_not_extend_encrypted_flow_lifetime(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        /** @var SiteConnectionService $connections */
        $connections = app(SiteConnectionService::class);
        $site = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');

        $authorizeUrl = $connections->begin($site);
        $state = $this->queryValue($authorizeUrl, 'state');
        DB::table('site_oauth_flows')->where('site_record_id', $site->getKey())->update([
            'expires_at' => now()->addHour(),
        ]);

        try {
            $connections->completeCallback($state, 'alpha-code', 'https://alpha.example.test', null);
            self::fail('Database-only flow expiry extension was accepted.');
        } catch (SiteConnectionException $exception) {
            self::assertSame('invalid_state', $exception->reason);
        }
        self::assertSame(SiteConnectionState::ReconnectRequired, $site->refresh()->connection_state);
    }

    private function pair(SiteConnectionService $connections, Site $site): void
    {
        $authorizeUrl = $connections->begin($site);
        $state = $this->queryValue($authorizeUrl, 'state');
        $connections->completeCallback($state, $site->site_id.'-code', $site->base_url, null);
        self::assertSame(SiteConnectionState::Connected, $site->refresh()->connection_state);
    }

    private function queryValue(string $url, string $key): string
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertIsString($query[$key] ?? null);

        return $query[$key];
    }

    private function bridgeResponse(Request $request)
    {
        $url = $request->url();
        $host = (string) parse_url($url, PHP_URL_HOST);
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
            $data = $request->data();
            $grant = (string) ($data['grant_type'] ?? '');
            $prefix = str_starts_with($host, 'alpha.') ? 'alpha' : 'beta';

            if ($grant === 'refresh_token') {
                return Http::response([
                    'token_type' => 'Bearer',
                    'expires_in' => 3600,
                    'access_token' => $prefix.'-refreshed-access',
                    'refresh_token' => $prefix.'-refreshed-refresh',
                    'scope' => 'mcp:use offline_access',
                ], 200);
            }

            return Http::response([
                'token_type' => 'Bearer',
                'expires_in' => 1,
                'access_token' => $prefix.'-access',
                'refresh_token' => $prefix.'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }

        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/revoke') {
            return Http::response('', 200);
        }

        return Http::response(['error' => 'not_found'], 404);
    }
}
