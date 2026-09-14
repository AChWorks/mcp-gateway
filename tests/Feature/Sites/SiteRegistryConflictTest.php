<?php

namespace Tests\Feature\Sites;

use App\Application\Sites\SiteRegistry;
use App\Domain\Sites\SiteConnectionState;
use App\Domain\Sites\SiteCredential;
use App\Infrastructure\Http\DnsResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

final class SiteRegistryConflictTest extends TestCase
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
        Http::fake(fn (Request $request) => $this->metadataResponse($request));
    }

    public function test_conflicting_target_update_does_not_touch_existing_credential(): void
    {
        /** @var SiteRegistry $registry */
        $registry = app(SiteRegistry::class);
        $alpha = $registry->create('alpha', 'Alpha', 'https://alpha.example.test');
        $registry->create('beta', 'Beta', 'https://beta.example.test');

        $alpha->forceFill(['connection_state' => SiteConnectionState::Connected])->save();
        SiteCredential::query()->create([
            'site_record_id' => $alpha->getKey(),
            'client_id' => 'https://gateway.example.test/oauth/client.json',
            'resource_url' => $alpha->mcp_resource_url,
            'binding_hash' => str_repeat('a', 64),
            'encrypted_payload' => 'opaque-existing-credential',
            'access_expires_at' => now()->addHour(),
        ]);

        try {
            $registry->update($alpha, 'Alpha', 'https://beta.example.test');
            self::fail('A duplicate canonical target was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('already registered', $exception->getMessage());
        }

        $alpha->refresh();
        self::assertSame('https://alpha.example.test', $alpha->base_url);
        self::assertSame(SiteConnectionState::Connected, $alpha->connection_state);
        self::assertTrue($alpha->credential()->exists());
        self::assertSame('opaque-existing-credential', $alpha->credential()->firstOrFail()->encrypted_payload);
    }

    private function metadataResponse(Request $request)
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

        return Http::response(['error' => 'not_found'], 404);
    }
}
