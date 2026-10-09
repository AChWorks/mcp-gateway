<?php

namespace Tests\Feature\OAuth;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Infrastructure\OAuth\ChatGptClientMetadata;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Models\User;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use RuntimeException;
use Tests\TestCase;

final class ClientProfileIsolationTest extends TestCase
{
    use RefreshDatabase;

    private const CHATGPT = 'https://chatgpt.com/oauth/client.json';

    private const FIXTURE = 'https://agent.example.test/oauth/client.json';

    private const FIXTURE_REDIRECT = 'https://agent.example.test/callback';

    private string $fixturePrivateKey;

    private string $chatPrivateKey;

    protected function setUp(): void
    {
        parent::setUp();

        Artisan::call('gateway:oauth-keygen', ['--force' => true]);
        [$this->fixturePrivateKey, $fixtureJwk] = $this->clientKeypair('fixture-key');
        [$this->chatPrivateKey, $chatJwk] = $this->clientKeypair('chat-key');

        config()->set('oauth.client_profiles', [
            ...config('oauth.client_profiles'),
            'fixture' => [
                'client_id' => self::FIXTURE,
                'display_name' => 'Verified fixture',
                'strategy' => 'pinned_private_key_jwt',
                'enabled' => true,
                'redirect_uris' => [self::FIXTURE_REDIRECT],
                'jwks' => ['keys' => [$fixtureJwk]],
            ],
        ]);

        $metadata = [
            'client_id' => self::CHATGPT,
            'client_uri' => 'https://chatgpt.com/',
            'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'client_name' => 'ChatGPT',
            'token_endpoint_auth_signing_alg' => 'RS256',
            'jwks_uri' => 'https://chatgpt.com/oauth/jwks.json',
        ];
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($metadata, JSON_THROW_ON_ERROR)),
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['keys' => [$chatJwk]], JSON_THROW_ON_ERROR)),
        ]);
        $this->app->instance(ChatGptClientMetadata::class, new ChatGptClientMetadata(
            new Client(['handler' => HandlerStack::create($mock)]),
        ));

        app(ClientProfileRegistry::class)->register('fixture');
    }

    public function test_approved_clients_get_separate_grants_tokens_and_consent_identity(): void
    {
        $user = $this->operator();
        $fixtureCode = $this->authorize($user, self::FIXTURE, self::FIXTURE_REDIRECT);
        $chatCode = $this->authorize($user, self::CHATGPT, 'https://chatgpt.com/connector_platform_oauth_redirect');

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($this->parameters(self::FIXTURE, self::FIXTURE_REDIRECT)))
            ->assertOk()->assertSee('Verified fixture')->assertSee('fixture')->assertSee(self::FIXTURE);

        $fixtureTokens = $this->exchange($fixtureCode, self::FIXTURE, self::FIXTURE_REDIRECT, $this->fixturePrivateKey, 'fixture-key');
        $chatTokens = $this->exchange($chatCode, self::CHATGPT, 'https://chatgpt.com/connector_platform_oauth_redirect', $this->chatPrivateKey, 'chat-key');

        self::assertNotSame($chatTokens['access_token'], $fixtureTokens['access_token']);
        self::assertNotSame($chatTokens['refresh_token'], $fixtureTokens['refresh_token']);
        self::assertSame('fixture', \DB::table('oauth_authorizations')->where('client_id', self::FIXTURE)->value('client_profile_key'));
        self::assertSame('chatgpt', \DB::table('oauth_authorizations')->where('client_id', self::CHATGPT)->value('client_profile_key'));

        $mcp = ['jsonrpc' => '2.0', 'method' => 'tools/list', 'id' => 1, 'params' => [
            '_meta' => [
                'io.modelcontextprotocol/protocolVersion' => '2026-07-28',
                'io.modelcontextprotocol/clientCapabilities' => (object) [],
                'io.modelcontextprotocol/clientInfo' => ['name' => 'profile-fixture-test', 'version' => '1.0'],
            ],
        ]];
        $headers = [
            'Host' => (string) parse_url((string) config('oauth.resource'), PHP_URL_HOST),
            'MCP-Protocol-Version' => '2026-07-28',
            'Mcp-Method' => 'tools/list',
        ];
        $this->withHeaders([...$headers, 'Authorization' => 'Bearer '.$fixtureTokens['access_token']])
            ->postJson('/mcp', $mcp)->assertOk();
        $this->withHeaders([...$headers, 'Authorization' => 'Bearer '.$chatTokens['access_token']])
            ->postJson('/mcp', $mcp)->assertOk();

        // A refresh issued to one client cannot be used by a different authenticated client.
        $this->refresh($fixtureTokens['refresh_token'], self::CHATGPT, $this->chatPrivateKey, 'chat-key')
            ->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

        $this->refresh($fixtureTokens['refresh_token'], self::FIXTURE, $this->fixturePrivateKey, 'fixture-key')
            ->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
    }

    public function test_cross_client_code_and_assertion_confusion_is_rejected(): void
    {
        $user = $this->operator();
        $fixtureCode = $this->authorize($user, self::FIXTURE, self::FIXTURE_REDIRECT);

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CHATGPT,
            'code' => $fixtureCode,
            'redirect_uri' => 'https://chatgpt.com/connector_platform_oauth_redirect',
            'code_verifier' => str_repeat('v', 64),
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->assertion(self::CHATGPT, $this->chatPrivateKey, 'chat-key'),
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::FIXTURE,
            'code' => $fixtureCode,
            'redirect_uri' => self::FIXTURE_REDIRECT,
            'code_verifier' => str_repeat('v', 64),
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->assertion(self::FIXTURE, $this->chatPrivateKey, 'chat-key'),
        ])->assertUnauthorized()->assertJsonPath('error', 'invalid_client');

        $this->exchange($fixtureCode, self::FIXTURE, self::FIXTURE_REDIRECT, $this->fixturePrivateKey, 'fixture-key');
    }

    public function test_profile_disable_invalidates_previous_access_and_refresh_and_cannot_be_reenabled_implicitly(): void
    {
        $user = $this->operator();
        $fixtureCode = $this->authorize($user, self::FIXTURE, self::FIXTURE_REDIRECT);
        $tokens = $this->exchange($fixtureCode, self::FIXTURE, self::FIXTURE_REDIRECT, $this->fixturePrivateKey, 'fixture-key');

        app(ClientProfileRegistry::class)->disable('fixture');
        $this->withToken($tokens['access_token'])
            ->postJson('/mcp', ['jsonrpc' => '2.0', 'method' => 'ping', 'id' => 3])->assertUnauthorized();

        $this->refresh($tokens['refresh_token'], self::FIXTURE, $this->fixturePrivateKey, 'fixture-key')
            ->assertUnauthorized()->assertJsonPath('error', 'invalid_client');

        try {
            app(ClientProfileRegistry::class)->register('fixture');
            self::fail('Revoked profile was silently reactivated.');
        } catch (RuntimeException $expected) {
            self::assertStringContainsString('revoked', $expected->getMessage());
        }

        self::assertSame(2, (int) \DB::table('oauth_client_profiles')->where('profile_key', 'fixture')->value('generation'));
        self::assertSame(1, (int) \DB::table('oauth_authorizations')->where('client_id', self::FIXTURE)->value('client_profile_generation'));

        app(ClientProfileRegistry::class)->enable('fixture');
        self::assertSame(2, app(ClientProfileRegistry::class)->active(self::FIXTURE)['generation']);
        $this->withToken($tokens['access_token'])
            ->postJson('/mcp', ['jsonrpc' => '2.0', 'method' => 'tools/list', 'id' => 4])
            ->assertUnauthorized();
        $this->refresh($tokens['refresh_token'], self::FIXTURE, $this->fixturePrivateKey, 'fixture-key')
            ->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

        $newCode = $this->authorize($user, self::FIXTURE, self::FIXTURE_REDIRECT);
        $newTokens = $this->exchange($newCode, self::FIXTURE, self::FIXTURE_REDIRECT, $this->fixturePrivateKey, 'fixture-key');
        self::assertNotSame($tokens['access_token'], $newTokens['access_token']);
        self::assertSame(2, (int) \DB::table('oauth_authorizations')
            ->where('client_id', self::FIXTURE)->whereNull('revoked_at')->value('client_profile_generation'));
    }

    public function test_cli_requires_explicit_confirmation_before_revocation(): void
    {
        self::assertSame(1, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'disable', 'key' => 'fixture',
        ]));
        self::assertNotNull(app(ClientProfileRegistry::class)->active(self::FIXTURE));
        self::assertSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'disable', 'key' => 'fixture', '--confirm' => true,
        ]));
        self::assertNull(app(ClientProfileRegistry::class)->active(self::FIXTURE));
        self::assertSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'enable', 'key' => 'fixture', '--confirm' => true,
        ]));
        self::assertSame(2, app(ClientProfileRegistry::class)->active(self::FIXTURE)['generation']);
    }

    public function test_owner_can_inspect_and_revoke_only_selected_client_authorization(): void
    {
        $operator = $this->operator();
        $fixtureTokens = $this->exchange(
            $this->authorize($operator, self::FIXTURE, self::FIXTURE_REDIRECT),
            self::FIXTURE, self::FIXTURE_REDIRECT, $this->fixturePrivateKey, 'fixture-key',
        );
        $chatTokens = $this->exchange(
            $this->authorize($operator, self::CHATGPT, 'https://chatgpt.com/connector_platform_oauth_redirect'),
            self::CHATGPT, 'https://chatgpt.com/connector_platform_oauth_redirect', $this->chatPrivateKey, 'chat-key',
        );

        $owner = User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner@example.test',
            'password' => Hash::make('OwnerSecure!234'),
            'role' => GatewayRole::Owner->value,
            'site_scope_mode' => SiteScopeMode::All->value,
            'access_enabled' => true,
        ]);

        $this->actingAs($operator)->get('/admin/oauth-clients')->assertForbidden();
        $this->actingAs($owner)->get('/admin/oauth-clients')
            ->assertOk()->assertSee('Approved AI client applications')
            ->assertSee('fixture')->assertSee('chatgpt');

        $grant = \DB::table('oauth_authorizations')->where('client_id', self::FIXTURE)->first();
        self::assertNotNull($grant);

        $this->actingAs($owner)->delete('/admin/oauth-clients/authorizations/'.$grant->id, [
            'current_password' => 'wrong',
        ])->assertSessionHasErrors('current_password');
        self::assertNull(\DB::table('oauth_authorizations')->where('id', $grant->id)->value('revoked_at'));

        $this->actingAs($owner)->delete('/admin/oauth-clients/authorizations/'.$grant->id, [
            'current_password' => 'OwnerSecure!234',
        ])->assertRedirect('/admin/oauth-clients');

        self::assertNotNull(\DB::table('oauth_authorizations')->where('id', $grant->id)->value('revoked_at'));
        self::assertNull(\DB::table('oauth_authorizations')->where('client_id', self::CHATGPT)->value('revoked_at'));
        self::assertSame('fixture', \DB::table('activity_events')
            ->where('operation', 'oauth-client-authorization-revoked')->value('client_profile_key'));

        $this->withToken($fixtureTokens['access_token'])
            ->postJson('/mcp', ['jsonrpc' => '2.0', 'method' => 'tools/list', 'id' => 5])
            ->assertUnauthorized();

        // The other client's authorization, refresh and access tokens remain valid.
        $this->refresh($chatTokens['refresh_token'], self::CHATGPT, $this->chatPrivateKey, 'chat-key')
            ->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
    }

    public function test_preflight_fails_for_identity_mutation_or_unrevoked_profile_removal(): void
    {
        $registry = app(ClientProfileRegistry::class);
        $registry->assertReady();
        self::assertSame(0, Artisan::call('gateway:oauth-client-profile', ['operation' => 'check']));

        $configured = config('oauth.client_profiles');
        config()->set('oauth.client_profiles', [
            'chatgpt' => $configured['chatgpt'],
        ]);
        try {
            $registry->assertReady();
            self::fail('Active registered profile was silently removed from configuration.');
        } catch (RuntimeException $expected) {
            self::assertStringContainsString('Revoke', $expected->getMessage());
        }

        config()->set('oauth.client_profiles', $configured);
        config()->set('oauth.client_profiles.fixture.client_id', 'https://other.example.test/oauth/client.json');
        try {
            $registry->assertReady();
            self::fail('Existing profile key was rebound to a new protocol client.');
        } catch (RuntimeException $expected) {
            self::assertStringContainsString('identity', $expected->getMessage());
        }

        config()->set('oauth.client_profiles', $configured);
        $registry->disable('fixture');
        config()->set('oauth.client_profiles', [
            'chatgpt' => $configured['chatgpt'],
        ]);
        $registry->assertReady();
        self::assertSame(0, Artisan::call('gateway:oauth-client-profile', ['operation' => 'check']));
    }

    public function test_unknown_duplicate_and_unsafe_remote_profile_origins_fail_closed(): void
    {
        self::assertNull(app(ClientProfileRegistry::class)->active('https://unknown.example.test/oauth/client.json'));

        $profiles = config('oauth.client_profiles');
        config()->set('oauth.client_profiles', [...$profiles, 'other' => [
            ...$profiles['fixture'], 'display_name' => 'Impersonator',
        ]]);
        try {
            app(ClientProfileRegistry::class)->configured();
            self::fail('Duplicate client IDs were accepted.');
        } catch (RuntimeException $expected) {
            self::assertStringContainsString('Duplicate', $expected->getMessage());
        }

        config()->set('oauth.client_profiles', [...$profiles, 'unsafe' => [
            'client_id' => 'http://127.0.0.1/private',
            'display_name' => 'Unsafe',
            'strategy' => 'cimd_private_key_jwt',
            'enabled' => true,
        ]]);
        $this->expectException(RuntimeException::class);
        app(ClientProfileRegistry::class)->configured();
    }

    private function authorize(User $user, string $clientId, string $redirect): string
    {
        $response = $this->actingAs($user)->post('/oauth/authorize', [
            ...$this->parameters($clientId, $redirect),
            'decision' => 'approve',
        ])->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        self::assertIsString($query['code'] ?? null);
        self::assertSame((string) config('oauth.issuer'), $query['iss'] ?? null);

        return $query['code'];
    }

    /** @return array<string, string> */
    private function exchange(string $code, string $clientId, string $redirect, string $key, string $kid): array
    {
        $response = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'redirect_uri' => $redirect,
            'code' => $code,
            'code_verifier' => str_repeat('v', 64),
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->assertion($clientId, $key, $kid),
        ])->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);

        return $response->json();
    }

    /** @return TestResponse<\Illuminate\Http\Response> */
    private function refresh(string $token, string $clientId, string $key, string $kid): TestResponse
    {
        return $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'refresh_token' => $token,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->assertion($clientId, $key, $kid),
        ]);
    }

    /** @return array<string,string> */
    private function parameters(string $clientId, string $redirect): array
    {
        $verifier = str_repeat('v', 64);

        return [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirect,
            'scope' => 'mcp',
            'state' => 'state-'.Str::uuid(),
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
            'resource' => (string) config('oauth.resource'),
        ];
    }

    private function assertion(string $clientId, string $key, string $kid): string
    {
        $now = time();

        return JWT::encode([
            'iss' => $clientId,
            'sub' => $clientId,
            'aud' => (string) config('oauth.issuer').'/oauth/token',
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => (string) Str::uuid(),
        ], $key, 'RS256', $kid);
    }

    /** @return array{string,array<string,mixed>} */
    private function clientKeypair(string $kid): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $privateKey = '';
        self::assertTrue(openssl_pkey_export($key, $privateKey));
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsArray($details['rsa'] ?? null);

        return [$privateKey, [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $kid,
            'n' => JWT::urlsafeB64Encode($details['rsa']['n']),
            'e' => JWT::urlsafeB64Encode($details['rsa']['e']),
        ]];
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'OAuth operator',
            'email' => 'operator@example.test',
            'password' => 'irrelevant',
            'role' => GatewayRole::Operator->value,
            'site_scope_mode' => SiteScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
    }
}
