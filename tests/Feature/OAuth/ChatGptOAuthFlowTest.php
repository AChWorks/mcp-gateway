<?php

namespace Tests\Feature\OAuth;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use App\Infrastructure\OAuth\League\ResponseTypes\RecoverableBearerTokenResponse;
use App\Models\User;
use App\Support\CorrelationId;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ChatGptOAuthFlowTest extends TestCase
{
    use RefreshDatabase;

    private const CLIENT_ID = 'https://chatgpt.com/oauth/client.json';

    private const REDIRECT_URI = 'https://chatgpt.com/connector_platform_oauth_redirect';

    private const CLIENT_KID = 'test-chatgpt-key';

    private string $clientPrivateKey;

    /** @var array<string, mixed> */
    private array $clientJwk;

    protected function setUp(): void
    {
        parent::setUp();

        Artisan::call('gateway:oauth-keygen', ['--force' => true]);
        [$this->clientPrivateKey, $this->clientJwk] = $this->newClientKeypair();
        $this->bindClientMetadataFixture();
    }

    public function test_discovery_metadata_and_unauthenticated_mcp_challenge_are_resource_bound(): void
    {
        $resource = (string) config('oauth.resource');
        $issuer = (string) config('oauth.issuer');

        $this->getJson('/.well-known/oauth-protected-resource/mcp')
            ->assertOk()
            ->assertJson([
                'resource' => $resource,
                'authorization_servers' => [$issuer],
                'scopes_supported' => ['mcp', 'offline_access'],
                'bearer_methods_supported' => ['header'],
            ]);

        $this->getJson('/.well-known/oauth-authorization-server')
            ->assertOk()
            ->assertJson([
                'issuer' => $issuer,
                'authorization_endpoint' => $issuer.'/oauth/authorize',
                'token_endpoint' => $issuer.'/oauth/token',
                'revocation_endpoint' => $issuer.'/oauth/revoke',
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'code_challenge_methods_supported' => ['S256'],
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'client_id_metadata_document_supported' => true,
                'authorization_response_iss_parameter_supported' => true,
                'protected_resources' => [$resource],
            ]);

        $this->postJson('/mcp', ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'ping'])
            ->assertUnauthorized()
            ->assertHeader(
                'WWW-Authenticate',
                'Bearer resource_metadata="'.$issuer.'/.well-known/oauth-protected-resource/mcp", scope="mcp"',
            );
    }

    public function test_authorization_requires_an_existing_operator_session(): void
    {
        $this->get('/oauth/authorize?'.http_build_query($this->authorizationParameters()))
            ->assertStatus(401)
            ->assertSee('Administrator sign-in required')
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->assertHeader(
                'Content-Security-Policy',
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            );
    }

    public function test_authorization_rejects_wrong_resource_redirect_and_non_s256_pkce(): void
    {
        $user = $this->operator();

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($this->authorizationParameters([
                'resource' => 'https://wrong.example/mcp',
            ])))
            ->assertStatus(400);

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($this->authorizationParameters([
                'redirect_uri' => 'https://attacker.example/callback',
            ])))
            ->assertUnauthorized();

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($this->authorizationParameters([
                'code_challenge_method' => 'plain',
            ])))
            ->assertStatus(400);

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($this->authorizationParameters([
                'scope' => 'offline_access',
            ])))
            ->assertStatus(400);
    }

    public function test_full_oauth_refresh_mcp_and_revocation_flow(): void
    {
        $user = $this->operator();
        $verifier = str_repeat('v', 64);
        $parameters = $this->authorizationParameters([
            'code_challenge' => $this->s256($verifier),
            'scope' => 'mcp offline_access',
        ]);

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($parameters))
            ->assertOk()
            ->assertSee('Authorize ChatGPT')
            ->assertSee(self::CLIENT_ID)
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->assertHeader(
                'Content-Security-Policy',
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com; frame-ancestors 'none'; base-uri 'none'",
            );

        $authorization = $this->actingAs($user)->post('/oauth/authorize', [
            ...$parameters,
            'decision' => 'approve',
        ]);
        $authorization->assertRedirect();
        $code = $this->authorizationCode((string) $authorization->headers->get('Location'));

        $tokenResponse = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $tokenResponse->assertOk()->assertJsonStructure([
            'token_type', 'expires_in', 'access_token', 'refresh_token',
        ]);
        $authorizationCodeCorrelationId = (string) $tokenResponse->headers->get(CorrelationId::HEADER);
        self::assertTrue(Str::isUuid($authorizationCodeCorrelationId));
        self::assertDatabaseHas('activity_events', [
            'correlation_id' => $authorizationCodeCorrelationId,
            'operation' => 'oauth-token-authorization-code',
            'outcome' => 'success',
            'error_code' => null,
        ]);

        $accessToken = (string) $tokenResponse->json('access_token');
        $refreshToken = (string) $tokenResponse->json('refresh_token');
        self::assertNotSame('', $accessToken);
        self::assertNotSame('', $refreshToken);
        self::assertStringNotContainsString($accessToken, (string) $this->databaseDump('oauth_access_tokens'));
        self::assertStringNotContainsString($refreshToken, (string) $this->databaseDump('oauth_refresh_tokens'));

        $mcpHeaders = [
            'Authorization' => 'Bearer '.$accessToken,
            'Host' => (string) parse_url((string) config('oauth.resource'), PHP_URL_HOST),
        ];

        $modernMeta = [
            'io.modelcontextprotocol/protocolVersion' => '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities' => (object) [],
            'io.modelcontextprotocol/clientInfo' => ['name' => 'oauth-flow-test', 'version' => '1.0.0'],
        ];
        $modernTools = $this->withHeaders([
            ...$mcpHeaders,
            'MCP-Protocol-Version' => '2026-07-28',
            'Mcp-Method' => 'tools/list',
        ])->postJson('/mcp', [
            'jsonrpc' => '2.0',
            'id' => 10,
            'method' => 'tools/list',
            'params' => ['_meta' => $modernMeta],
        ]);
        $modernTools->assertOk();
        self::assertFalse($modernTools->headers->has('Mcp-Session-Id'));
        self::assertSame([
            'sites-list',
            'site-context',
            'site-abilities-read',
            'site-ability-execute',
        ], array_column((array) $modernTools->json('result.tools'), 'name'));

        $modernCall = $this->withHeaders([
            ...$mcpHeaders,
            'MCP-Protocol-Version' => '2026-07-28',
            'Mcp-Method' => 'tools/call',
            'Mcp-Name' => 'sites-list',
        ])->postJson('/mcp', [
            'jsonrpc' => '2.0',
            'id' => 11,
            'method' => 'tools/call',
            'params' => [
                'name' => 'sites-list',
                'arguments' => (object) [],
                '_meta' => $modernMeta,
            ],
        ]);
        $modernCall->assertOk()
            ->assertJsonPath('result.structuredContent.ok', true)
            ->assertJsonPath('result.structuredContent.sites', [])
            ->assertJsonPath('result.structuredContent.truncated', false);
        self::assertIsString($modernCall->json('result.structuredContent.correlation_id'));

        $this->withHeaders([
            ...$mcpHeaders,
            'MCP-Protocol-Version' => '2026-07-28',
            'Mcp-Method' => 'tools/call',
        ])->postJson('/mcp', [
            'jsonrpc' => '2.0',
            'id' => 12,
            'method' => 'tools/list',
            'params' => ['_meta' => $modernMeta],
        ])->assertStatus(400);

        // Legacy 2025-era clients remain supported on the same endpoint.
        $this->withoutHeaders(['MCP-Protocol-Version', 'Mcp-Method', 'Mcp-Name']);
        $initialize = $this->withHeaders($mcpHeaders)->postJson('/mcp', [
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'initialize',
            'params' => [
                'protocolVersion' => '2025-11-25',
                'capabilities' => (object) [],
                'clientInfo' => ['name' => 'oauth-flow-test', 'version' => '1.0.0'],
            ],
        ]);
        $initialize->assertOk()->assertJsonPath('result.protocolVersion', '2025-11-25');
        $sessionId = (string) $initialize->headers->get('Mcp-Session-Id');
        self::assertNotSame('', $sessionId);

        $sessionHeaders = [
            ...$mcpHeaders,
            'Mcp-Session-Id' => $sessionId,
            'Mcp-Protocol-Version' => '2025-11-25',
        ];
        $this->withHeaders($sessionHeaders)->postJson('/mcp', [
            'jsonrpc' => '2.0',
            'method' => 'notifications/initialized',
        ])->assertStatus(202);

        $tools = $this->withHeaders($sessionHeaders)->postJson('/mcp', [
            'jsonrpc' => '2.0',
            'id' => 2,
            'method' => 'tools/list',
        ]);
        $tools->assertOk();
        $toolNames = array_column((array) $tools->json('result.tools'), 'name');
        self::assertSame([
            'sites-list',
            'site-context',
            'site-abilities-read',
            'site-ability-execute',
        ], $toolNames);

        $refreshResponse = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $refreshResponse->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
        $refreshCorrelationId = (string) $refreshResponse->headers->get(CorrelationId::HEADER);
        self::assertTrue(Str::isUuid($refreshCorrelationId));
        self::assertDatabaseHas('activity_events', [
            'correlation_id' => $refreshCorrelationId,
            'operation' => 'oauth-token-refresh',
            'outcome' => 'success',
            'error_code' => null,
        ]);

        $refreshedAccessToken = (string) $refreshResponse->json('access_token');
        $refreshedRefreshToken = (string) $refreshResponse->json('refresh_token');
        self::assertNotSame($accessToken, $refreshedAccessToken);
        self::assertNotSame($refreshToken, $refreshedRefreshToken);

        $tokenRowsAfterRotation = [
            'access' => \DB::table('oauth_access_tokens')->count(),
            'refresh' => \DB::table('oauth_refresh_tokens')->count(),
        ];

        $recoveryResponse = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $recoveryResponse->assertOk();
        self::assertSame($refreshResponse->getContent(), $recoveryResponse->getContent());
        self::assertFalse($recoveryResponse->headers->has(RecoverableBearerTokenResponse::INTERNAL_RECOVERY_HEADER));
        self::assertSame($tokenRowsAfterRotation['access'], \DB::table('oauth_access_tokens')->count());
        self::assertSame($tokenRowsAfterRotation['refresh'], \DB::table('oauth_refresh_tokens')->count());
        self::assertSame(0, (int) \DB::table('oauth_refresh_recoveries')->value('uses_remaining'));

        $recoveryCorrelationId = (string) $recoveryResponse->headers->get(CorrelationId::HEADER);
        self::assertTrue(Str::isUuid($recoveryCorrelationId));
        self::assertDatabaseHas('activity_events', [
            'correlation_id' => $recoveryCorrelationId,
            'operation' => 'oauth-token-refresh-recovery',
            'outcome' => 'success',
            'error_code' => null,
        ]);

        $replayResponse = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $replayResponse->assertStatus(400);
        $replayCorrelationId = (string) $replayResponse->headers->get(CorrelationId::HEADER);
        self::assertTrue(Str::isUuid($replayCorrelationId));
        self::assertDatabaseHas('activity_events', [
            'correlation_id' => $replayCorrelationId,
            'operation' => 'oauth-token-refresh',
            'outcome' => 'failure',
            'error_code' => 'invalid_grant',
        ]);

        $recoveryStorage = json_encode(
            \DB::table('oauth_refresh_recoveries')->get()->all(),
            JSON_THROW_ON_ERROR,
        );
        self::assertStringNotContainsString($accessToken, $recoveryStorage);
        self::assertStringNotContainsString($refreshToken, $recoveryStorage);
        self::assertStringNotContainsString($refreshedAccessToken, $recoveryStorage);
        self::assertStringNotContainsString($refreshedRefreshToken, $recoveryStorage);

        $oauthActivity = json_encode(
            \DB::table('activity_events')->where('operation', 'like', 'oauth-token-%')->get()->all(),
            JSON_THROW_ON_ERROR,
        );
        self::assertStringNotContainsString($accessToken, $oauthActivity);
        self::assertStringNotContainsString($refreshToken, $oauthActivity);
        self::assertStringNotContainsString($refreshedAccessToken, $oauthActivity);
        self::assertStringNotContainsString($refreshedRefreshToken, $oauthActivity);

        $this->post('/oauth/revoke', [
            'client_id' => self::CLIENT_ID,
            'token' => $refreshedRefreshToken,
            'token_type_hint' => 'refresh_token',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/revoke'),
        ])->assertOk();

        $this->withHeaders([
            'Authorization' => 'Bearer '.$refreshedAccessToken,
            'Host' => (string) parse_url((string) config('oauth.resource'), PHP_URL_HOST),
        ])->postJson('/mcp', [
            'jsonrpc' => '2.0',
            'id' => 3,
            'method' => 'tools/list',
        ])->assertUnauthorized();
    }

    public function test_refresh_recovery_requires_fresh_client_assertion_and_exact_bindings(): void
    {
        [$refreshToken] = $this->issueRefreshableToken();

        $rotationAssertion = $this->clientAssertion((string) config('oauth.issuer').'/oauth/token');
        $rotation = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $rotationAssertion,
        ]);
        $rotation->assertOk();

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $rotationAssertion,
        ])->assertUnauthorized();

        self::assertSame(1, (int) \DB::table('oauth_refresh_recoveries')->value('uses_remaining'));

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => 'https://attacker.example/client.json',
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ])->assertUnauthorized();

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => 'https://wrong.example/mcp',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ])->assertStatus(400);

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'scope' => 'mcp',
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ])->assertStatus(400);

        self::assertSame(1, (int) \DB::table('oauth_refresh_recoveries')->value('uses_remaining'));

        $recovered = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $recovered->assertOk();
        self::assertSame($rotation->getContent(), $recovered->getContent());
        self::assertSame(0, (int) \DB::table('oauth_refresh_recoveries')->value('uses_remaining'));
    }

    public function test_refresh_recovery_rejects_revoked_authorization_and_invalid_successors(): void
    {
        [$refreshToken] = $this->issueRefreshableToken();
        $rotation = $this->rotateRefreshToken($refreshToken);
        $successorRefreshToken = (string) $rotation->json('refresh_token');

        $this->post('/oauth/revoke', [
            'client_id' => self::CLIENT_ID,
            'token' => $successorRefreshToken,
            'token_type_hint' => 'refresh_token',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/revoke'),
        ])->assertOk();

        $this->recoverOldRefreshToken($refreshToken)->assertStatus(400);
        self::assertSame(1, (int) \DB::table('oauth_refresh_recoveries')->value('uses_remaining'));

        \DB::table('oauth_refresh_recoveries')->delete();

        [$refreshToken] = $this->issueRefreshableToken();
        $rotation = $this->rotateRefreshToken($refreshToken);
        $successorAccessId = $this->accessTokenIdentifier((string) $rotation->json('access_token'));
        \DB::table('oauth_access_tokens')->where('id', $successorAccessId)->update([
            'revoked_at' => now(),
            'updated_at' => now(),
        ]);

        $this->recoverOldRefreshToken($refreshToken)->assertStatus(400);

        \DB::table('oauth_refresh_recoveries')->delete();

        [$refreshToken] = $this->issueRefreshableToken();
        $rotation = $this->rotateRefreshToken($refreshToken);
        $successorRefreshPayload = app(\App\Infrastructure\OAuth\RefreshTokenInspector::class)
            ->inspect((string) $rotation->json('refresh_token'));
        self::assertIsArray($successorRefreshPayload);
        self::assertIsString($successorRefreshPayload['refresh_token_id'] ?? null);

        \DB::table('oauth_refresh_tokens')
            ->where('id', $successorRefreshPayload['refresh_token_id'])
            ->update(['expires_at' => now()->subSecond(), 'updated_at' => now()]);

        $this->recoverOldRefreshToken($refreshToken)->assertStatus(400);
    }

    public function test_refresh_recovery_window_expiry_restores_normal_replay_rejection(): void
    {
        [$refreshToken] = $this->issueRefreshableToken();
        $this->rotateRefreshToken($refreshToken);

        \DB::table('oauth_refresh_recoveries')->update([
            'recovery_expires_at' => now()->subSecond(),
            'updated_at' => now(),
        ]);

        $this->recoverOldRefreshToken($refreshToken)->assertStatus(400);
        self::assertSame(0, \DB::table('oauth_refresh_recoveries')->count());

        $oldPayload = app(\App\Infrastructure\OAuth\RefreshTokenInspector::class)->inspect($refreshToken);
        self::assertIsArray($oldPayload);
        self::assertIsString($oldPayload['refresh_token_id'] ?? null);
        self::assertNotNull(
            \DB::table('oauth_refresh_tokens')
                ->where('id', $oldPayload['refresh_token_id'])
                ->value('revoked_at'),
        );
    }

    public function test_mcp_only_authorization_does_not_issue_a_refresh_token(): void
    {
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user);

        $response = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);

        $response->assertOk()->assertJsonMissingPath('refresh_token');
        self::assertSame(['mcp'], json_decode((string) \DB::table('oauth_access_tokens')->value('scopes'), true, flags: JSON_THROW_ON_ERROR));
        self::assertSame(0, \DB::table('oauth_refresh_tokens')->count());
    }

    public function test_denied_authorization_response_is_issuer_stamped(): void
    {
        $user = $this->operator();
        $response = $this->actingAs($user)->post('/oauth/authorize', [
            ...$this->authorizationParameters(),
            'decision' => 'deny',
        ]);

        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        self::assertSame('access_denied', $query['error'] ?? null);
        self::assertSame((string) config('oauth.issuer'), $query['iss'] ?? null);
    }

    public function test_client_assertion_audience_and_replay_are_rejected(): void
    {
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user);

        $wrongAudience = $this->clientAssertion('https://wrong.example/oauth/token');
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $wrongAudience,
        ])->assertUnauthorized();

        $assertion = $this->clientAssertion((string) config('oauth.issuer').'/oauth/token');
        $valid = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $assertion,
        ]);
        $valid->assertOk();

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $assertion,
        ])->assertUnauthorized();
    }

    public function test_client_assertion_rejects_wrong_client_key_algorithm_key_id_and_expiry(): void
    {
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user);
        $tokenRequest = [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        ];
        $audience = (string) config('oauth.issuer').'/oauth/token';

        $this->post('/oauth/token', [
            ...$tokenRequest,
            'client_id' => 'https://attacker.example/client.json',
            'client_assertion' => $this->clientAssertion($audience),
        ])->assertUnauthorized();

        [$foreignPrivateKey] = $this->newClientKeypair();
        $this->post('/oauth/token', [
            ...$tokenRequest,
            'client_assertion' => $this->clientAssertion($audience, privateKey: $foreignPrivateKey),
        ])->assertUnauthorized();

        $this->post('/oauth/token', [
            ...$tokenRequest,
            'client_assertion' => $this->clientAssertion(
                $audience,
                privateKey: 'test-hmac-secret-that-is-at-least-32-bytes-long',
                algorithm: 'HS256',
            ),
        ])->assertUnauthorized();

        $this->post('/oauth/token', [
            ...$tokenRequest,
            'client_assertion' => $this->clientAssertion($audience, keyId: 'unknown-key-id'),
        ])->assertUnauthorized();

        $now = time();
        $this->post('/oauth/token', [
            ...$tokenRequest,
            'client_assertion' => $this->clientAssertion($audience, [
                'iat' => $now - 180,
                'exp' => $now - 60,
            ]),
        ])->assertUnauthorized();

        $this->post('/oauth/token', [
            ...$tokenRequest,
            'client_assertion' => $this->clientAssertion($audience, [
                'iat' => $now - 200,
                'exp' => $now + 200,
            ]),
        ])->assertUnauthorized();

        $this->post('/oauth/token', [
            ...$tokenRequest,
            'client_assertion' => $this->clientAssertion($audience),
        ])->assertOk();
    }

    public function test_refresh_scope_can_narrow_and_drops_offline_refresh_authority(): void
    {
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user, 'mcp offline_access');
        $token = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $token->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
        $refreshToken = (string) $token->json('refresh_token');

        $narrowed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'scope' => 'mcp',
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $narrowed->assertOk()->assertJsonMissingPath('refresh_token');

        $accessTokenId = $this->accessTokenIdentifier((string) $narrowed->json('access_token'));
        self::assertSame(
            ['mcp'],
            json_decode((string) \DB::table('oauth_access_tokens')->where('id', $accessTokenId)->value('scopes'), true, flags: JSON_THROW_ON_ERROR),
        );
        self::assertSame(1, \DB::table('oauth_refresh_tokens')->count());
        self::assertNotNull(\DB::table('oauth_refresh_tokens')->value('revoked_at'));
    }

    public function test_expired_authorization_code_is_rejected(): void
    {
        config()->set('oauth.ttl.authorization_code_seconds', 1);
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user);
        sleep(2);

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ])->assertStatus(400);
    }

    public function test_code_exchange_rejects_wrong_resource_pkce_scope_and_code_reuse(): void
    {
        $user = $this->operator();

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($this->authorizationParameters(['scope' => 'admin'])))
            ->assertStatus(400);

        [$code, $verifier] = $this->approvedAuthorizationCode($user);
        $assertion = $this->clientAssertion((string) config('oauth.issuer').'/oauth/token');
        $base = [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $assertion,
        ];

        $this->post('/oauth/token', [
            ...$base,
            'resource' => 'https://wrong.example/mcp',
        ])->assertStatus(400);

        $this->post('/oauth/token', [
            ...$base,
            'code_verifier' => str_repeat('x', 64),
        ])->assertStatus(400);

        $valid = $this->post('/oauth/token', [
            ...$base,
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $valid->assertOk();

        $this->post('/oauth/token', [
            ...$base,
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ])->assertStatus(400);
    }

    /** @return array{0:string,1:string} */
    private function issueRefreshableToken(): array
    {
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user, 'mcp offline_access');
        $response = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $response->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);

        return [(string) $response->json('refresh_token'), (string) $response->json('access_token')];
    }

    private function rotateRefreshToken(string $refreshToken): \Illuminate\Testing\TestResponse
    {
        $response = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
        $response->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);

        return $response;
    }

    private function recoverOldRefreshToken(string $refreshToken): \Illuminate\Testing\TestResponse
    {
        return $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) config('oauth.issuer').'/oauth/token'),
        ]);
    }

    /** @return array<string, string> */
    private function authorizationParameters(array $overrides = []): array
    {
        $verifier = str_repeat('v', 64);

        return array_replace([
            'response_type' => 'code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'mcp',
            'state' => 'state-'.Str::uuid(),
            'code_challenge' => $this->s256($verifier),
            'code_challenge_method' => 'S256',
            'resource' => (string) config('oauth.resource'),
        ], $overrides);
    }

    /** @return array{0: string, 1: string} */
    private function approvedAuthorizationCode(User $user, string $scope = 'mcp'): array
    {
        $verifier = str_repeat('v', 64);
        $parameters = $this->authorizationParameters([
            'code_challenge' => $this->s256($verifier),
            'scope' => $scope,
        ]);
        $response = $this->actingAs($user)->post('/oauth/authorize', [
            ...$parameters,
            'decision' => 'approve',
        ]);
        $response->assertRedirect();

        return [$this->authorizationCode((string) $response->headers->get('Location')), $verifier];
    }

    private function authorizationCode(string $redirect): string
    {
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        self::assertIsString($query['code'] ?? null);
        self::assertSame((string) config('oauth.issuer'), $query['iss'] ?? null);

        return $query['code'];
    }

    /** @param array<string, mixed> $claimOverrides */
    private function clientAssertion(
        string $audience,
        array $claimOverrides = [],
        ?string $privateKey = null,
        string $algorithm = 'RS256',
        ?string $keyId = self::CLIENT_KID,
    ): string {
        $now = time();
        $claims = array_replace([
            'iss' => self::CLIENT_ID,
            'sub' => self::CLIENT_ID,
            'aud' => $audience,
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => (string) Str::uuid(),
        ], $claimOverrides);

        return JWT::encode($claims, $privateKey ?? $this->clientPrivateKey, $algorithm, $keyId);
    }

    private function accessTokenIdentifier(string $token): string
    {
        $parts = explode('.', $token);
        self::assertCount(3, $parts);
        $payload = json_decode(JWT::urlsafeB64Decode($parts[1]), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertIsString($payload['jti'] ?? null);

        return $payload['jti'];
    }

    private function s256(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'Gateway Operator',
            'email' => 'operator@example.test',
            'password' => Hash::make('test-password-not-used-for-oauth'),
        ]);
    }

    private function bindClientMetadataFixture(): void
    {
        $metadata = [
            'client_id' => self::CLIENT_ID,
            'client_uri' => 'https://chatgpt.com/',
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'client_name' => 'ChatGPT',
            'token_endpoint_auth_signing_alg' => 'RS256',
            'jwks_uri' => 'https://chatgpt.com/oauth/jwks.json',
        ];
        $jwks = ['keys' => [$this->clientJwk]];
        $metadataJson = json_encode($metadata, JSON_THROW_ON_ERROR);
        $jwksJson = json_encode($jwks, JSON_THROW_ON_ERROR);
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $metadataJson),
            new Response(200, ['Content-Type' => 'application/json'], $jwksJson),
            new Response(200, ['Content-Type' => 'application/json'], $metadataJson),
            new Response(200, ['Content-Type' => 'application/json'], $jwksJson),
        ]);
        $client = new Client(['handler' => HandlerStack::create($mock)]);

        $this->app->instance(ChatGptClientMetadata::class, new ChatGptClientMetadata($client));
    }

    /** @return array{0: string, 1: array<string, mixed>} */
    private function newClientKeypair(): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
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
            'kid' => self::CLIENT_KID,
            'n' => JWT::urlsafeB64Encode($details['rsa']['n']),
            'e' => JWT::urlsafeB64Encode($details['rsa']['e']),
        ]];
    }

    private function databaseDump(string $table): string
    {
        return json_encode(\DB::table($table)->get()->all(), JSON_THROW_ON_ERROR);
    }
}
