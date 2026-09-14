<?php

namespace Tests\Feature\Sites;

use App\Infrastructure\OAuth\GatewayBridgeClientIdentity;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Artisan;
use Tests\TestCase;

final class GatewayBridgeClientIdentityTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.name', 'MCP Gateway Test');
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/sites/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');
        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);
    }

    public function test_public_metadata_matches_the_integrated_wp_ai_bridge_client_contract(): void
    {
        $this->getJson('/oauth/client.json')
            ->assertOk()
            ->assertJson([
                'client_id' => 'https://gateway.example.test/oauth/client.json',
                'client_name' => 'MCP Gateway Test',
                'redirect_uris' => ['https://gateway.example.test/oauth/sites/callback'],
                'grant_types' => ['authorization_code', 'refresh_token'],
                'response_types' => ['code'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks_uri' => 'https://gateway.example.test/oauth/jwks.json',
            ])
            ->assertHeader('Cache-Control', 'public, max-age=300');

        $jwks = $this->getJson('/oauth/jwks.json')
            ->assertOk()
            ->assertJsonPath('keys.0.kty', 'RSA')
            ->assertJsonPath('keys.0.use', 'sig')
            ->assertJsonPath('keys.0.alg', 'RS256')
            ->json();

        self::assertIsString($jwks['keys'][0]['kid'] ?? null);
        self::assertIsString($jwks['keys'][0]['n'] ?? null);
        self::assertIsString($jwks['keys'][0]['e'] ?? null);
        self::assertLessThanOrEqual(160, strlen($jwks['keys'][0]['kid']));
        self::assertLessThanOrEqual(1024, strlen($jwks['keys'][0]['n']));
        self::assertLessThanOrEqual(32, strlen($jwks['keys'][0]['e']));
    }

    public function test_private_key_jwt_assertion_is_rs256_bound_and_short_lived(): void
    {
        /** @var GatewayBridgeClientIdentity $identity */
        $identity = app(GatewayBridgeClientIdentity::class);
        $audience = 'https://wp.example.test/wp-json/wp-ai-bridge/v1/oauth/token';
        $jwt = $identity->assertion($audience);
        $publicKey = file_get_contents((string) config('bridge.keys.public'));
        self::assertIsString($publicKey);

        $claims = JWT::decode($jwt, new Key($publicKey, 'RS256'));
        self::assertSame($identity->clientId(), $claims->iss);
        self::assertSame($identity->clientId(), $claims->sub);
        self::assertSame($audience, $claims->aud);
        self::assertIsString($claims->jti);
        self::assertGreaterThanOrEqual(time() - 2, $claims->iat);
        self::assertLessThanOrEqual(600, $claims->exp - $claims->iat);

        [$headerPart] = explode('.', $jwt, 2);
        $header = json_decode($this->base64UrlDecode($headerPart), true, 16, JSON_THROW_ON_ERROR);
        self::assertSame('RS256', $header['alg'] ?? null);
        self::assertIsString($header['kid'] ?? null);
    }

    public function test_bridge_key_generator_refuses_gateway_oauth_key_paths(): void
    {
        config()->set('bridge.keys.private', (string) config('oauth.keys.private'));
        config()->set('bridge.keys.public', (string) config('oauth.keys.public'));

        self::assertSame(1, Artisan::call('gateway:bridge-client-keygen', ['--force' => true]));
        self::assertStringContainsString('distinct', Artisan::output());
    }

    public function test_assertion_fails_closed_when_private_and_public_keys_do_not_match(): void
    {
        $otherPrivate = (string) config('bridge.keys.private').'.other';
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($key);
        $pem = '';
        self::assertTrue(openssl_pkey_export($key, $pem));
        self::assertNotFalse(file_put_contents($otherPrivate, $pem));
        chmod($otherPrivate, 0600);

        try {
            config()->set('bridge.keys.private', $otherPrivate);
            /** @var GatewayBridgeClientIdentity $identity */
            $identity = app(GatewayBridgeClientIdentity::class);
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('does not match');
            $identity->assertion('https://wp.example.test/wp-json/wp-ai-bridge/v1/oauth/token');
        } finally {
            @unlink($otherPrivate);
        }
    }

    private function base64UrlDecode(string $value): string
    {
        $padding = strlen($value) % 4;
        if ($padding !== 0) {
            $value .= str_repeat('=', 4 - $padding);
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        self::assertIsString($decoded);

        return $decoded;
    }
}
