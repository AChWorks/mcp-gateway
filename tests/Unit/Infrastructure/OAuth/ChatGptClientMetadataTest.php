<?php

namespace Tests\Unit\Infrastructure\OAuth;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Cache;
use RuntimeException;
use Tests\TestCase;

final class ChatGptClientMetadataTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        config()->set('oauth.client.id', 'https://chatgpt.com/oauth/client.json');
    }

    public function test_accepts_only_same_origin_rs256_jwks(): void
    {
        $service = $this->service([
            $this->metadataResponse(),
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'keys' => [[
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => 'key-1',
                    'n' => 'AQAB',
                    'e' => 'AQAB',
                ]],
            ], JSON_THROW_ON_ERROR)),
        ]);

        self::assertSame('ChatGPT', $service->clientName());
        self::assertSame(['https://chatgpt.com/connector_platform_oauth_redirect'], $service->redirectUris());
        self::assertCount(1, $service->jwks()['keys']);
    }

    public function test_rejects_off_origin_jwks_uri(): void
    {
        $service = $this->service([
            $this->metadataResponse(['jwks_uri' => 'https://attacker.example/jwks.json']),
        ]);

        $this->expectException(RuntimeException::class);
        $service->metadata();
    }

    public function test_rejects_same_host_jwks_on_a_different_port(): void
    {
        $service = $this->service([
            $this->metadataResponse(['jwks_uri' => 'https://chatgpt.com:8443/oauth/jwks.json']),
        ]);

        $this->expectException(RuntimeException::class);
        $service->metadata();
    }

    public function test_unknown_key_id_refreshes_once_then_respects_cooldown(): void
    {
        $jwksJson = json_encode([
            'keys' => [[
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => 'known-key',
                'n' => 'AQAB',
                'e' => 'AQAB',
            ]],
        ], JSON_THROW_ON_ERROR);
        $service = $this->service([
            $this->metadataResponse(),
            new Response(200, ['Content-Type' => 'application/json'], $jwksJson),
            $this->metadataResponse(),
            new Response(200, ['Content-Type' => 'application/json'], $jwksJson),
        ]);

        self::assertSame('known-key', $service->jwksForKeyId('missing-key')['keys'][0]['kid']);
        self::assertSame('known-key', $service->jwksForKeyId('missing-key')['keys'][0]['kid']);
    }

    public function test_rejects_metadata_response_over_size_limit(): void
    {
        config()->set('oauth.client.max_response_bytes', 1024);
        $body = json_encode(['padding' => str_repeat('x', 2048)], JSON_THROW_ON_ERROR);
        $service = $this->service([
            new Response(200, [
                'Content-Type' => 'application/json',
                'Content-Length' => (string) strlen($body),
            ], $body),
        ]);

        $this->expectException(RuntimeException::class);
        $service->metadata();
    }

    /** @param list<Response> $responses */
    private function service(array $responses): ChatGptClientMetadata
    {
        $mock = new MockHandler($responses);

        return new ChatGptClientMetadata(new Client(['handler' => HandlerStack::create($mock)]));
    }

    /** @param array<string, mixed> $overrides */
    private function metadataResponse(array $overrides = []): Response
    {
        $metadata = array_replace([
            'client_id' => 'https://chatgpt.com/oauth/client.json',
            'client_uri' => 'https://chatgpt.com/',
            'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'client_name' => 'ChatGPT',
            'token_endpoint_auth_signing_alg' => 'RS256',
            'jwks_uri' => 'https://chatgpt.com/oauth/jwks.json',
        ], $overrides);

        return new Response(200, ['Content-Type' => 'application/json'], json_encode($metadata, JSON_THROW_ON_ERROR));
    }
}
