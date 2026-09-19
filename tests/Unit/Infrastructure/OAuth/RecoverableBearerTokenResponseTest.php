<?php

namespace Tests\Unit\Infrastructure\OAuth;

use App\Infrastructure\OAuth\League\ResponseTypes\RecoverableBearerTokenResponse;
use DateTimeImmutable;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use Mockery;
use Tests\TestCase;

final class RecoverableBearerTokenResponseTest extends TestCase
{
    public function test_generated_response_marks_refresh_token_issuance_without_exposing_internal_state_in_body(): void
    {
        $responseType = new RecoverableBearerTokenResponse;
        $responseType->setEncryptionKey('test-encryption-key');
        $responseType->setAccessToken($this->accessToken());
        $responseType->setRefreshToken($this->refreshToken());

        $response = $responseType->generateHttpResponse(new Response);

        self::assertSame('1', $response->getHeaderLine(RecoverableBearerTokenResponse::INTERNAL_REFRESH_TOKEN_ISSUED_HEADER));
        $payload = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertArrayHasKey('refresh_token', $payload);
        self::assertArrayNotHasKey('refresh_token_issued', $payload);
    }

    public function test_generated_response_marks_absence_of_refresh_token(): void
    {
        $responseType = new RecoverableBearerTokenResponse;
        $responseType->setAccessToken($this->accessToken());

        $response = $responseType->generateHttpResponse(new Response);

        self::assertSame('0', $response->getHeaderLine(RecoverableBearerTokenResponse::INTERNAL_REFRESH_TOKEN_ISSUED_HEADER));
        $payload = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertArrayNotHasKey('refresh_token', $payload);
    }

    public function test_recovered_response_carries_authoritative_refresh_token_state(): void
    {
        $withRefresh = (new RecoverableBearerTokenResponse)
            ->restorePreparedBody('{"token_type":"Bearer","access_token":"opaque","refresh_token":"opaque-refresh"}', true)
            ->generateHttpResponse(new Response);
        self::assertSame('1', $withRefresh->getHeaderLine(RecoverableBearerTokenResponse::INTERNAL_RECOVERY_HEADER));
        self::assertSame('1', $withRefresh->getHeaderLine(RecoverableBearerTokenResponse::INTERNAL_REFRESH_TOKEN_ISSUED_HEADER));

        $withoutRefresh = (new RecoverableBearerTokenResponse)
            ->restorePreparedBody('{"token_type":"Bearer","access_token":"opaque"}', false)
            ->generateHttpResponse(new Response);
        self::assertSame('1', $withoutRefresh->getHeaderLine(RecoverableBearerTokenResponse::INTERNAL_RECOVERY_HEADER));
        self::assertSame('0', $withoutRefresh->getHeaderLine(RecoverableBearerTokenResponse::INTERNAL_REFRESH_TOKEN_ISSUED_HEADER));
    }

    private function accessToken(): AccessTokenEntityInterface
    {
        $client = Mockery::mock(ClientEntityInterface::class);
        $client->shouldReceive('getIdentifier')->andReturn('https://chatgpt.com/oauth/client.json');

        $token = Mockery::mock(AccessTokenEntityInterface::class);
        $token->shouldReceive('getExpiryDateTime')->andReturn(new DateTimeImmutable('+1 hour'));
        $token->shouldReceive('toString')->andReturn('opaque-access-token');
        $token->shouldReceive('getClient')->andReturn($client);
        $token->shouldReceive('getIdentifier')->andReturn('access-id');
        $token->shouldReceive('getScopes')->andReturn([]);
        $token->shouldReceive('getUserIdentifier')->andReturn('1');

        return $token;
    }

    private function refreshToken(): RefreshTokenEntityInterface
    {
        $token = Mockery::mock(RefreshTokenEntityInterface::class);
        $token->shouldReceive('getIdentifier')->andReturn('refresh-id');
        $token->shouldReceive('getExpiryDateTime')->andReturn(new DateTimeImmutable('+30 days'));

        return $token;
    }
}
