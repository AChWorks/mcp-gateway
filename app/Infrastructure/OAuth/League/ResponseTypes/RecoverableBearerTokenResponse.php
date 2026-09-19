<?php

namespace App\Infrastructure\OAuth\League\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

final class RecoverableBearerTokenResponse extends BearerTokenResponse
{
    public const INTERNAL_RECOVERY_HEADER = 'X-MCP-Gateway-Internal-OAuth-Recovery';

    public const INTERNAL_REFRESH_TOKEN_ISSUED_HEADER = 'X-MCP-Gateway-Internal-OAuth-Refresh-Issued';

    private ?string $preparedBody = null;

    private bool $recovered = false;

    private ?bool $recoveredRefreshTokenIssued = null;

    public function accessToken(): AccessTokenEntityInterface
    {
        return $this->accessToken;
    }

    public function refreshToken(): ?RefreshTokenEntityInterface
    {
        return isset($this->refreshToken) ? $this->refreshToken : null;
    }

    public function prepareResponseBody(): string
    {
        if ($this->preparedBody !== null) {
            return $this->preparedBody;
        }

        $responseParams = [
            'token_type' => 'Bearer',
            'expires_in' => $this->accessToken->getExpiryDateTime()->getTimestamp() - time(),
            'access_token' => $this->accessToken->toString(),
        ];

        if (isset($this->refreshToken)) {
            $refreshTokenPayload = json_encode([
                'client_id' => $this->accessToken->getClient()->getIdentifier(),
                'refresh_token_id' => $this->refreshToken->getIdentifier(),
                'access_token_id' => $this->accessToken->getIdentifier(),
                'scopes' => $this->accessToken->getScopes(),
                'user_id' => $this->accessToken->getUserIdentifier(),
                'expire_time' => $this->refreshToken->getExpiryDateTime()->getTimestamp(),
            ]);

            if ($refreshTokenPayload === false) {
                throw new LogicException('Error encountered JSON encoding the refresh token payload');
            }

            $responseParams['refresh_token'] = $this->encrypt($refreshTokenPayload);
        }

        $encoded = json_encode(array_merge($this->getExtraParams($this->accessToken), $responseParams));
        if ($encoded === false) {
            throw new LogicException('Error encountered JSON encoding response parameters');
        }

        return $this->preparedBody = $encoded;
    }

    public function restorePreparedBody(string $body, bool $refreshTokenIssued): self
    {
        if ($body === '' || $this->preparedBody !== null) {
            throw new RuntimeException('OAuth refresh recovery response state is invalid.');
        }

        $this->preparedBody = $body;
        $this->recovered = true;
        $this->recoveredRefreshTokenIssued = $refreshTokenIssued;

        return $this;
    }

    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8')
            ->withHeader(
                self::INTERNAL_REFRESH_TOKEN_ISSUED_HEADER,
                $this->refreshTokenIssued() ? '1' : '0',
            );

        if ($this->recovered) {
            $response = $response->withHeader(self::INTERNAL_RECOVERY_HEADER, '1');
        }

        $response->getBody()->write($this->prepareResponseBody());

        return $response;
    }

    private function refreshTokenIssued(): bool
    {
        if ($this->recovered) {
            if ($this->recoveredRefreshTokenIssued === null) {
                throw new RuntimeException('OAuth refresh recovery token state is unavailable.');
            }

            return $this->recoveredRefreshTokenIssued;
        }

        return isset($this->refreshToken);
    }
}
