<?php

namespace App\Infrastructure\OAuth;

use App\Infrastructure\OAuth\League\Grants\PrivateKeyJwtAuthCodeGrant;
use App\Infrastructure\OAuth\League\Grants\PrivateKeyJwtRefreshTokenGrant;
use App\Infrastructure\OAuth\League\Repositories\AccessTokenRepository;
use App\Infrastructure\OAuth\League\Repositories\AuthCodeRepository;
use App\Infrastructure\OAuth\League\Repositories\ClientRepository;
use App\Infrastructure\OAuth\League\Repositories\RefreshTokenRepository;
use App\Infrastructure\OAuth\League\Repositories\ScopeRepository;
use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;

final class OAuthServerManager
{
    private ?AuthorizationServer $authorizationServer = null;

    private ?ResourceServer $resourceServer = null;

    public function __construct(
        private readonly ClientRepository $clients,
        private readonly AccessTokenRepository $accessTokens,
        private readonly ScopeRepository $scopes,
        private readonly AuthCodeRepository $authCodes,
        private readonly RefreshTokenRepository $refreshTokens,
        private readonly PrivateKeyJwtClientAuthenticator $clientAuthenticator,
    ) {}

    public function authorizationServer(): AuthorizationServer
    {
        if ($this->authorizationServer !== null) {
            return $this->authorizationServer;
        }

        $privateKey = new CryptKey((string) config('oauth.keys.private'));
        $server = new AuthorizationServer(
            $this->clients,
            $this->accessTokens,
            $this->scopes,
            $privateKey,
            $this->encryptionKey(),
        );
        $server->setDefaultScope((string) config('oauth.scope'));
        $server->revokeRefreshTokens(true);

        $authCodeGrant = new PrivateKeyJwtAuthCodeGrant(
            $this->authCodes,
            $this->refreshTokens,
            $this->secondsInterval((int) config('oauth.ttl.authorization_code_seconds')),
            $this->clientAuthenticator,
        );
        $authCodeGrant->setRefreshTokenTTL($this->secondsInterval((int) config('oauth.ttl.refresh_token_seconds')));

        $refreshGrant = new PrivateKeyJwtRefreshTokenGrant(
            $this->refreshTokens,
            $this->clientAuthenticator,
        );
        $refreshGrant->setRefreshTokenTTL($this->secondsInterval((int) config('oauth.ttl.refresh_token_seconds')));

        $accessTtl = $this->secondsInterval((int) config('oauth.ttl.access_token_seconds'));
        $server->enableGrantType($authCodeGrant, $accessTtl);
        $server->enableGrantType($refreshGrant, $accessTtl);

        return $this->authorizationServer = $server;
    }

    public function resourceServer(): ResourceServer
    {
        if ($this->resourceServer !== null) {
            return $this->resourceServer;
        }

        return $this->resourceServer = new ResourceServer(
            $this->accessTokens,
            new CryptKey((string) config('oauth.keys.public')),
        );
    }

    public function encryptionKey(): string
    {
        $applicationKey = (string) config('app.key');
        if ($applicationKey === '') {
            throw new \RuntimeException('APP_KEY is required for the OAuth encryption key.');
        }

        return hash_hmac('sha256', 'mcp-gateway:league-oauth:v1', $applicationKey);
    }

    private function secondsInterval(int $seconds): DateInterval
    {
        return new DateInterval('PT'.max(1, $seconds).'S');
    }
}
