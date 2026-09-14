<?php

namespace App\Infrastructure\OAuth\League\Grants;

use App\Infrastructure\OAuth\PrivateKeyJwtClientAuthenticator;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

final class PrivateKeyJwtRefreshTokenGrant extends RefreshTokenGrant
{
    use IssuesRefreshTokensForOfflineAccess;

    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly PrivateKeyJwtClientAuthenticator $clientAuthenticator,
    ) {
        parent::__construct($refreshTokenRepository);
    }

    protected function validateClient(ServerRequestInterface $request): ClientEntityInterface
    {
        $clientId = $this->clientAuthenticator->validate($request, [
            (string) config('oauth.issuer'),
            rtrim((string) config('oauth.issuer'), '/').'/oauth/token',
        ]);

        return $this->getClientEntityOrFail($clientId, $request);
    }
}
