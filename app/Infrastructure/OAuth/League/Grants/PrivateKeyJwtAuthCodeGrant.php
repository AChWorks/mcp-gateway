<?php

namespace App\Infrastructure\OAuth\League\Grants;

use App\Infrastructure\OAuth\PrivateKeyJwtClientAuthenticator;
use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ServerRequestInterface;

final class PrivateKeyJwtAuthCodeGrant extends AuthCodeGrant
{
    use IssuesRefreshTokensForOfflineAccess;

    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
        private readonly PrivateKeyJwtClientAuthenticator $clientAuthenticator,
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
    }

    protected function validateClient(ServerRequestInterface $request): ClientEntityInterface
    {
        $clientId = $this->clientAuthenticator->validate($request, [
            (string) config('oauth.issuer'),
            rtrim((string) config('oauth.issuer'), '/').'/oauth/token',
        ]);

        return $this->getClientEntityOrFail($clientId, $request);
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $query = $request->getQueryParams();
        if (($query['code_challenge_method'] ?? null) !== 'S256'
            || ! is_string($query['code_challenge'] ?? null)
            || (string) $query['code_challenge'] === '') {
            throw OAuthServerException::invalidRequest(
                'code_challenge_method',
                'PKCE with code_challenge_method=S256 is required.',
            );
        }

        return parent::validateAuthorizationRequest($request);
    }
}
