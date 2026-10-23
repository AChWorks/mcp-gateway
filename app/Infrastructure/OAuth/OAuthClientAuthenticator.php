<?php

namespace App\Infrastructure\OAuth;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

final readonly class OAuthClientAuthenticator
{
    public function __construct(
        private ClientProfileRegistry $profiles,
        private PrivateKeyJwtClientAuthenticator $privateKeyJwt,
        private DcrClientSecretAuthenticator $dcrSecret,
    ) {}

    /** @param list<string> $allowedAudiences */
    public function validate(ServerRequestInterface $request, array $allowedAudiences): string
    {
        $parameters = $request->getParsedBody();
        $clientId = is_array($parameters) ? ($parameters['client_id'] ?? null) : null;
        if (! is_string($clientId) || $clientId === '' || strlen($clientId) > 255) {
            throw OAuthServerException::invalidClient($request);
        }

        $profile = $this->profiles->active($clientId);
        if ($profile === null) {
            throw OAuthServerException::invalidClient($request);
        }

        return match ($profile['strategy']) {
            'cimd_private_key_jwt', 'pinned_private_key_jwt' => $this->privateKeyJwt->validate($request, $allowedAudiences),
            'dcr_client_secret_post' => $this->dcrSecret->validate($request, $clientId),
            default => throw OAuthServerException::invalidClient($request),
        };
    }
}
