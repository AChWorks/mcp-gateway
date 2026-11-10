<?php

namespace App\Infrastructure\OAuth;

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
            throw OAuthClientAuthDiagnostic::invalidClient($request, 'client_identity', 'client_id_missing_or_invalid');
        }

        try {
            $profile = $this->profiles->active($clientId);
        } catch (\Throwable $exception) {
            OAuthClientAuthDiagnostic::remember('client_profile', 'profile_lookup_failed', $exception);
            throw $exception;
        }
        if ($profile === null) {
            throw OAuthClientAuthDiagnostic::invalidClient($request, 'client_profile', 'client_profile_unavailable');
        }

        return match ($profile['strategy']) {
            'cimd_private_key_jwt', 'pinned_private_key_jwt' => $this->privateKeyJwt->validate($request, $allowedAudiences),
            'dcr_client_secret_post' => $this->dcrSecret->validate($request, $clientId),
            default => throw OAuthClientAuthDiagnostic::invalidClient($request, 'client_profile', 'authentication_strategy_unsupported'),
        };
    }
}
