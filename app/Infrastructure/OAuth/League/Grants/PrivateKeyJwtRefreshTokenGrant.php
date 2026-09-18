<?php

namespace App\Infrastructure\OAuth\League\Grants;

use App\Infrastructure\OAuth\League\ResponseTypes\RecoverableBearerTokenResponse;
use App\Infrastructure\OAuth\PrivateKeyJwtClientAuthenticator;
use App\Infrastructure\OAuth\RefreshTokenRecoveryStore;
use DateInterval;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

final class PrivateKeyJwtRefreshTokenGrant extends RefreshTokenGrant
{
    private const VALIDATED_CLIENT_ATTRIBUTE = 'gateway.oauth.validated_client';

    /** @var list<string>|null */
    private ?array $validatedRefreshTokenScopes = null;

    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly PrivateKeyJwtClientAuthenticator $clientAuthenticator,
        private readonly RefreshTokenRecoveryStore $recovery,
    ) {
        parent::__construct($refreshTokenRepository);
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        $client = $this->authenticateClient($request);
        $validatedRequest = $request->withAttribute(self::VALIDATED_CLIENT_ATTRIBUTE, $client);

        if (! $responseType instanceof RecoverableBearerTokenResponse) {
            throw new RuntimeException('OAuth refresh recovery requires the recoverable response type.');
        }

        try {
            return DB::transaction(function () use (
                $validatedRequest,
                $responseType,
                $accessTokenTTL,
            ): ResponseTypeInterface {
                $result = parent::respondToAccessTokenRequest(
                    $validatedRequest,
                    $responseType,
                    $accessTokenTTL,
                );

                if (! $result instanceof RecoverableBearerTokenResponse) {
                    throw new RuntimeException('OAuth refresh response type changed unexpectedly.');
                }

                $this->recovery->stage($validatedRequest, $result);

                return $result;
            });
        } catch (OAuthServerException $exception) {
            if ($exception->getErrorType() !== 'invalid_grant') {
                throw $exception;
            }

            $recovered = $this->recovery->recover(
                $validatedRequest,
                $responseType,
                $client->getIdentifier(),
            );

            if ($recovered === null) {
                throw $exception;
            }

            return $recovered;
        }
    }

    /** @return array<string, mixed> */
    protected function validateOldRefreshToken(ServerRequestInterface $request, string $clientId): array
    {
        $oldRefreshToken = parent::validateOldRefreshToken($request, $clientId);
        $scopes = $oldRefreshToken['scopes'] ?? null;
        if (! is_array($scopes)) {
            throw OAuthServerException::invalidRefreshToken('Token scope binding is invalid.');
        }

        $this->validatedRefreshTokenScopes = $this->normalizeScopeIdentifiers($scopes);

        return $oldRefreshToken;
    }

    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        if ($this->validatedRefreshTokenScopes === null) {
            throw new RuntimeException('Refresh token scope context is unavailable.');
        }

        $accessTokenScopes = $this->normalizeScopeIdentifiers(array_map(
            static fn ($scope): string => $scope->getIdentifier(),
            $accessToken->getScopes(),
        ));

        // RFC 6749 Section 6 requires a replacement refresh token to retain
        // the exact scope of the refresh token presented by the client.
        // A narrowed access token is valid, but narrowing ends refresh authority.
        if ($accessTokenScopes !== $this->validatedRefreshTokenScopes) {
            return null;
        }

        foreach ($accessTokenScopes as $scope) {
            if ($scope === (string) config('oauth.scope')) {
                return parent::issueRefreshToken($accessToken);
            }
        }

        return null;
    }

    /**
     * @param  array<mixed>  $scopes
     * @return list<string>
     */
    private function normalizeScopeIdentifiers(array $scopes): array
    {
        $normalized = [];
        foreach ($scopes as $scope) {
            if (! is_string($scope) || $scope === '') {
                throw OAuthServerException::invalidRefreshToken('Token scope binding is invalid.');
            }

            $normalized[] = $scope;
        }

        $normalized = array_values(array_unique($normalized));
        sort($normalized, SORT_STRING);

        return $normalized;
    }

    protected function validateClient(ServerRequestInterface $request): ClientEntityInterface
    {
        $validatedClient = $request->getAttribute(self::VALIDATED_CLIENT_ATTRIBUTE);
        if ($validatedClient instanceof ClientEntityInterface) {
            return $validatedClient;
        }

        return $this->authenticateClient($request);
    }

    private function authenticateClient(ServerRequestInterface $request): ClientEntityInterface
    {
        $clientId = $this->clientAuthenticator->validate($request, [
            (string) config('oauth.issuer'),
            rtrim((string) config('oauth.issuer'), '/').'/oauth/token',
        ]);

        return $this->getClientEntityOrFail($clientId, $request);
    }
}
