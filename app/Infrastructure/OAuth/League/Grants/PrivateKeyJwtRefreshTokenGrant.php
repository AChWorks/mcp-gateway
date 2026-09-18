<?php

namespace App\Infrastructure\OAuth\League\Grants;

use App\Infrastructure\OAuth\League\ResponseTypes\RecoverableBearerTokenResponse;
use App\Infrastructure\OAuth\PrivateKeyJwtClientAuthenticator;
use App\Infrastructure\OAuth\RefreshTokenRecoveryStore;
use DateInterval;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

final class PrivateKeyJwtRefreshTokenGrant extends RefreshTokenGrant
{
    use IssuesRefreshTokensForMcpAccess;

    private const VALIDATED_CLIENT_ATTRIBUTE = 'gateway.oauth.validated_client';

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
