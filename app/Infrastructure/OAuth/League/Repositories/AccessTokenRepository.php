<?php

namespace App\Infrastructure\OAuth\League\Repositories;

use App\Infrastructure\OAuth\League\Entities\AccessTokenEntity;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final readonly class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(private OAuthAuthorizationStore $authorizations) {}

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        $token = new AccessTokenEntity;
        $token->setClient($clientEntity);

        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }

        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $userIdentifier = $accessTokenEntity->getUserIdentifier();
        if ($userIdentifier === null) {
            throw new \RuntimeException('Access token is missing its user identifier.');
        }

        $scopes = $this->scopeIdentifiers($accessTokenEntity->getScopes());
        $resource = (string) config('oauth.resource');
        $authorizationId = $this->authorizations->activeId(
            $accessTokenEntity->getClient()->getIdentifier(),
            $userIdentifier,
            $resource,
            $scopes,
        );

        try {
            DB::table('oauth_access_tokens')->insert([
                'id' => $accessTokenEntity->getIdentifier(),
                'authorization_id' => $authorizationId,
                'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
                'user_id' => (int) $userIdentifier,
                'resource' => $resource,
                'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
                'expires_at' => $accessTokenEntity->getExpiryDateTime(),
                'revoked_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (QueryException $exception) {
            if (in_array((string) $exception->getCode(), ['23000', '19'], true)) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }

            throw $exception;
        }
    }

    public function revokeAccessToken(string $tokenId): void
    {
        DB::table('oauth_access_tokens')
            ->where('id', $tokenId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now(), 'updated_at' => now()]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $row = DB::table('oauth_access_tokens as tokens')
            ->join('oauth_authorizations as authorizations', 'authorizations.id', '=', 'tokens.authorization_id')
            ->join('users', 'users.id', '=', 'tokens.user_id')
            ->where('tokens.id', $tokenId)
            ->select([
                'tokens.client_id',
                'tokens.resource',
                'tokens.expires_at',
                'tokens.revoked_at',
                'authorizations.revoked_at as authorization_revoked_at',
                'users.access_enabled as user_access_enabled',
            ])
            ->first();

        return $row === null
            || $row->revoked_at !== null
            || $row->authorization_revoked_at !== null
            || ! (bool) $row->user_access_enabled
            || (string) $row->client_id !== (string) config('oauth.client.id')
            || (string) $row->resource !== (string) config('oauth.resource')
            || now()->gte($row->expires_at);
    }

    /** @param ScopeEntityInterface[] $scopes
     * @return list<string>
     */
    private function scopeIdentifiers(array $scopes): array
    {
        $identifiers = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $scopes,
        );
        sort($identifiers, SORT_STRING);

        return array_values(array_unique($identifiers));
    }
}
