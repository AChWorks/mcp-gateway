<?php

namespace App\Infrastructure\OAuth\League\Repositories;

use App\Infrastructure\OAuth\ClientProfileRegistry;
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
    public function __construct(private OAuthAuthorizationStore $authorizations, private ClientProfileRegistry $profiles) {}

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
        return ! $this->tokenUsable($this->findToken($tokenId));
    }

    /**
     * Revalidate the exact bearer AND its parent consent at the final MCP
     * effect boundary. Identity is supplied only by the verified HTTP
     * middleware, never by MCP Tool arguments or caller-controlled metadata.
     */
    public function authorizesDispatch(
        string $tokenId, int $userId, string $clientId, string $profileKey, int $profileGeneration,
    ): bool {
        $row = $this->findToken($tokenId);
        if ($row === null || ! $this->tokenUsable($row)
            || (int) $row->user_id !== $userId
            || (int) $row->authorization_user_id !== $userId
            || ! hash_equals((string) $row->client_id, $clientId)
            || ! hash_equals((string) $row->client_profile_key, $profileKey)
            || (int) $row->client_profile_generation !== $profileGeneration
            || (string) $row->authorization_resource !== (string) config('oauth.resource')
            || ! hash_equals((string) $row->authorization_resource_hash,
                hash('sha256', (string) config('oauth.resource')))) {
            return false;
        }

        $scope = (string) config('oauth.scope');
        $tokenScopes = json_decode((string) $row->scopes, true);
        $consentScopes = json_decode((string) $row->authorization_scopes, true);

        return is_array($tokenScopes) && in_array($scope, $tokenScopes, true)
            && is_array($consentScopes) && in_array($scope, $consentScopes, true);
    }

    private function findToken(string $tokenId): ?object
    {
        return DB::table('oauth_access_tokens as tokens')
            ->join('oauth_authorizations as authorizations', 'authorizations.id', '=', 'tokens.authorization_id')
            ->join('users', 'users.id', '=', 'tokens.user_id')
            ->where('tokens.id', $tokenId)
            ->select([
                'tokens.user_id',
                'tokens.client_id',
                'tokens.resource',
                'tokens.scopes',
                'tokens.expires_at',
                'tokens.revoked_at',
                'authorizations.user_id as authorization_user_id',
                'authorizations.client_id as authorization_client_id',
                'authorizations.client_profile_key',
                'authorizations.client_profile_generation',
                'authorizations.resource as authorization_resource',
                'authorizations.resource_hash as authorization_resource_hash',
                'authorizations.scopes as authorization_scopes',
                'authorizations.revoked_at as authorization_revoked_at',
                'users.access_enabled as user_access_enabled',
                'users.ai_access_enabled as user_ai_access_enabled',
            ])
            ->first();
    }

    private function tokenUsable(?object $row): bool
    {
        return $row !== null
            && $row->revoked_at === null
            && $row->authorization_revoked_at === null
            && (bool) $row->user_access_enabled
            && (bool) $row->user_ai_access_enabled
            && (int) $row->user_id === (int) $row->authorization_user_id
            && hash_equals((string) $row->client_id, (string) $row->authorization_client_id)
            && $this->profiles->authorizes(
                (string) $row->client_id,
                is_string($row->client_profile_key) ? $row->client_profile_key : null,
                $row->client_profile_generation === null ? null : (int) $row->client_profile_generation,
            )
            && (string) $row->resource === (string) config('oauth.resource')
            && now()->lt($row->expires_at);
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
