<?php

namespace App\Infrastructure\OAuth\League\Repositories;

use App\Infrastructure\OAuth\League\Entities\AuthCodeEntity;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

final readonly class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(private OAuthAuthorizationStore $authorizations) {}

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCodeEntity;
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $userIdentifier = $authCodeEntity->getUserIdentifier();
        if ($userIdentifier === null) {
            throw new \RuntimeException('Authorization code is missing its user identifier.');
        }

        $scopes = $this->scopeIdentifiers($authCodeEntity->getScopes());
        $resource = (string) config('oauth.resource');
        $authorizationId = $this->authorizations->activeId(
            $authCodeEntity->getClient()->getIdentifier(),
            $userIdentifier,
            $resource,
            $scopes,
        );

        try {
            DB::table('oauth_auth_codes')->insert([
                'id' => $authCodeEntity->getIdentifier(),
                'authorization_id' => $authorizationId,
                'client_id' => $authCodeEntity->getClient()->getIdentifier(),
                'user_id' => (int) $userIdentifier,
                'resource' => $resource,
                'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
                'expires_at' => $authCodeEntity->getExpiryDateTime(),
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

    public function revokeAuthCode(string $codeId): void
    {
        DB::table('oauth_auth_codes')
            ->where('id', $codeId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now(), 'updated_at' => now()]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $row = DB::table('oauth_auth_codes as codes')
            ->join('oauth_authorizations as authorizations', 'authorizations.id', '=', 'codes.authorization_id')
            ->where('codes.id', $codeId)
            ->select([
                'codes.client_id',
                'codes.resource',
                'codes.expires_at',
                'codes.revoked_at',
                'authorizations.revoked_at as authorization_revoked_at',
            ])
            ->lockForUpdate()
            ->first();

        return $row === null
            || $row->revoked_at !== null
            || $row->authorization_revoked_at !== null
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
