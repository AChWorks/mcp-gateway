<?php

namespace App\Infrastructure\OAuth\League\Repositories;

use App\Infrastructure\OAuth\League\Entities\RefreshTokenEntity;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $accessTokenId = $refreshTokenEntity->getAccessToken()->getIdentifier();
        $accessToken = DB::table('oauth_access_tokens')->where('id', $accessTokenId)->first();

        if ($accessToken === null) {
            throw new \RuntimeException('Refresh token access-token binding is missing.');
        }

        try {
            DB::table('oauth_refresh_tokens')->insert([
                'id' => $refreshTokenEntity->getIdentifier(),
                'access_token_id' => $accessTokenId,
                'authorization_id' => $accessToken->authorization_id,
                'client_id' => $accessToken->client_id,
                'user_id' => $accessToken->user_id,
                'resource' => $accessToken->resource,
                'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
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

    public function revokeRefreshToken(string $tokenId): void
    {
        DB::table('oauth_refresh_tokens')
            ->where('id', $tokenId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now(), 'updated_at' => now()]);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $row = DB::table('oauth_refresh_tokens as tokens')
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
            ->lockForUpdate()
            ->first();

        return $row === null
            || $row->revoked_at !== null
            || $row->authorization_revoked_at !== null
            || ! (bool) $row->user_access_enabled
            || (string) $row->client_id !== (string) config('oauth.client.id')
            || (string) $row->resource !== (string) config('oauth.resource')
            || now()->gte($row->expires_at);
    }
}
