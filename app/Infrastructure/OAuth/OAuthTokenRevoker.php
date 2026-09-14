<?php

namespace App\Infrastructure\OAuth;

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\DB;

final readonly class OAuthTokenRevoker
{
    public function __construct(private RefreshTokenInspector $refreshTokens) {}

    public function revoke(string $presentedToken, string $clientId): void
    {
        if ($presentedToken === '' || strlen($presentedToken) > 32768) {
            return;
        }

        $authorizationId = $this->authorizationFromAccessToken($presentedToken, $clientId)
            ?? $this->authorizationFromRefreshToken($presentedToken, $clientId);

        if ($authorizationId === null) {
            return;
        }

        DB::transaction(function () use ($authorizationId, $clientId): void {
            $authorization = DB::table('oauth_authorizations')
                ->where('id', $authorizationId)
                ->where('client_id', $clientId)
                ->lockForUpdate()
                ->first();

            if ($authorization === null || $authorization->revoked_at !== null) {
                return;
            }

            $now = now();
            DB::table('oauth_authorizations')->where('id', $authorizationId)->update([
                'revoked_at' => $now,
                'updated_at' => $now,
            ]);
        });
    }

    private function authorizationFromAccessToken(string $token, string $clientId): ?string
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        try {
            $payload = json_decode(JWT::urlsafeB64Decode($parts[1]), true, flags: JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        $identifier = is_array($payload) ? ($payload['jti'] ?? null) : null;
        if (! is_string($identifier) || $identifier === '') {
            return null;
        }

        $row = DB::table('oauth_access_tokens')
            ->where('id', $identifier)
            ->where('client_id', $clientId)
            ->first(['authorization_id']);

        return $row === null ? null : (string) $row->authorization_id;
    }

    private function authorizationFromRefreshToken(string $token, string $clientId): ?string
    {
        $payload = $this->refreshTokens->inspect($token);
        if ($payload === null || ($payload['client_id'] ?? null) !== $clientId) {
            return null;
        }

        $identifier = $payload['refresh_token_id'] ?? null;
        if (! is_string($identifier) || $identifier === '') {
            return null;
        }

        $row = DB::table('oauth_refresh_tokens')
            ->where('id', $identifier)
            ->where('client_id', $clientId)
            ->first(['authorization_id']);

        return $row === null ? null : (string) $row->authorization_id;
    }
}
