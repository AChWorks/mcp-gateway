<?php

namespace App\Infrastructure\OAuth;

use App\Infrastructure\OAuth\League\ResponseTypes\RecoverableBearerTokenResponse;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Throwable;

final readonly class RefreshTokenRecoveryStore
{
    public function __construct(
        private RefreshTokenInspector $refreshTokens,
        private OAuthEncryptionKey $keys,
        private OAuthRefreshRecoveryCipher $cipher,
    ) {}

    public function stage(
        ServerRequestInterface $request,
        RecoverableBearerTokenResponse $response,
    ): void {
        $parameters = $this->parameters($request);
        $presentedToken = $this->presentedRefreshToken($parameters);
        $oldPayload = $this->refreshTokens->inspect($presentedToken);
        if ($oldPayload === null) {
            throw new RuntimeException('Rotated refresh token could not be inspected for recovery staging.');
        }

        $oldRefreshTokenId = $this->requiredString($oldPayload, 'refresh_token_id', 128);
        $oldAccessTokenId = $this->requiredString($oldPayload, 'access_token_id', 128);
        $oldClientId = $this->requiredString($oldPayload, 'client_id', 1024);
        $oldUserId = $this->requiredNumericIdentifier($oldPayload, 'user_id');
        $oldScopes = $this->payloadScopes($oldPayload);

        $old = DB::table('oauth_refresh_tokens')
            ->where('id', $oldRefreshTokenId)
            ->lockForUpdate()
            ->first();

        if ($old === null
            || $old->revoked_at === null
            || (string) $old->access_token_id !== $oldAccessTokenId
            || (string) $old->client_id !== $oldClientId
            || (string) $old->client_id !== (string) config('oauth.client.id')
            || (string) $old->user_id !== $oldUserId
            || (string) $old->resource !== (string) config('oauth.resource')) {
            throw new RuntimeException('Rotated refresh token recovery binding is invalid.');
        }

        $accessToken = $response->accessToken();
        $successorAccessTokenId = $accessToken->getIdentifier();
        $access = DB::table('oauth_access_tokens')
            ->where('id', $successorAccessTokenId)
            ->lockForUpdate()
            ->first();

        if ($access === null
            || $access->revoked_at !== null
            || (string) $access->authorization_id !== (string) $old->authorization_id
            || (string) $access->client_id !== (string) $old->client_id
            || (string) $access->user_id !== (string) $old->user_id
            || (string) $access->resource !== (string) $old->resource) {
            throw new RuntimeException('Successor access token recovery binding is invalid.');
        }

        $successorRefreshToken = $response->refreshToken();
        $successorRefreshTokenId = $successorRefreshToken?->getIdentifier();
        if ($successorRefreshTokenId !== null) {
            $successorRefresh = DB::table('oauth_refresh_tokens')
                ->where('id', $successorRefreshTokenId)
                ->lockForUpdate()
                ->first();

            if ($successorRefresh === null
                || $successorRefresh->revoked_at !== null
                || (string) $successorRefresh->access_token_id !== $successorAccessTokenId
                || (string) $successorRefresh->authorization_id !== (string) $old->authorization_id
                || (string) $successorRefresh->client_id !== (string) $old->client_id
                || (string) $successorRefresh->user_id !== (string) $old->user_id
                || (string) $successorRefresh->resource !== (string) $old->resource) {
                throw new RuntimeException('Successor refresh token recovery binding is invalid.');
            }
        }

        $effectiveScopes = $this->scopeIdentifiers($accessToken->getScopes());
        if ($effectiveScopes !== $this->requestedScopes($parameters, $oldScopes)) {
            throw new RuntimeException('Refresh recovery scope binding is invalid.');
        }

        $oldTokenHash = $this->oldTokenHash($presentedToken);
        $responseBody = $response->prepareResponseBody();
        $envelope = json_encode([
            'version' => 1,
            'old_token_hash' => $oldTokenHash,
            'authorization_id' => (string) $old->authorization_id,
            'client_id' => (string) $old->client_id,
            'user_id' => (string) $old->user_id,
            'resource' => (string) $old->resource,
            'successor_access_token_id' => $successorAccessTokenId,
            'successor_refresh_token_id' => $successorRefreshTokenId,
            'effective_scopes' => $effectiveScopes,
            'response_body' => $responseBody,
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $this->pruneExpired();

        DB::table('oauth_refresh_recoveries')->insert([
            'old_token_hash' => $oldTokenHash,
            'old_refresh_token_id' => $oldRefreshTokenId,
            'successor_access_token_id' => $successorAccessTokenId,
            'successor_refresh_token_id' => $successorRefreshTokenId,
            'authorization_id' => $old->authorization_id,
            'client_id' => $old->client_id,
            'user_id' => $old->user_id,
            'resource' => $old->resource,
            'effective_scopes' => json_encode($effectiveScopes, JSON_THROW_ON_ERROR),
            'response_ciphertext' => $this->cipher->seal($envelope),
            'recovery_expires_at' => now()->addSeconds($this->recoverySeconds()),
            'uses_remaining' => 1,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->capRecords();
    }

    public function recover(
        ServerRequestInterface $request,
        RecoverableBearerTokenResponse $response,
        string $validatedClientId,
    ): ?RecoverableBearerTokenResponse {
        $parameters = $this->parameters($request);

        try {
            $presentedToken = $this->presentedRefreshToken($parameters);
            $oldPayload = $this->refreshTokens->inspect($presentedToken);
            if ($oldPayload === null) {
                return null;
            }

            $oldRefreshTokenId = $this->requiredString($oldPayload, 'refresh_token_id', 128);
            $oldClientId = $this->requiredString($oldPayload, 'client_id', 1024);
            $oldUserId = $this->requiredNumericIdentifier($oldPayload, 'user_id');
            $oldScopes = $this->payloadScopes($oldPayload);
            $oldTokenHash = $this->oldTokenHash($presentedToken);
        } catch (Throwable) {
            return null;
        }

        return DB::transaction(function () use (
            $parameters,
            $oldRefreshTokenId,
            $oldClientId,
            $oldUserId,
            $oldScopes,
            $oldTokenHash,
            $validatedClientId,
            $response,
        ): ?RecoverableBearerTokenResponse {
            $this->pruneExpired();

            $recovery = DB::table('oauth_refresh_recoveries')
                ->where('old_token_hash', $oldTokenHash)
                ->lockForUpdate()
                ->first();

            if ($recovery === null
                || (int) $recovery->uses_remaining < 1
                || ! $this->isFuture((string) $recovery->recovery_expires_at)
                || ! hash_equals((string) $recovery->client_id, $validatedClientId)
                || ! hash_equals((string) $recovery->client_id, $oldClientId)
                || ! hash_equals((string) $recovery->client_id, (string) config('oauth.client.id'))
                || ! hash_equals((string) $recovery->resource, (string) ($parameters['resource'] ?? ''))
                || ! hash_equals((string) $recovery->resource, (string) config('oauth.resource'))
                || (string) $recovery->old_refresh_token_id !== $oldRefreshTokenId
                || (string) $recovery->user_id !== $oldUserId) {
                return null;
            }

            $old = DB::table('oauth_refresh_tokens')
                ->where('id', $oldRefreshTokenId)
                ->lockForUpdate()
                ->first();

            if ($old === null
                || $old->revoked_at === null
                || ! $this->isFuture((string) $old->expires_at)
                || (string) $old->authorization_id !== (string) $recovery->authorization_id
                || (string) $old->client_id !== (string) $recovery->client_id
                || (string) $old->user_id !== (string) $recovery->user_id
                || (string) $old->resource !== (string) $recovery->resource) {
                return null;
            }

            $authorization = DB::table('oauth_authorizations')
                ->where('id', $recovery->authorization_id)
                ->where('client_id', $recovery->client_id)
                ->where('user_id', $recovery->user_id)
                ->lockForUpdate()
                ->first();

            if ($authorization === null
                || $authorization->revoked_at !== null
                || (string) $authorization->resource !== (string) $recovery->resource) {
                return null;
            }

            $successorAccess = DB::table('oauth_access_tokens')
                ->where('id', $recovery->successor_access_token_id)
                ->lockForUpdate()
                ->first();

            if ($successorAccess === null
                || $successorAccess->revoked_at !== null
                || ! $this->isFuture((string) $successorAccess->expires_at)
                || (string) $successorAccess->authorization_id !== (string) $recovery->authorization_id
                || (string) $successorAccess->client_id !== (string) $recovery->client_id
                || (string) $successorAccess->user_id !== (string) $recovery->user_id
                || (string) $successorAccess->resource !== (string) $recovery->resource) {
                return null;
            }

            $successorRefreshTokenId = is_string($recovery->successor_refresh_token_id)
                ? $recovery->successor_refresh_token_id
                : null;

            if ($successorRefreshTokenId !== null) {
                $successorRefresh = DB::table('oauth_refresh_tokens')
                    ->where('id', $successorRefreshTokenId)
                    ->lockForUpdate()
                    ->first();

                if ($successorRefresh === null
                    || $successorRefresh->revoked_at !== null
                    || ! $this->isFuture((string) $successorRefresh->expires_at)
                    || (string) $successorRefresh->access_token_id !== (string) $recovery->successor_access_token_id
                    || (string) $successorRefresh->authorization_id !== (string) $recovery->authorization_id
                    || (string) $successorRefresh->client_id !== (string) $recovery->client_id
                    || (string) $successorRefresh->user_id !== (string) $recovery->user_id
                    || (string) $successorRefresh->resource !== (string) $recovery->resource) {
                    return null;
                }
            }

            try {
                $storedScopes = $this->decodeScopes((string) $recovery->effective_scopes);
            } catch (Throwable) {
                return null;
            }

            if ($storedScopes !== $this->requestedScopes($parameters, $oldScopes)) {
                return null;
            }

            try {
                $envelope = json_decode(
                    $this->cipher->open((string) $recovery->response_ciphertext),
                    true,
                    flags: JSON_THROW_ON_ERROR,
                );
            } catch (Throwable) {
                return null;
            }

            if (! is_array($envelope)
                || ($envelope['version'] ?? null) !== 1
                || ($envelope['old_token_hash'] ?? null) !== $oldTokenHash
                || ($envelope['authorization_id'] ?? null) !== (string) $recovery->authorization_id
                || ($envelope['client_id'] ?? null) !== (string) $recovery->client_id
                || ($envelope['user_id'] ?? null) !== (string) $recovery->user_id
                || ($envelope['resource'] ?? null) !== (string) $recovery->resource
                || ($envelope['successor_access_token_id'] ?? null) !== (string) $recovery->successor_access_token_id
                || ($envelope['successor_refresh_token_id'] ?? null) !== $successorRefreshTokenId
                || ($envelope['effective_scopes'] ?? null) !== $storedScopes
                || ! is_string($envelope['response_body'] ?? null)
                || ! $this->validResponseBody(
                    $envelope['response_body'],
                    (string) $recovery->successor_access_token_id,
                    $successorRefreshTokenId,
                )) {
                return null;
            }

            DB::table('oauth_refresh_recoveries')
                ->where('old_token_hash', $oldTokenHash)
                ->where('uses_remaining', '>', 0)
                ->update([
                    'uses_remaining' => (int) $recovery->uses_remaining - 1,
                    'updated_at' => now(),
                ]);

            return $response->restorePreparedBody($envelope['response_body']);
        });
    }

    /** @param array<string, mixed> $parameters */
    private function presentedRefreshToken(array $parameters): string
    {
        $token = $parameters['refresh_token'] ?? null;
        if (! is_string($token) || $token === '' || strlen($token) > 32768) {
            throw new RuntimeException('Refresh token is unavailable for recovery.');
        }

        return $token;
    }

    /** @return array<string, mixed> */
    private function parameters(ServerRequestInterface $request): array
    {
        $body = $request->getParsedBody();
        if (is_array($body)) {
            return $body;
        }

        return is_object($body) ? get_object_vars($body) : [];
    }

    /** @param array<string, mixed> $payload */
    private function requiredString(array $payload, string $key, int $maxLength): string
    {
        $value = $payload[$key] ?? null;
        if (! is_string($value) || $value === '' || strlen($value) > $maxLength) {
            throw new RuntimeException('Refresh token payload binding is invalid.');
        }

        return $value;
    }

    /** @param array<string, mixed> $payload */
    private function requiredNumericIdentifier(array $payload, string $key): string
    {
        $value = $payload[$key] ?? null;
        if ((! is_string($value) && ! is_int($value)) || ! ctype_digit((string) $value)) {
            throw new RuntimeException('Refresh token user binding is invalid.');
        }

        return (string) $value;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return list<string>
     */
    private function payloadScopes(array $payload): array
    {
        $scopes = $payload['scopes'] ?? null;
        if (! is_array($scopes)) {
            throw new RuntimeException('Refresh token scope binding is invalid.');
        }

        return $this->normalizeScopes($scopes);
    }

    /**
     * @param  array<string, mixed>  $parameters
     * @param  list<string>  $fallback
     * @return list<string>
     */
    private function requestedScopes(array $parameters, array $fallback): array
    {
        $scope = $parameters['scope'] ?? null;
        if ($scope === null || $scope === '') {
            return $fallback;
        }
        if (! is_string($scope) || strlen($scope) > 256) {
            throw new RuntimeException('Refresh recovery scope request is invalid.');
        }

        $requested = preg_split('/\s+/', trim($scope), -1, PREG_SPLIT_NO_EMPTY);
        if (! is_array($requested)) {
            throw new RuntimeException('Refresh recovery scope request is invalid.');
        }

        return $this->normalizeScopes($requested);
    }

    /**
     * @param  ScopeEntityInterface[]  $scopes
     * @return list<string>
     */
    private function scopeIdentifiers(array $scopes): array
    {
        return $this->normalizeScopes(array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $scopes,
        ));
    }

    /**
     * @param  array<mixed>  $scopes
     * @return list<string>
     */
    private function normalizeScopes(array $scopes): array
    {
        $normalized = [];
        foreach ($scopes as $scope) {
            if (! is_string($scope) || $scope === '') {
                throw new RuntimeException('Refresh recovery scope binding is invalid.');
            }
            $normalized[] = $scope;
        }

        $normalized = array_values(array_unique($normalized));
        sort($normalized, SORT_STRING);

        return $normalized;
    }

    /** @return list<string> */
    private function decodeScopes(string $encoded): array
    {
        $decoded = json_decode($encoded, true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($decoded)) {
            throw new RuntimeException('Stored refresh recovery scopes are invalid.');
        }

        return $this->normalizeScopes($decoded);
    }

    private function oldTokenHash(string $token): string
    {
        return hash_hmac('sha256', $token, $this->keys->refreshRecoveryLookup());
    }

    private function recoverySeconds(): int
    {
        return max(5, min(60, (int) config('oauth.refresh_recovery.seconds', 30)));
    }

    private function maxRecords(): int
    {
        return max(100, min(10000, (int) config('oauth.refresh_recovery.max_records', 1000)));
    }

    private function pruneExpired(): void
    {
        DB::table('oauth_refresh_recoveries')
            ->where('recovery_expires_at', '<=', now())
            ->delete();
    }

    private function capRecords(): void
    {
        $overflow = DB::table('oauth_refresh_recoveries')->count() - $this->maxRecords();
        if ($overflow <= 0) {
            return;
        }

        $hashes = DB::table('oauth_refresh_recoveries')
            ->orderBy('created_at')
            ->limit($overflow)
            ->pluck('old_token_hash')
            ->all();

        if ($hashes !== []) {
            DB::table('oauth_refresh_recoveries')->whereIn('old_token_hash', $hashes)->delete();
        }
    }

    private function isFuture(string $timestamp): bool
    {
        $parsed = strtotime($timestamp);

        return $parsed !== false && $parsed > time();
    }

    private function validResponseBody(
        string $body,
        string $expectedAccessTokenId,
        ?string $expectedRefreshTokenId,
    ): bool {
        try {
            $decoded = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return false;
        }

        if (! is_array($decoded)
            || ($decoded['token_type'] ?? null) !== 'Bearer'
            || ! is_int($decoded['expires_in'] ?? null)
            || $decoded['expires_in'] < 0
            || ! is_string($decoded['access_token'] ?? null)
            || $decoded['access_token'] === '') {
            return false;
        }

        $parts = explode('.', $decoded['access_token']);
        if (count($parts) !== 3) {
            return false;
        }

        try {
            $accessPayload = json_decode(JWT::urlsafeB64Decode($parts[1]), true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return false;
        }

        if (! is_array($accessPayload) || ($accessPayload['jti'] ?? null) !== $expectedAccessTokenId) {
            return false;
        }

        if ($expectedRefreshTokenId === null) {
            return ! array_key_exists('refresh_token', $decoded);
        }

        $refreshToken = $decoded['refresh_token'] ?? null;
        if (! is_string($refreshToken) || $refreshToken === '') {
            return false;
        }

        $refreshPayload = $this->refreshTokens->inspect($refreshToken);

        return is_array($refreshPayload)
            && ($refreshPayload['refresh_token_id'] ?? null) === $expectedRefreshTokenId
            && ($refreshPayload['access_token_id'] ?? null) === $expectedAccessTokenId
            && ($refreshPayload['client_id'] ?? null) === (string) config('oauth.client.id');
    }
}
