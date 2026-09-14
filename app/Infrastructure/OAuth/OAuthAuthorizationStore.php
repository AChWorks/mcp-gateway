<?php

namespace App\Infrastructure\OAuth;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

final class OAuthAuthorizationStore
{
    /** @param list<string> $scopes */
    public function approve(int $userId, string $clientId, string $resource, array $scopes): string
    {
        $scopes = $this->normalizeScopes($scopes);
        $resourceHash = hash('sha256', $resource);

        return DB::transaction(function () use ($userId, $clientId, $resource, $resourceHash, $scopes): string {
            if (DB::table('users')->where('id', $userId)->lockForUpdate()->first() === null) {
                throw new RuntimeException('OAuth operator no longer exists.');
            }

            $active = DB::table('oauth_authorizations')
                ->where('client_id', $clientId)
                ->where('user_id', $userId)
                ->where('resource_hash', $resourceHash)
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->get();

            foreach ($active as $authorization) {
                $storedScopes = $this->decodeScopes((string) $authorization->scopes);

                if ((string) $authorization->resource === $resource && $storedScopes === $scopes) {
                    DB::table('oauth_authorizations')->where('id', $authorization->id)->update([
                        'updated_at' => now(),
                    ]);

                    return (string) $authorization->id;
                }
            }

            if ($active->isNotEmpty()) {
                DB::table('oauth_authorizations')
                    ->whereIn('id', $active->pluck('id')->all())
                    ->update(['revoked_at' => now(), 'updated_at' => now()]);
            }

            $id = (string) Str::ulid();
            DB::table('oauth_authorizations')->insert([
                'id' => $id,
                'user_id' => $userId,
                'client_id' => $clientId,
                'resource' => $resource,
                'resource_hash' => $resourceHash,
                'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
                'revoked_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            return $id;
        });
    }

    /** @param list<string> $scopes */
    public function activeId(string $clientId, string $userIdentifier, string $resource, array $scopes): string
    {
        if (! ctype_digit($userIdentifier)) {
            throw new RuntimeException('OAuth user identifier is invalid.');
        }

        $scopes = $this->normalizeScopes($scopes);
        $rows = DB::table('oauth_authorizations')
            ->where('client_id', $clientId)
            ->where('user_id', (int) $userIdentifier)
            ->where('resource_hash', hash('sha256', $resource))
            ->whereNull('revoked_at')
            ->orderByDesc('created_at')
            ->get();

        foreach ($rows as $row) {
            $authorizedScopes = $this->decodeScopes((string) $row->scopes);
            if ((string) $row->resource === $resource && array_diff($scopes, $authorizedScopes) === []) {
                return (string) $row->id;
            }
        }

        throw new RuntimeException('No active OAuth authorization matches the token context.');
    }

    public function isActive(string $authorizationId): bool
    {
        return DB::table('oauth_authorizations')
            ->where('id', $authorizationId)
            ->whereNull('revoked_at')
            ->exists();
    }

    /**
     * @param  list<string>  $scopes
     * @return list<string>
     */
    private function normalizeScopes(array $scopes): array
    {
        $scopes = array_values(array_unique(array_map('strval', $scopes)));
        sort($scopes, SORT_STRING);

        return $scopes;
    }

    /** @return list<string> */
    private function decodeScopes(string $scopes): array
    {
        $decoded = json_decode($scopes, true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($decoded)) {
            throw new RuntimeException('Stored OAuth scopes are invalid.');
        }

        return $this->normalizeScopes($decoded);
    }
}
