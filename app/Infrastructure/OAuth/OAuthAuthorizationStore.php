<?php

namespace App\Infrastructure\OAuth;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

final class OAuthAuthorizationStore
{
    public function __construct(private readonly ClientProfileRegistry $profiles) {}

    /** @param list<string> $scopes */
    public function approve(int $userId, string $clientId, string $resource, array $scopes): string
    {
        $scopes = $this->normalizeScopes($scopes);
        $resourceHash = hash('sha256', $resource);

        return DB::transaction(function () use ($userId, $clientId, $resource, $resourceHash, $scopes): string {
            // Read and lock the *current* durable profile before touching grants.
            // A consent page/client lookup may have observed a profile before
            // Owner disable/retirement. A nonlocking pre-transaction lookup here
            // would let that stale generation create an unrevoked consent after
            // a DCR registration was permanently retired.
            //
            // Lock order: profile -> DCR registration -> user -> authorization.
            // Disable uses profile; retirement uses anchor -> profile -> DCR,
            // so no approval can write a grant after retirement commits.
            $stored = DB::table('oauth_client_profiles')->where('client_id', $clientId)
                ->lockForUpdate()->first(['profile_key', 'client_id', 'auth_strategy',
                    'generation', 'disabled_at']);
            if ($stored === null || $stored->disabled_at !== null) {
                throw new OAuthClientApprovalUnavailable('OAuth client profile is disabled or unregistered.');
            }

            if ($stored->auth_strategy === 'dcr_client_secret_post') {
                $dcr = DB::table('oauth_dcr_clients')->where('client_id', $clientId)
                    ->lockForUpdate()->first(['client_id', 'profile_key', 'retired_at']);
                if ($dcr === null || $dcr->retired_at !== null
                    || ! hash_equals((string) $stored->profile_key, (string) $dcr->profile_key)
                    || ! hash_equals((string) $stored->client_id, (string) $dcr->client_id)) {
                    throw new OAuthClientApprovalUnavailable('OAuth client registration is retired or inconsistent.');
                }
            }

            $profile = $this->profiles->active($clientId);
            if ($profile === null
                || ! hash_equals((string) $stored->client_id, (string) $profile['client_id'])
                || ! hash_equals((string) $stored->profile_key, (string) $profile['key'])
                || ! hash_equals((string) $stored->auth_strategy, (string) $profile['strategy'])
                || (int) $stored->generation !== $profile['generation']) {
                throw new OAuthClientApprovalUnavailable('OAuth client profile changed before authorization approval.');
            }

            if (DB::table('users')->where('id', $userId)
                ->where('access_enabled', true)->where('ai_access_enabled', true)
                ->lockForUpdate()->first() === null) {
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

                if ((string) $authorization->resource === $resource
                    && (string) $authorization->client_profile_key === $profile['key']
                    && (int) $authorization->client_profile_generation === $profile['generation']
                    && $storedScopes === $scopes) {
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
                'client_profile_key' => $profile['key'],
                'client_profile_generation' => $profile['generation'],
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

        $profile = $this->profiles->active($clientId)
            ?? throw new RuntimeException('OAuth client profile is disabled or unregistered.');

        $scopes = $this->normalizeScopes($scopes);
        // A consent from before channel revocation must never be reusable
        // for new authorization codes/access tokens while AI is disabled.
        if (! DB::table('users')->where('id', (int) $userIdentifier)
            ->where('access_enabled', true)->where('ai_access_enabled', true)->exists()) {
            throw new RuntimeException('This Gateway account is not authorized to connect AI clients.');
        }
        $rows = DB::table('oauth_authorizations')
            ->where('client_id', $clientId)
            ->where('client_profile_key', $profile['key'])
            ->where('client_profile_generation', $profile['generation'])
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
        $row = DB::table('oauth_authorizations')
            ->where('id', $authorizationId)
            ->whereNull('revoked_at')
            ->first(['client_id', 'client_profile_key', 'client_profile_generation']);

        return $row !== null && $this->profiles->authorizes(
            (string) $row->client_id,
            is_string($row->client_profile_key) ? $row->client_profile_key : null,
            $row->client_profile_generation === null ? null : (int) $row->client_profile_generation,
        );
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
