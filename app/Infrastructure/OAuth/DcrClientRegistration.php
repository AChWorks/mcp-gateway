<?php

namespace App\Infrastructure\OAuth;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use InvalidArgumentException;
use RuntimeException;

final class DcrClientRegistration
{
    private const REGISTRATION_LIMIT = 512;

    private const MAX_REDIRECT_URIS = 4;

    // Count successful admissions globally, not invalid or malformed requests.
    // With 24-hour orphan reclamation this bounds distributed pre-consent abuse.
    private const MAX_ADMISSIONS_PER_HOUR = 15;

    private const GLOBAL_ADMISSION_KEY = 'oauth-dcr:successful-registrations:global';

    private const UNCONSENTED_GRACE_HOURS = 24;

    private const RECLAIM_BATCH_SIZE = 8;

    /**
     * RFC 7591 public registration of an authenticated, PKCE-required client.
     * The registration endpoint does not grant access to any Gateway account.
     *
     * @param  array<string, mixed>  $metadata
     * @return array<string, mixed>
     */
    public function register(array $metadata): array
    {
        if (config('oauth.dcr.registration_enabled') !== true) {
            throw new InvalidArgumentException('Dynamic client registration is disabled.');
        }

        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (! is_array($redirectUris) || ! array_is_list($redirectUris)
            || $redirectUris === [] || count($redirectUris) > self::MAX_REDIRECT_URIS) {
            throw new InvalidArgumentException('Unsupported OAuth redirect URIs.');
        }

        foreach ($redirectUris as $uri) {
            if (! is_string($uri) || strlen($uri) > 2048 || ! $this->trustedChatGptCallback($uri)) {
                throw new InvalidArgumentException('Unsupported OAuth redirect URI.');
            }
        }
        if (count(array_unique($redirectUris)) !== count($redirectUris)) {
            throw new InvalidArgumentException('Duplicate OAuth redirect URI.');
        }

        if (($metadata['token_endpoint_auth_method'] ?? 'client_secret_post') !== 'client_secret_post') {
            throw new InvalidArgumentException('Supported token authentication method is client_secret_post.');
        }
        if (! $this->permittedSet($metadata['grant_types'] ?? null, ['authorization_code', 'refresh_token'])) {
            throw new InvalidArgumentException('Unsupported OAuth grant types.');
        }
        if (! $this->permittedSet($metadata['response_types'] ?? null, ['code'])) {
            throw new InvalidArgumentException('Unsupported OAuth response types.');
        }

        $requestedName = $metadata['client_name'] ?? 'ChatGPT';
        if (! is_string($requestedName) || trim($requestedName) === ''
            || mb_strlen($requestedName) > 160) {
            throw new InvalidArgumentException('Invalid OAuth client name.');
        }

        // Redirects are strictly ChatGPT-owned, but untrusted registration metadata
        // must never control the consent UI's trusted-looking application name.
        $name = 'ChatGPT (DCR)';

        // Cheap preliminary rejection keeps already-exhausted distributed
        // traffic off the MariaDB admission lock. The *authoritative* repeat
        // under that lock is still required to prevent quota races.
        $this->assertGlobalAdmissionAvailable();
        $clientId = 'dcr_'.bin2hex(random_bytes(24));
        $profileKey = 'dcr_'.bin2hex(random_bytes(16));
        $secret = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');

        DB::transaction(function () use ($clientId, $profileKey, $secret, $redirectUris, $name): void {
            // Serialize registrations using one existing durable row on MariaDB.
            // This makes the global admission limit meaningful under concurrency.
            $anchor = DB::table('oauth_client_profiles')->where('profile_key', 'chatgpt')
                ->lockForUpdate()->first(['profile_key']);
            if ($anchor === null) {
                throw new RuntimeException('OAuth client registration capacity is unavailable.');
            }

            // Check the shared success budget *before* any capacity-recovery
            // effects. Rate-rejected requests must never retire even an orphan.
            // The admission anchor serializes the check and subsequent hit.
            $this->assertGlobalAdmissionAvailable();

            if (DB::table('oauth_dcr_clients')->whereNull('retired_at')->count() >= self::REGISTRATION_LIMIT) {
                $this->reclaimExpiredNeverAuthorizedRegistrations();
            }

            if (DB::table('oauth_dcr_clients')->whereNull('retired_at')->count() >= self::REGISTRATION_LIMIT) {
                throw new RuntimeException('OAuth client registration capacity is unavailable.');
            }

            DB::table('oauth_client_profiles')->insert([
                'profile_key' => $profileKey,
                'client_id' => $clientId,
                'auth_strategy' => 'dcr_client_secret_post',
                'generation' => 1,
                'disabled_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            DB::table('oauth_dcr_clients')->insert([
                'client_id' => $clientId,
                'profile_key' => $profileKey,
                'secret_hash' => hash('sha256', $secret),
                'redirect_uris' => json_encode($redirectUris, JSON_THROW_ON_ERROR),
                'display_name' => trim($name),
                'ever_authorized_at' => null,
                'auto_retirement_eligible' => true,
                'retired_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            // A rare DB commit failure may conservatively charge an attempt.
            // Never admit uncounted registrations if the limiter store fails.
            RateLimiter::hit(self::GLOBAL_ADMISSION_KEY, 3600);
        });

        return [
            'client_id' => $clientId,
            'client_secret' => $secret,
            'client_id_issued_at' => time(),
            'client_secret_expires_at' => 0,
            'client_name' => trim($name),
            'redirect_uris' => $redirectUris,
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'client_secret_post',
        ];
    }

    private function assertGlobalAdmissionAvailable(): void
    {
        if (RateLimiter::tooManyAttempts(self::GLOBAL_ADMISSION_KEY, self::MAX_ADMISSIONS_PER_HOUR)) {
            throw new DcrRegistrationRateLimited(max(
                1, RateLimiter::availableIn(self::GLOBAL_ADMISSION_KEY),
            ));
        }
    }

    /**
     * Capacity-pressure recovery only: an old registration that has NEVER
     * obtained any authorization can be retired without revoking a consent.
     *
     * Keep the exact admission -> profile -> DCR lock order. OAuth consent
     * locks profile -> DCR; after waiting for that lock, use a CURRENT
     * (FOR UPDATE) grant read, not the earlier MariaDB repeatable-read
     * snapshot, before permanently fencing the pending identity.
     */
    private function reclaimExpiredNeverAuthorizedRegistrations(): void
    {
        $cutoff = now()->subHours(self::UNCONSENTED_GRACE_HOURS);
        $candidates = DB::table('oauth_dcr_clients as clients')
            ->whereNull('clients.retired_at')
            ->where('clients.auto_retirement_eligible', true)
            ->whereNull('clients.ever_authorized_at')
            ->where('clients.created_at', '<=', $cutoff)
            ->whereNotExists(static function ($query): void {
                $query->selectRaw('1')->from('oauth_authorizations as grants')
                    ->whereColumn('grants.client_id', 'clients.client_id');
            })
            ->orderBy('clients.created_at')
            ->limit(self::RECLAIM_BATCH_SIZE)
            ->get(['clients.client_id', 'clients.profile_key']);

        foreach ($candidates as $candidate) {
            $profile = DB::table('oauth_client_profiles')
                ->where('profile_key', $candidate->profile_key)
                ->lockForUpdate()->first(['client_id', 'auth_strategy', 'generation', 'disabled_at']);
            $client = DB::table('oauth_dcr_clients')
                ->where('profile_key', $candidate->profile_key)
                ->where('created_at', '<=', $cutoff)
                ->lockForUpdate()->first(['client_id', 'retired_at', 'ever_authorized_at', 'auto_retirement_eligible']);

            if ($profile === null || $client === null
                || $profile->auth_strategy !== 'dcr_client_secret_post'
                || $profile->client_id !== $candidate->client_id
                || $client->client_id !== $candidate->client_id
                || $client->retired_at !== null
                || $client->ever_authorized_at !== null
                || ! (bool) $client->auto_retirement_eligible
                || DB::table('oauth_authorizations')->where('client_id', $candidate->client_id)
                    ->lockForUpdate()->first(['id']) !== null) {
                continue;
            }

            if ($profile->disabled_at === null) {
                DB::table('oauth_client_profiles')->where('profile_key', $candidate->profile_key)
                    ->update([
                        'generation' => (int) $profile->generation + 1,
                        'disabled_at' => now(),
                        'updated_at' => now(),
                    ]);
            }

            // Keep the immutable client/secret digest and audit histories.
            // Retired client IDs cannot ever be reused or re-enabled.
            DB::table('oauth_dcr_clients')->where('profile_key', $candidate->profile_key)
                ->whereNull('retired_at')
                ->update(['retired_at' => now(), 'auto_retirement_eligible' => false, 'updated_at' => now()]);
        }
    }

    private function trustedChatGptCallback(string $uri): bool
    {
        return $uri === 'https://chatgpt.com/connector_platform_oauth_redirect'
            || preg_match('~^https://chatgpt[.]com/connector/oauth/[A-Za-z0-9_-]{1,128}$~D', $uri) === 1;
    }

    /** @param list<string> $allowed */
    private function permittedSet(mixed $value, array $allowed): bool
    {
        return $value === null
            || (is_array($value) && array_is_list($value) && $value !== []
                && count(array_filter($value, 'is_string')) === count($value)
                && count($value) <= count($allowed)
                && count(array_unique($value, SORT_REGULAR)) === count($value)
                && array_diff($value, $allowed) === []);
    }
}
