<?php

namespace App\Infrastructure\OAuth;

use Firebase\JWT\JWK;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

final class ClientProfileRegistry
{
    /**
     * Each configured profile is a reviewed application, never metadata selected from
     * an incoming OAuth request. The database binds key, protocol ID and auth method
     * immutably, and stores the revocation generation across deployments.
     *
     * @return array<string, array{key:string,client_id:string,display_name:string,strategy:string,enabled:bool,redirect_uris:list<string>,jwks:array<string,mixed>}>
     */
    public function configured(): array
    {
        $raw = config('oauth.client_profiles');
        if (! is_array($raw) || $raw === []) {
            throw new RuntimeException('OAuth client profile allowlist is missing.');
        }

        $profiles = [];
        $ids = [];
        foreach ($raw as $key => $value) {
            if (! is_string($key) || preg_match('/^[a-z][a-z0-9_-]{0,47}$/D', $key) !== 1 || ! is_array($value)) {
                throw new RuntimeException('Invalid OAuth client profile key or configuration.');
            }

            $clientId = $value['client_id'] ?? null;
            $strategy = $value['strategy'] ?? null;
            $name = $value['display_name'] ?? null;
            if (! is_string($clientId) || strlen($clientId) > 255 || ! $this->safeClientId($clientId)
                || ! is_string($name) || trim($name) === '' || mb_strlen($name) > 160
                || ! in_array($strategy, ['cimd_private_key_jwt', 'pinned_private_key_jwt'], true)
                || ! is_bool($value['enabled'] ?? null)) {
                throw new RuntimeException('OAuth client profile identity or authentication contract is invalid.');
            }
            if (isset($ids[$clientId])) {
                throw new RuntimeException('Duplicate OAuth client ID across supported profiles.');
            }
            $ids[$clientId] = true;

            $redirectUris = $value['redirect_uris'] ?? [];
            $jwks = $value['jwks'] ?? [];
            if ($strategy === 'pinned_private_key_jwt') {
                if (! is_array($redirectUris) || $redirectUris === [] || count($redirectUris) > 16
                    || ! is_array($jwks) || ! is_array($jwks['keys'] ?? null) || $jwks['keys'] === []) {
                    throw new RuntimeException('Pinned OAuth client profile is missing redirect URIs or JWKS.');
                }
                foreach ($redirectUris as $redirectUri) {
                    if (! is_string($redirectUri) || ! $this->safeRedirectUri($redirectUri)) {
                        throw new RuntimeException('Pinned OAuth client redirect URI is unsafe.');
                    }
                }
                if (! array_is_list($jwks['keys']) || count($jwks['keys']) > 16) {
                    throw new RuntimeException('Pinned OAuth client JWKS must contain at most 16 ordered keys.');
                }

                $keyIds = [];
                foreach ($jwks['keys'] as $keyEntry) {
                    if (! is_array($keyEntry) || ($keyEntry['kty'] ?? null) !== 'RSA'
                        || ($keyEntry['alg'] ?? null) !== 'RS256'
                        || ! is_string($keyEntry['kid'] ?? null)
                        || $keyEntry['kid'] === ''
                        || strlen($keyEntry['kid']) > 256
                        || ($keyEntry['use'] ?? 'sig') !== 'sig') {
                        throw new RuntimeException('Pinned OAuth client signing key is unsupported.');
                    }

                    if (array_intersect(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'], array_keys($keyEntry)) !== []) {
                        throw new RuntimeException('Pinned OAuth client JWKS must contain public key material only.');
                    }

                    if (! $this->validRsaPublicComponents($keyEntry)) {
                        throw new RuntimeException('Pinned OAuth client RSA signing key components are invalid.');
                    }

                    if (isset($keyIds[$keyEntry['kid']])) {
                        throw new RuntimeException('Pinned OAuth client signing key IDs must be unique.');
                    }
                    $keyIds[$keyEntry['kid']] = true;
                }

                // Use the runtime JWT verifier's JWK parser during startup health.
                // Header-only validation is insufficient: RSA n/e may be absent
                // or unparseable, leaving an enabled profile unable to authenticate.
                try {
                    $keys = JWK::parseKeySet($jwks);
                } catch (Throwable $exception) {
                    throw new RuntimeException('Pinned OAuth client signing key is not a usable RSA/RS256 public key.', previous: $exception);
                }

                if (count($keys) !== count($keyIds)) {
                    throw new RuntimeException('Pinned OAuth client JWKS contains an ambiguous or unsupported key.');
                }

                foreach ($keys as $parsedKey) {
                    $material = $parsedKey->getKeyMaterial();
                    $details = $material instanceof \OpenSSLAsymmetricKey
                        ? openssl_pkey_get_details($material)
                        : false;
                    if ($parsedKey->getAlgorithm() !== 'RS256'
                        || ! is_array($details)
                        || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA
                        || ($details['bits'] ?? 0) < 2048) {
                        throw new RuntimeException('Pinned OAuth client signing key must be a valid RSA/RS256 public key of at least 2048 bits.');
                    }
                }
            } elseif ($key !== 'chatgpt' || $clientId !== (string) config('oauth.client.id')) {
                // Until another CIMD implementation has been security-reviewed, the
                // original fixed ChatGPT metadata/JWKS path is the only remote fetcher.
                throw new RuntimeException('Unreviewed remote OAuth client metadata source.');
            }

            $profiles[$key] = [
                'key' => $key,
                'client_id' => $clientId,
                'display_name' => $name,
                'strategy' => $strategy,
                'enabled' => $value['enabled'],
                'redirect_uris' => array_values($redirectUris),
                'jwks' => $jwks,
            ];
        }

        return $profiles;
    }

    /**
     * Deployment/health preflight. Unexpected live registry rows are never
     * silently reassigned or revived by a changed configuration file.
     */
    public function assertReady(): void
    {
        $configured = $this->configured();
        $registered = DB::table('oauth_client_profiles')->get()->keyBy('profile_key');
        $activeCount = 0;

        foreach ($configured as $profile) {
            $stored = $registered->get($profile['key']);
            if ($stored === null) {
                if ($profile['enabled']) {
                    throw new RuntimeException('Configured OAuth client profile requires explicit registration.');
                }

                continue;
            }
            if (! hash_equals((string) $stored->client_id, $profile['client_id'])
                || ! hash_equals((string) $stored->auth_strategy, $profile['strategy'])) {
                throw new RuntimeException('OAuth client profile identity differs from durable registration.');
            }
            if (! $profile['enabled'] && $stored->disabled_at === null) {
                throw new RuntimeException('Disable the OAuth client profile durably before changing its configuration.');
            }
            if ($profile['enabled'] && $stored->disabled_at === null) {
                $activeCount++;
            }
        }

        foreach ($registered as $key => $stored) {
            if (! isset($configured[$key]) && $stored->disabled_at === null) {
                throw new RuntimeException('Revoke the registered OAuth client profile before removing it from configuration.');
            }
        }

        if ($activeCount === 0) {
            throw new RuntimeException('There is no active, explicitly supported OAuth client profile.');
        }
    }

    /** @return array<string, mixed>|null */
    public function active(string $clientId): ?array
    {
        foreach ($this->configured() as $profile) {
            if (! hash_equals($profile['client_id'], $clientId)) {
                continue;
            }

            if (! $profile['enabled']) {
                return null;
            }

            $stored = DB::table('oauth_client_profiles')
                ->where('profile_key', $profile['key'])
                ->first(['client_id', 'auth_strategy', 'generation', 'disabled_at']);

            if ($stored === null
                || $stored->disabled_at !== null
                || ! hash_equals((string) $stored->client_id, $clientId)
                || ! hash_equals((string) $stored->auth_strategy, $profile['strategy'])) {
                return null;
            }

            return [...$profile, 'generation' => (int) $stored->generation];
        }

        return null;
    }

    public function authorizes(string $clientId, ?string $profileKey, ?int $generation): bool
    {
        if ($profileKey === null || $generation === null) {
            return false;
        }

        $profile = $this->active($clientId);

        return $profile !== null
            && hash_equals($profile['key'], $profileKey)
            && $profile['generation'] === $generation;
    }

    /**
     * Explicit operator action for a profile already defined in reviewed config.
     * Registration never silently rebinds an existing profile or revives revocations.
     */
    public function register(string $key): void
    {
        $profile = $this->configured()[$key] ?? null;
        if ($profile === null || ! $profile['enabled']) {
            throw new InvalidArgumentException('No enabled, configured OAuth client profile with that key.');
        }

        DB::transaction(static function () use ($profile): void {
            $other = DB::table('oauth_client_profiles')
                ->where('client_id', $profile['client_id'])
                ->where('profile_key', '!=', $profile['key'])
                ->exists();
            if ($other) {
                throw new RuntimeException('OAuth client identity is already registered to another profile.');
            }

            $existing = DB::table('oauth_client_profiles')
                ->where('profile_key', $profile['key'])->lockForUpdate()->first();
            if ($existing !== null) {
                if ($existing->client_id !== $profile['client_id'] || $existing->auth_strategy !== $profile['strategy']
                    || $existing->disabled_at !== null) {
                    throw new RuntimeException('OAuth client profile identity is immutable or revoked.');
                }

                return;
            }

            DB::table('oauth_client_profiles')->insert([
                'profile_key' => $profile['key'],
                'client_id' => $profile['client_id'],
                'auth_strategy' => $profile['strategy'],
                'generation' => 1,
                'disabled_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        });
    }

    /**
     * Durable revocation invalidates every earlier authorization/token generation.
     * Re-registration cannot re-enable a revoked profile; a separate explicit and
     * reviewed re-enable path may be added with monotonically increasing generation.
     */
    public function disable(string $key): void
    {
        DB::transaction(static function () use ($key): void {
            $profile = DB::table('oauth_client_profiles')->where('profile_key', $key)
                ->lockForUpdate()->first();
            if ($profile === null) {
                throw new InvalidArgumentException('Unknown registered OAuth client profile.');
            }
            if ($profile->disabled_at !== null) {
                return;
            }

            DB::table('oauth_client_profiles')->where('profile_key', $key)->update([
                'generation' => (int) $profile->generation + 1,
                'disabled_at' => now(),
                'updated_at' => now(),
            ]);
        });
    }

    /**
     * Explicit re-enablement retains the generation bumped at disable, so every
     * previously issued code/refresh/access token remains invalid permanently.
     */
    public function enable(string $key): void
    {
        $configured = $this->configured()[$key] ?? null;
        if ($configured === null || ! $configured['enabled']) {
            throw new InvalidArgumentException('OAuth client profile is not enabled in reviewed configuration.');
        }

        DB::transaction(static function () use ($key, $configured): void {
            $profile = DB::table('oauth_client_profiles')->where('profile_key', $key)
                ->lockForUpdate()->first();
            if ($profile === null || $profile->disabled_at === null) {
                throw new RuntimeException('OAuth client profile is not in the disabled state.');
            }
            if (! hash_equals((string) $profile->client_id, $configured['client_id'])
                || ! hash_equals((string) $profile->auth_strategy, $configured['strategy'])) {
                throw new RuntimeException('OAuth client profile identity is immutable.');
            }

            DB::table('oauth_client_profiles')->where('profile_key', $key)->update([
                'disabled_at' => null,
                'updated_at' => now(),
            ]);
        });
    }

    /** @param array<string, mixed> $key */
    private function validRsaPublicComponents(array $key): bool
    {
        $modulus = $this->decodeCanonicalRsaComponent($key['n'] ?? null, 4096);
        $exponent = $this->decodeCanonicalRsaComponent($key['e'] ?? null, 16);

        return $modulus !== null && strlen($modulus) >= 256
            && ord($modulus[0]) !== 0
            && (ord($modulus[strlen($modulus) - 1]) & 1) === 1
            && $exponent !== null && strlen($exponent) <= 8
            && ord($exponent[0]) !== 0
            && (ord($exponent[strlen($exponent) - 1]) & 1) === 1
            && (strlen($exponent) > 1 || ord($exponent[0]) >= 3);
    }

    private function decodeCanonicalRsaComponent(mixed $encoded, int $maxLength): ?string
    {
        if (! is_string($encoded) || $encoded === '' || strlen($encoded) > $maxLength
            || preg_match('/^[A-Za-z0-9_-]+$/D', $encoded) !== 1) {
            return null;
        }

        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($decoded === false || $decoded === ''
            || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $encoded) {
            return null;
        }

        return $decoded;
    }

    private function safeClientId(string $url): bool
    {
        $parts = parse_url($url);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && is_string($parts['host'] ?? null)
            && preg_match('/^[a-z0-9][a-z0-9.-]+$/D', (string) $parts['host']) === 1
            && ! filter_var($parts['host'], FILTER_VALIDATE_IP)
            && ! isset($parts['user']) && ! isset($parts['pass'])
            && ! isset($parts['fragment']) && ! isset($parts['query']) && ! isset($parts['port'])
            && $parts['path'] !== '/' && $parts['path'] !== '';
    }

    private function safeRedirectUri(string $url): bool
    {
        $parts = parse_url($url);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && is_string($parts['host'] ?? null) && $parts['host'] !== ''
            && ! isset($parts['user']) && ! isset($parts['pass']) && ! isset($parts['fragment']);
    }
}
