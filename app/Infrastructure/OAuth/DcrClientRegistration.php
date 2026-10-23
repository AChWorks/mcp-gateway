<?php

namespace App\Infrastructure\OAuth;

use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use RuntimeException;

final class DcrClientRegistration
{
    private const REGISTRATION_LIMIT = 512;

    private const MAX_REDIRECT_URIS = 4;

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
        $clientId = 'dcr_'.bin2hex(random_bytes(24));
        $profileKey = 'dcr_'.bin2hex(random_bytes(16));
        $secret = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');

        DB::transaction(static function () use ($clientId, $profileKey, $secret, $redirectUris, $name): void {
            // Serialize registrations using one existing durable row on MariaDB.
            // This makes the global admission limit meaningful under concurrency.
            $anchor = DB::table('oauth_client_profiles')->where('profile_key', 'chatgpt')
                ->lockForUpdate()->first(['profile_key']);
            if ($anchor === null || DB::table('oauth_dcr_clients')->count() >= self::REGISTRATION_LIMIT) {
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
                'created_at' => now(),
                'updated_at' => now(),
            ]);
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
