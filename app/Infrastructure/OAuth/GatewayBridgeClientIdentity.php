<?php

namespace App\Infrastructure\OAuth;

use Firebase\JWT\JWT;
use RuntimeException;

final class GatewayBridgeClientIdentity
{
    public const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /** @return array<string, mixed> */
    public function metadata(): array
    {
        $clientId = $this->httpsUrl((string) config('bridge.client.id'), 'Gateway OAuth client ID', 256);
        $redirectUri = $this->httpsUrl((string) config('bridge.client.redirect_uri'), 'Gateway OAuth redirect URI', 512);
        $jwksUri = $this->httpsUrl((string) config('bridge.client.jwks_uri'), 'Gateway OAuth JWKS URI', 512);

        return [
            'client_id' => $clientId,
            'client_name' => mb_substr((string) config('bridge.client.name', 'MCP Gateway'), 0, 120),
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'jwks_uri' => $jwksUri,
        ];
    }

    /** @return array{keys:list<array<string, string>>} */
    public function jwks(): array
    {
        $key = $this->publicJwk();

        return ['keys' => [$key]];
    }

    public function clientId(): string
    {
        return (string) $this->metadata()['client_id'];
    }

    public function redirectUri(): string
    {
        /** @var list<string> $redirects */
        $redirects = $this->metadata()['redirect_uris'];

        return $redirects[0];
    }

    public function assertion(string $audience): string
    {
        $audience = $this->httpsUrl($audience, 'OAuth assertion audience', 512);
        $privateKey = $this->readKey((string) config('bridge.keys.private'), 'private');
        $this->assertPrivateMatchesConfiguredPublic($privateKey);
        $jwk = $this->publicJwk();
        $now = time();
        $ttl = max(30, min(600, (int) config('bridge.client.assertion_ttl_seconds', 300)));

        return JWT::encode([
            'iss' => $this->clientId(),
            'sub' => $this->clientId(),
            'aud' => $audience,
            'iat' => $now,
            'exp' => $now + $ttl,
            'jti' => $this->base64Url(random_bytes(32)),
        ], $privateKey, 'RS256', $jwk['kid']);
    }

    /** @return array<string, string> */
    private function publicJwk(): array
    {
        $publicKey = $this->readKey((string) config('bridge.keys.public'), 'public');
        $key = openssl_pkey_get_public($publicKey);
        if ($key === false) {
            throw new RuntimeException('Gateway Bridge client public key is invalid.');
        }

        $details = openssl_pkey_get_details($key);
        if (
            ! is_array($details)
            || ! isset($details['rsa'])
            || ! is_array($details['rsa'])
            || ! is_string($details['rsa']['n'] ?? null)
            || ! is_string($details['rsa']['e'] ?? null)
        ) {
            throw new RuntimeException('Gateway Bridge client RSA public key details are unavailable.');
        }

        $kid = substr(hash('sha256', $publicKey), 0, 40);

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $kid,
            'n' => $this->base64Url($details['rsa']['n']),
            'e' => $this->base64Url($details['rsa']['e']),
        ];
    }

    private function assertPrivateMatchesConfiguredPublic(string $privateKey): void
    {
        $private = openssl_pkey_get_private($privateKey);
        $public = openssl_pkey_get_public($this->readKey((string) config('bridge.keys.public'), 'public'));
        if ($private === false || $public === false) {
            throw new RuntimeException('Gateway Bridge client signing keypair is invalid.');
        }

        $privateDetails = openssl_pkey_get_details($private);
        $publicDetails = openssl_pkey_get_details($public);
        if (
            ! is_array($privateDetails)
            || ! is_array($publicDetails)
            || ! is_string($privateDetails['key'] ?? null)
            || ! is_string($publicDetails['key'] ?? null)
            || ! hash_equals(trim($privateDetails['key']), trim($publicDetails['key']))
        ) {
            throw new RuntimeException('Gateway Bridge client signing keypair does not match.');
        }
    }

    private function readKey(string $path, string $kind): string
    {
        if ($path === '' || ! is_file($path) || ! is_readable($path)) {
            throw new RuntimeException('Gateway Bridge client '.$kind.' key is unavailable.');
        }

        $contents = file_get_contents($path);
        if (! is_string($contents) || $contents === '') {
            throw new RuntimeException('Gateway Bridge client '.$kind.' key is unavailable.');
        }

        return $contents;
    }

    private function httpsUrl(string $url, string $label, int $maxLength): string
    {
        $parts = parse_url($url);
        if (
            ! is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || (string) ($parts['host'] ?? '') === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || strlen($url) > $maxLength
        ) {
            throw new RuntimeException($label.' must be an exact HTTPS URL.');
        }

        return $url;
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
