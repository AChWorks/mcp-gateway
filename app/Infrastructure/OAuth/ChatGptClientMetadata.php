<?php

namespace App\Infrastructure\OAuth;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Support\Facades\Cache;
use RuntimeException;

final class ChatGptClientMetadata
{
    private ?ClientInterface $httpClient;

    public function __construct(?ClientInterface $httpClient = null)
    {
        $this->httpClient = $httpClient;
    }

    /** @return array<string, mixed> */
    public function metadata(bool $refresh = false): array
    {
        $clientId = (string) config('oauth.client.id');
        $cacheKey = 'oauth:chatgpt:metadata:'.hash('sha256', $clientId);

        if ($refresh) {
            Cache::forget($cacheKey);
        }

        /** @var array<string, mixed> $metadata */
        $metadata = Cache::remember(
            $cacheKey,
            max(60, (int) config('oauth.client.metadata_cache_seconds')),
            fn (): array => $this->validateMetadata($this->fetchJson($clientId), $clientId),
        );

        return $metadata;
    }

    /** @return array<string, mixed> */
    public function jwks(bool $refresh = false): array
    {
        $metadata = $this->metadata($refresh);
        $jwksUri = (string) $metadata['jwks_uri'];
        $cacheKey = 'oauth:chatgpt:jwks:'.hash('sha256', $jwksUri);

        if ($refresh) {
            Cache::forget($cacheKey);
        }

        /** @var array<string, mixed> $jwks */
        $jwks = Cache::remember(
            $cacheKey,
            max(60, (int) config('oauth.client.metadata_cache_seconds')),
            fn (): array => $this->validateJwks($this->fetchJson($jwksUri)),
        );

        return $jwks;
    }

    /** @return array<string, mixed> */
    public function jwksForKeyId(string $keyId): array
    {
        $keyId = trim($keyId);
        if ($keyId === '' || strlen($keyId) > 256) {
            throw new RuntimeException('OAuth client signing key identifier is invalid.');
        }

        $jwks = $this->jwks();
        if ($this->containsKeyId($jwks, $keyId)) {
            return $jwks;
        }

        $cooldownKey = 'oauth:chatgpt:jwks-refresh:'.hash('sha256', (string) config('oauth.client.id'));
        if (! Cache::add($cooldownKey, true, 60)) {
            return $jwks;
        }

        return $this->jwks(true);
    }

    /** @return list<string> */
    public function redirectUris(): array
    {
        /** @var list<string> $redirectUris */
        $redirectUris = $this->metadata()['redirect_uris'];

        return $redirectUris;
    }

    public function clientName(): string
    {
        return (string) $this->metadata()['client_name'];
    }

    /** @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    private function validateMetadata(array $metadata, string $clientId): array
    {
        if (($metadata['client_id'] ?? null) !== $clientId) {
            throw new RuntimeException('OAuth client metadata client_id does not match its document URL.');
        }

        $clientUrl = $this->validatedHttpsUrl($clientId, 'OAuth client ID');
        if (($clientUrl['path'] ?? '/') === '/' || isset($clientUrl['query'])) {
            throw new RuntimeException('OAuth client ID metadata URL must have a stable non-root path without a query.');
        }

        if (! is_string($metadata['client_name'] ?? null) || trim((string) $metadata['client_name']) === '') {
            throw new RuntimeException('OAuth client metadata is missing client_name.');
        }

        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (! is_array($redirectUris) || $redirectUris === []) {
            throw new RuntimeException('OAuth client metadata is missing redirect_uris.');
        }
        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri) || $redirectUri === '') {
                throw new RuntimeException('OAuth client metadata contains an invalid redirect URI.');
            }
            $this->validatedHttpsUrl($redirectUri, 'OAuth redirect URI');
        }

        if (($metadata['token_endpoint_auth_method'] ?? null) !== 'private_key_jwt') {
            throw new RuntimeException('OAuth client must use private_key_jwt.');
        }
        if (($metadata['token_endpoint_auth_signing_alg'] ?? null) !== 'RS256') {
            throw new RuntimeException('OAuth client must use RS256 client assertions.');
        }

        if (! $this->containsString($metadata['grant_types'] ?? null, 'authorization_code')
            || ! $this->containsString($metadata['grant_types'] ?? null, 'refresh_token')
            || ! $this->containsString($metadata['response_types'] ?? null, 'code')) {
            throw new RuntimeException('OAuth client metadata does not advertise the required grant/response types.');
        }

        $jwksUri = $metadata['jwks_uri'] ?? null;
        if (! is_string($jwksUri) || $jwksUri === '') {
            throw new RuntimeException('OAuth client metadata is missing jwks_uri.');
        }
        $jwksUrl = $this->validatedHttpsUrl($jwksUri, 'OAuth client JWKS URI');
        if (! $this->sameOrigin($clientUrl, $jwksUrl) || isset($jwksUrl['query'])) {
            throw new RuntimeException('OAuth client JWKS URI must remain on the client metadata origin without a query.');
        }

        $metadata['redirect_uris'] = array_values(array_unique($redirectUris));

        return $metadata;
    }

    /** @param array<string, mixed> $jwks
     * @return array<string, mixed>
     */
    private function validateJwks(array $jwks): array
    {
        $keys = $jwks['keys'] ?? null;
        if (! is_array($keys)) {
            throw new RuntimeException('OAuth client JWKS document is missing keys.');
        }

        $safeKeys = [];
        foreach ($keys as $key) {
            if (! is_array($key)
                || ($key['kty'] ?? null) !== 'RSA'
                || ($key['alg'] ?? null) !== 'RS256'
                || ! is_string($key['kid'] ?? null)
                || (string) $key['kid'] === ''
                || ! in_array($key['use'] ?? 'sig', ['sig'], true)) {
                continue;
            }
            $safeKeys[] = $key;
        }

        if ($safeKeys === []) {
            throw new RuntimeException('OAuth client JWKS contains no usable RS256 signing keys.');
        }

        return ['keys' => $safeKeys];
    }

    /** @return array<string, mixed> */
    private function fetchJson(string $url): array
    {
        $response = $this->http()->request('GET', $url, [
            'allow_redirects' => false,
            'connect_timeout' => max(1, (int) config('oauth.client.connect_timeout_seconds')),
            'timeout' => max(1, (int) config('oauth.client.request_timeout_seconds')),
            'http_errors' => false,
            'stream' => true,
            'headers' => [
                'Accept' => 'application/json',
                'User-Agent' => 'MCP-Gateway/'.app()->version(),
            ],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('OAuth client metadata endpoint returned an unexpected status.');
        }

        $contentType = strtolower(trim(explode(';', $response->getHeaderLine('Content-Type'), 2)[0]));
        if ($contentType !== 'application/json' && ! str_ends_with($contentType, '+json')) {
            throw new RuntimeException('OAuth client metadata endpoint did not return JSON content.');
        }

        $maxBytes = max(1024, (int) config('oauth.client.max_response_bytes'));
        $contentLength = $response->getHeaderLine('Content-Length');
        if ($contentLength !== '' && ctype_digit($contentLength) && (int) $contentLength > $maxBytes) {
            throw new RuntimeException('OAuth client metadata response exceeds the configured size limit.');
        }

        $stream = $response->getBody();
        $body = '';
        while (! $stream->eof()) {
            $remaining = ($maxBytes + 1) - strlen($body);
            if ($remaining <= 0) {
                throw new RuntimeException('OAuth client metadata response exceeds the configured size limit.');
            }

            $chunk = $stream->read(min(8192, $remaining));
            if ($chunk === '') {
                break;
            }

            $body .= $chunk;
            if (strlen($body) > $maxBytes) {
                throw new RuntimeException('OAuth client metadata response exceeds the configured size limit.');
            }
        }

        $decoded = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($decoded)) {
            throw new RuntimeException('OAuth client metadata response is not a JSON object.');
        }

        return $decoded;
    }

    /** @return array<string, mixed> */
    private function validatedHttpsUrl(string $url, string $label): array
    {
        $parts = parse_url($url);
        if (! is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || ! is_string($parts['host'] ?? null)
            || (string) $parts['host'] === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])) {
            throw new RuntimeException($label.' must be an HTTPS URL without userinfo or fragment.');
        }

        return $parts;
    }

    /** @param array<string, mixed> $jwks */
    private function containsKeyId(array $jwks, string $keyId): bool
    {
        foreach ((array) ($jwks['keys'] ?? []) as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $keyId) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, mixed>  $left
     * @param  array<string, mixed>  $right
     */
    private function sameOrigin(array $left, array $right): bool
    {
        $leftPort = isset($left['port']) ? (int) $left['port'] : 443;
        $rightPort = isset($right['port']) ? (int) $right['port'] : 443;

        return strtolower((string) ($left['scheme'] ?? '')) === strtolower((string) ($right['scheme'] ?? ''))
            && strcasecmp((string) ($left['host'] ?? ''), (string) ($right['host'] ?? '')) === 0
            && $leftPort === $rightPort;
    }

    private function containsString(mixed $values, string $needle): bool
    {
        return is_array($values) && in_array($needle, $values, true);
    }

    private function http(): ClientInterface
    {
        return $this->httpClient ??= new Client;
    }
}
