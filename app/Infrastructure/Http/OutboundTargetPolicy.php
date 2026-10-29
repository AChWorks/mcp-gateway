<?php

namespace App\Infrastructure\Http;

final class OutboundTargetPolicy
{
    public function __construct(
        private readonly DnsResolver $dns,
        private readonly PublicIpAddressPolicy $ipPolicy,
    ) {}

    public function canonicalBaseUrl(string $url): string
    {
        $parts = $this->parseHttpsUrl($url, 1024);
        $canonical = $this->buildUrl($parts, true);
        $this->resolvePublicAddresses($parts['host']);

        return $canonical;
    }

    /**
     * Narrow exception for a ChatGPT-issued expiring file download URL.
     *
     * General remote endpoint validation deliberately prohibits queries.
     * Here, query parameters are opaque bearer-like tokens and MUST remain
     * private and unmodified. Only one exact trusted file origin is eligible;
     * the existing DNS/public-IP pinning, TLS and no-redirect rules still apply.
     */
    public function validateChatgptFileUrl(string $url, ?int $deadlineNs = null): ValidatedOutboundUrl
    {
        if ($url === '' || strlen($url) > 8192 || preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            throw new UnsafeOutboundTarget('Private file URL is invalid.', 'invalid_url');
        }
        $parts = parse_url($url);
        if (! is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || strtolower((string) ($parts['host'] ?? '')) !== 'files.oaiusercontent.com'
            || ! is_string($parts['path'] ?? null) || $parts['path'] === ''
            || isset($parts['port']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['fragment'])) {
            throw new UnsafeOutboundTarget('Private file URL origin is not allowed.', 'origin_not_allowed');
        }
        // Reuse the normal strict path/canonical-host and DNS checks, without
        // interpreting signed query bytes as a new origin, or logging them.
        $base = $this->validate('https://files.oaiusercontent.com'.$parts['path'], 8192, $deadlineNs);

        return new ValidatedOutboundUrl(
            $base->url.(isset($parts['query']) ? '?'.$parts['query'] : ''),
            $base->host, $base->port, $base->addresses,
        );
    }

    public function validate(string $url, int $maxLength = 2048, ?int $deadlineNs = null): ValidatedOutboundUrl
    {
        $parts = $this->parseHttpsUrl($url, $maxLength);
        $canonical = $this->buildUrl($parts, false);
        $addresses = $this->resolvePublicAddresses($parts['host'], $deadlineNs);

        return new ValidatedOutboundUrl(
            $canonical,
            $parts['host'],
            $parts['port'] ?? 443,
            $addresses,
        );
    }

    public function appendPath(string $canonicalBaseUrl, string $absolutePath): string
    {
        if ($absolutePath === '' || $absolutePath[0] !== '/' || str_contains($absolutePath, '?') || str_contains($absolutePath, '#')) {
            throw new UnsafeOutboundTarget('Outbound metadata path is invalid.', 'invalid_path');
        }

        $parts = $this->parseHttpsUrl($canonicalBaseUrl, 1024);
        $basePath = rtrim($parts['path'], '/');
        $parts['path'] = $basePath.$absolutePath;

        return $this->buildUrl($parts, false);
    }

    public function assertSameOrigin(string $url, string $canonicalBaseUrl): ValidatedOutboundUrl
    {
        $candidate = $this->validate($url);
        $base = $this->parseHttpsUrl($canonicalBaseUrl, 1024);
        $basePort = $base['port'] ?? 443;

        if (! hash_equals($base['host'], $candidate->host) || $basePort !== $candidate->port) {
            throw new UnsafeOutboundTarget('Outbound metadata points to a different origin.', 'origin_mismatch');
        }

        return $candidate;
    }

    /**
     * @return array{host:string,port?:int,path:string}
     */
    private function parseHttpsUrl(string $url, int $maxLength): array
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > $maxLength || preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            throw new UnsafeOutboundTarget('Outbound target URL is invalid.', 'invalid_url');
        }

        $parts = parse_url($url);
        if (! is_array($parts)) {
            throw new UnsafeOutboundTarget('Outbound target URL is malformed.', 'invalid_url');
        }

        if (strtolower((string) ($parts['scheme'] ?? '')) !== 'https') {
            throw new UnsafeOutboundTarget('Outbound targets must use HTTPS.', 'https_required');
        }
        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new UnsafeOutboundTarget('Outbound target URL contains unsupported components.', 'unsupported_url_components');
        }

        $host = strtolower(trim((string) ($parts['host'] ?? ''), '[]'));
        if ($host === '' || strlen($host) > 253 || preg_match('/[^\x20-\x7e]/', $host) === 1) {
            throw new UnsafeOutboundTarget('Outbound target host is invalid.', 'invalid_host');
        }

        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            $host = rtrim($host, '.');
            if ($host === '' || ! $this->validDnsName($host)) {
                throw new UnsafeOutboundTarget('Outbound target host is invalid.', 'invalid_host');
            }
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        if ($port !== null && $port < 1) {
            throw new UnsafeOutboundTarget('Outbound target port is invalid.');
        }

        $path = (string) ($parts['path'] ?? '');
        if ($path !== '') {
            $decodedPath = rawurldecode($path);
            if (str_contains($decodedPath, '\\') || preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $decodedPath) === 1) {
                throw new UnsafeOutboundTarget('Outbound target path is ambiguous.', 'invalid_path');
            }
            if ($path[0] !== '/') {
                throw new UnsafeOutboundTarget('Outbound target path is invalid.', 'invalid_path');
            }
        }

        return array_filter([
            'host' => $host,
            'port' => $port,
            'path' => $path,
        ], static fn (mixed $value): bool => $value !== null);
    }

    private function validDnsName(string $host): bool
    {
        $labels = explode('.', $host);
        if (count($labels) < 2) {
            return false;
        }

        foreach ($labels as $label) {
            if ($label === '' || strlen($label) > 63 || preg_match('/^(?!-)[a-z0-9-]+(?<!-)$/', $label) !== 1) {
                return false;
            }
        }

        return true;
    }

    /** @param array{host:string,port?:int,path:string} $parts */
    private function buildUrl(array $parts, bool $base): string
    {
        $host = str_contains($parts['host'], ':') ? '['.$parts['host'].']' : $parts['host'];
        $port = isset($parts['port']) && $parts['port'] !== 443 ? ':'.$parts['port'] : '';
        $path = $parts['path'];
        if ($base) {
            $path = rtrim($path, '/');
        }

        return 'https://'.$host.$port.$path;
    }

    /** @return list<string> */
    private function resolvePublicAddresses(string $host, ?int $deadlineNs = null): array
    {
        $addresses = $this->dns->resolve($host, $deadlineNs);
        if ($addresses === []) {
            throw new UnsafeOutboundTarget('Outbound target host did not resolve to an address.', 'dns_no_address');
        }

        foreach ($addresses as $address) {
            if (! $this->ipPolicy->isPublic($address)) {
                throw new UnsafeOutboundTarget('Outbound target resolved to a non-public address.', 'dns_non_public', $address);
            }
        }

        return $addresses;
    }
}
