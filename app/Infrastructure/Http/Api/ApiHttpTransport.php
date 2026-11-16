<?php

namespace App\Infrastructure\Http\Api;

use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\Http\SafeHttpResponse;

/**
 * Connector-neutral fixed-endpoint JSON REST transport. Never accepts a
 * client-supplied destination, redirect or authentication header.
 */
final readonly class ApiHttpTransport
{
    public function __construct(private SafeHttpClient $http) {}

    /**
     * @param  array<string, mixed>  $query
     * @param  array<string, string>  $trustedHeaders  Connector-owned only.
     */
    public function request(
        string $registeredBase, string $method, string $relativePath, array $query = [],
        ?string $jsonBody = null, array $trustedHeaders = [],
    ): SafeHttpResponse {
        if ($relativePath === '' || ! str_starts_with($relativePath, '/')
            || str_starts_with($relativePath, '//')
            || preg_match('/[\\\\?#\x00-\x20\x7f]/', $relativePath) === 1) {
            throw new OutboundRequestException('invalid_input', 'API relative path is invalid.', [], true);
        }
        foreach (explode('/', $relativePath) as $segment) {
            $decoded = rawurldecode($segment);
            if ($decoded === '.' || $decoded === '..'
                || str_contains($decoded, '/') || str_contains($decoded, '\\')
                || preg_match('/[\x00-\x1f\x7f]/', $decoded) === 1) {
                throw new OutboundRequestException('invalid_input', 'API relative path contains an unsafe segment.', [], true);
            }
        }
        if (preg_match('/^https:\/\//i', $registeredBase) !== 1
            || parse_url($registeredBase, PHP_URL_QUERY) !== null
            || parse_url($registeredBase, PHP_URL_FRAGMENT) !== null) {
            throw new OutboundRequestException('invalid_input', 'Registered API endpoint is invalid.', [], true);
        }

        $url = rtrim($registeredBase, '/').$relativePath;
        if ($query !== []) {
            foreach ($query as $key => $value) {
                if ($key === '' || preg_match('/[\x00-\x1f\x7f]/', $key) === 1
                    || (! is_scalar($value) && ! is_array($value) && $value !== null)) {
                    throw new OutboundRequestException('invalid_input', 'API query parameters are invalid.', [], true);
                }
            }
        }
        // Query is sent as structured HTTP options AFTER origin validation.
        // SafeHttpClient never accepts query-bearing destinations or redirects.
        if (strlen(http_build_query($query, '', '&', PHP_QUERY_RFC3986)) > 32768) {
            throw new OutboundRequestException('invalid_input', 'API query exceeds the single-request URL budget.', [], true);
        }

        return $this->http->requestJson($method, $url, $trustedHeaders, $jsonBody, $query);
    }
}
