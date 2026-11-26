<?php

namespace App\Infrastructure\Http\Api;

use App\Infrastructure\Connectors\Relay\LocalSocks5Route;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\Http\SafeHttpResponse;
use Closure;

/**
 * Connector-neutral fixed-endpoint REST transport. Never accepts a
 * client-supplied destination, redirect or authentication header.
 */
final readonly class ApiHttpTransport
{
    public function __construct(private SafeHttpClient $http) {}

    /**
     * @param  array<string, mixed>  $query
     * @param  array<string, string>  $trustedHeaders  Connector-owned only.
     * @param  array<array-key, mixed>  $formFields  Form field names to scalar/list values.
     * @param  list<mixed>  $formFiles  Inline base64 file parts (not local server paths).
     */
    public function request(
        string $registeredBase, string $method, string $relativePath, array $query = [],
        ?string $jsonBody = null, array $trustedHeaders = [],
        ?string $bodyText = null, ?string $contentType = null,
        array $formFields = [], array $formFiles = [], ?string $accept = null, ?LocalSocks5Route $relay = null, ?Closure $beforeDispatch = null,
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

        $modes = (int) ($jsonBody !== null) + (int) ($bodyText !== null)
            + (int) ($formFields !== [] || $formFiles !== []);
        if ($jsonBody !== null && ! json_validate($jsonBody)) {
            throw new OutboundRequestException('invalid_input', 'Outbound JSON body is invalid.', [], true);
        }
        if ($modes > 1) {
            throw new OutboundRequestException('invalid_input', 'Specify one API request body format.', [], true);
        }
        if ($contentType !== null && ! $this->validMediaType($contentType)) {
            throw new OutboundRequestException('invalid_input', 'API request content type is invalid.', [], true);
        }
        if ($accept !== null && ! $this->validMediaType($accept)) {
            throw new OutboundRequestException('invalid_input', 'API response accept type is invalid.', [], true);
        }
        if ($accept !== null) {
            // Only this non-authentication header is caller-selectable; host,
            // credentials and connector-owned headers remain authoritative.
            $trustedHeaders['Accept'] = $accept;
        }

        $encodedFields = null;
        $multipartParts = null;
        $rawBody = $bodyText ?? $jsonBody;
        $rawType = null;

        if ($formFields !== [] || $formFiles !== []) {
            if ($contentType !== null && ! in_array(strtolower($contentType), [
                'multipart/form-data', 'application/x-www-form-urlencoded',
            ], true)) {
                throw new OutboundRequestException('invalid_input', 'Form content type is invalid.', [], true);
            }
            if ($formFiles !== [] && strtolower($contentType ?? '') === 'application/x-www-form-urlencoded') {
                throw new OutboundRequestException('invalid_input', 'File parts require multipart/form-data.', [], true);
            }

            $parts = [];
            $fields = [];
            foreach ($formFields as $name => $value) {
                if (! is_string($name) || ! $this->validPartName($name)
                    || (! is_scalar($value) && ! is_array($value))) {
                    throw new OutboundRequestException('invalid_input', 'API form field is invalid.', [], true);
                }
                $values = is_array($value) ? $value : [$value];
                if ($values === []) {
                    continue;
                }
                $encoded = [];
                foreach ($values as $element) {
                    if (! is_scalar($element)) {
                        throw new OutboundRequestException('invalid_input', 'API form value is invalid.', [], true);
                    }
                    $encoded[] = is_bool($element) ? ($element ? 'true' : 'false') : (string) $element;
                    $parts[] = ['name' => $name, 'contents' => end($encoded)];
                }
                $fields[$name] = is_array($value) ? $encoded : $encoded[0];
            }

            foreach ($formFiles as $file) {
                if (! is_array($file)
                    || ! is_string($file['name'] ?? null) || ! $this->validPartName($file['name'])
                    || ! is_string($file['filename'] ?? null) || ! $this->validPartName($file['filename'])
                    || ! is_string($file['content_base64'] ?? null)
                    || ! $this->validMediaType($file['content_type'] ?? 'application/octet-stream')) {
                    throw new OutboundRequestException('invalid_input', 'API upload part is invalid.', [], true);
                }
                $bytes = base64_decode($file['content_base64'], true);
                if ($bytes === false) {
                    throw new OutboundRequestException('invalid_input', 'API upload part base64 is invalid.', [], true);
                }
                $parts[] = [
                    'name' => $file['name'], 'contents' => $bytes, 'filename' => $file['filename'],
                    'headers' => ['Content-Type' => $file['content_type'] ?? 'application/octet-stream'],
                ];
            }
            if ($formFiles !== [] || strtolower($contentType ?? '') === 'multipart/form-data') {
                $multipartParts = $parts;
            } else {
                $encodedFields = $fields;
            }
        } elseif ($rawBody !== null) {
            if ($bodyText !== null && $contentType === null) {
                throw new OutboundRequestException('invalid_input', 'Raw API request body requires a content type.', [], true);
            }
            $rawType = $contentType ?? 'application/json';
            if ($jsonBody !== null && strtolower($rawType) === 'application/json') {
                $rawType = 'application/json';
            }
        } elseif ($contentType !== null) {
            throw new OutboundRequestException('invalid_input', 'Content type requires a request body.', [], true);
        }

        // Body encoding changes only the payload. Every format has one
        // dispatch boundary with the same trusted destination and route.
        return $this->http->requestApi(
            $method, $url, $trustedHeaders, $query,
            rawBody: $rawBody, contentType: $rawType,
            formFields: $encodedFields, multipartParts: $multipartParts, relay: $relay, beforeDispatch: $beforeDispatch,
        );
    }

    private function validMediaType(mixed $type): bool
    {
        return is_string($type) && strlen($type) <= 255
            && preg_match('/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:;[ \t]*[a-z0-9!#$&^_.+-]+=[a-z0-9!#$&^_.+-]+)*$/iD', $type) === 1;
    }

    private function validPartName(string $value): bool
    {
        return $value !== '' && strlen($value) <= 255
            && ! str_contains($value, '/') && ! str_contains($value, '\\')
            && preg_match('/[\x00-\x1f\x7f]/', $value) !== 1;
    }
}
