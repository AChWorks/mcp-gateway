<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Application\Mcp\McpDispatchAdmission;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetConfig;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetVault;
use App\Infrastructure\Http\Api\ApiHttpTransport;
use App\Infrastructure\Http\Api\OpenApiOperationCatalog;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

/**
 * Shared application-level Target operations, independent of MCP transport.
 * A later Admin action can invoke the SAME service without a self-MCP call.
 * A new API path doesn't need a Gateway tool, code registration or version.
 */
final readonly class ArvanApiOperations
{
    // Bound the diagnostic-only decoder; if further decoding is possible,
    // redact the opaque evidence rather than spend unbounded CPU or guess.
    private const DIAGNOSTIC_URL_DECODE_PASSES = 8;

    public function __construct(
        private AccessControl $access,
        private McpDispatchAdmission $admission,
        private ActivityRecorder $activity,
        private SafeHttpClient $http,
        private ApiHttpTransport $transport,
        private OpenApiOperationCatalog $catalog,
        private ArvanApiTargetVault $vault,
    ) {}

    /** @return array<string, mixed> */
    public function catalog(
        User $user, string $targetId, int $offset = 0, int $limit = 20, ?string $search = null,
    ): array {
        $operation = 'arvan-api-catalog';
        $target = $this->target($user, $targetId, GatewayPermission::ArvanApiInspect);
        if (! $target instanceof Target) {
            return $this->failed($operation, null, 'target_not_found');
        }
        if (($reason = $this->blockedReason($user, $target, GatewayPermission::ArvanApiInspect)) !== null) {
            return $this->failed($operation, $target, $reason);
        }
        if ($offset < 0 || $limit < 1 || $limit > 100 || ($search !== null && mb_strlen($search) > 255)) {
            return $this->failed($operation, $target, 'invalid_input');
        }
        $config = $this->config($target);
        if ($config?->spec_url === null) {
            return $this->failed($operation, $target, 'catalog_unavailable', [
                'source_error_code' => 'openapi_spec_url_missing',
                'source_error_message' => 'Target has no Owner-configured OpenAPI description URL.',
                'failure_origin' => 'gateway_admission', 'failure_stage' => 'admission',
                'request_not_sent' => true, 'retry_safe' => true,
            ]);
        }

        try {
            // Public documentation retrieval never receives the API key.
            $response = $this->http->getApiDocument($config->spec_url);
            if ($response->status < 200 || $response->status >= 300) {
                return $this->failed($operation, $target, 'catalog_unavailable', [
                    'http_status' => $response->status, 'failure_origin' => 'downstream_http',
                    'failure_stage' => 'remote_http',
                ]);
            }
            $result = $this->catalog->page($this->catalog->parse($response->body), $offset, $limit, $search);
        } catch (OutboundRequestException|InvalidArgumentException $exception) {
            return $this->failed($operation, $target, 'catalog_unavailable', [
                'failure_stage' => 'operation',
                'exception_class' => $exception::class,
                'source_error_message' => $exception->getMessage(),
            ]);
        }

        $this->activity->record(CorrelationId::current(), $operation, 'success', $target);

        return ['ok' => true, 'target_id' => $target->target_id,
            'base_url' => $config->base_url,
            'operations' => $result['operations'],
            'total' => $result['total'],
            'next_offset' => $result['next_offset'],
            'note' => 'Catalog is untrusted descriptive data, not a new authorization grant. Explicit method/path permission is checked at dispatch.',
        ];
    }

    /**
     * A registered API root can execute new compatible endpoints even when
     * an OpenAPI catalog is absent/stale. Never take an absolute URL or secret
     * from the client. Caller-selected methods are classified by effect.
     *
     * @param  array<string, mixed>  $query
     * @param  array<string, mixed>  $formFields
     * @param  list<array<string,mixed>>  $formFiles
     * @return array<string, mixed>
     */
    public function execute(
        User $user, string $targetId, string $method, string $path,
        array $query = [], ?string $bodyJson = null,
        ?string $bodyText = null, ?string $contentType = null,
        array $formFields = [], array $formFiles = [], ?string $accept = null,
    ): array {
        $operation = 'arvan-api-request';
        $method = strtoupper(trim($method));
        $permission = match ($method) {
            'GET', 'HEAD', 'OPTIONS' => GatewayPermission::ArvanApiRead,
            'POST', 'PUT', 'PATCH' => GatewayPermission::ArvanApiWrite,
            'DELETE' => GatewayPermission::ArvanApiDestructive,
            default => GatewayPermission::ArvanApiUnclassified,
        };
        $target = $this->target($user, $targetId, $permission);
        if (! $target instanceof Target) {
            return $this->failed($operation, null, 'target_not_found');
        }
        if (($reason = $this->blockedReason($user, $target, $permission)) !== null) {
            return $this->failed($operation, $target, $reason);
        }
        if (! preg_match('/^[A-Z][A-Z0-9-]*$/D', $method)
            || in_array($method, ['CONNECT', 'TRACE'], true)
            || $path === '' || strlen($path) > 1024
            || ($bodyJson !== null && ! json_validate($bodyJson))) {
            return $this->failed($operation, $target, 'invalid_input');
        }

        $config = $this->config($target);
        $credential = $this->credential($target);
        if (! $config instanceof ArvanApiTargetConfig || ! $credential instanceof TargetCredential) {
            return $this->failed($operation, $target, 'credential_unavailable');
        }
        try {
            $key = $this->vault->open($target, $config, $credential);
        } catch (RuntimeException) {
            return $this->failed($operation, $target, 'credential_unavailable');
        }

        // Fresh authorization and revocation boundary AFTER reading Target and
        // credential. No token is sent if identity/grants/pause changed.
        $freshUser = User::query()->find($user->getKey());
        $currentConfig = $this->config($target);
        $currentCredential = $this->credential($target);
        if (! $freshUser instanceof User
            || $this->blockedReason($freshUser, $target, $permission) !== null
            || ! $currentConfig instanceof ArvanApiTargetConfig
            || ! $currentCredential instanceof TargetCredential
            || ! hash_equals($currentConfig->base_url, $config->base_url)
            || ! hash_equals((string) $currentCredential->encrypted_payload, (string) $credential->encrypted_payload)) {
            return $this->failed($operation, $target, 'forbidden');
        }

        // Use a stable, correlatable HTTP identity for all dispatched
        // outcomes. Never copy query, JSON body, key or raw client headers
        // into Activity. The path is selectively redacted before persistence.
        $identity = $this->apiIdentity($method, $path, $key);

        try {
            $response = $this->transport->request(
                $config->base_url, $method, $path, $query, $bodyJson,
                ['Authorization' => 'Apikey '.$key, 'Accept' => 'application/json'],
                $bodyText, $contentType, $formFields, $formFiles, $accept,
            );
        } catch (OutboundRequestException $exception) {
            $unknown = $permission !== GatewayPermission::ArvanApiRead && ! $exception->preDispatch;

            return $this->failed($operation, $target, $unknown ? 'outcome_unknown' : $exception->reason, [
                ...$exception->details,
                'failure_origin' => $exception->preDispatch ? 'gateway_admission' : 'gateway_transport',
                'request_not_sent' => $exception->preDispatch,
                'effect_unconfirmed' => $unknown,
                'retry_safe' => $exception->preDispatch,
                'api_operation' => $identity,
            ], $unknown);
        } catch (Throwable $exception) {
            return $this->failed($operation, $target, 'outcome_unknown', [
                'exception_class' => $exception::class,
                'failure_origin' => 'unknown',
                'effect_unconfirmed' => true,
                'retry_safe' => false,
                'api_operation' => $identity,
            ], true);
        }

        $status = $response->status;
        $requestId = $response->header('X-Request-ID');
        if ($requestId !== null) {
            // Provider response headers are untrusted, too. Do not echo a
            // credential (or embedded control chars) as a diagnostic ID.
            $requestId = preg_replace('/[\x00-\x1f\x7f]/', '', $requestId) ?? '';
            $requestId = mb_strcut($this->redactCredentialEcho($requestId, $key), 0, 256, 'UTF-8');
        }
        // The provider may echo the credential in reversible URL encodings.
        // Redact before either returning a response or persisting an excerpt.
        $body = $this->redactCredentialEcho($response->body, $key);
        $decoded = json_decode($body, true);
        $payload = json_last_error() === JSON_ERROR_NONE ? $decoded : $body;
        if ($status < 200 || $status >= 300) {
            $unknown = $permission !== GatewayPermission::ArvanApiRead;

            return $this->failed($operation, $target, $unknown ? 'outcome_unknown' : 'upstream_http_error', [
                'failure_origin' => 'downstream_http', 'failure_stage' => 'remote_http',
                'http_status' => $status,
                'api_operation' => [...$identity, 'provider_request_id' => $requestId],
                'source_error_details' => [
                    'provider_request_id' => $requestId,
                    'response_excerpt' => mb_substr($body, 0, 4096),
                    'response_truncated' => mb_strlen($body) > 4096,
                ],
                'effect_unconfirmed' => $unknown, 'retry_safe' => false,
            ], $unknown);
        }
        $this->activity->record(CorrelationId::current(), $operation, 'success', $target, null, [
            'http_status' => $status,
            'api_operation' => [...$identity, 'provider_request_id' => $requestId],
        ]);

        return ['ok' => true, 'target_id' => $target->target_id,
            'http_status' => $status, 'upstream_request_id' => $requestId, 'data' => $payload,
        ];
    }

    /**
     * Bounded identity for operator reconciliation; secrets, body and query
     * are never retained. Hash lets the operator compare an unredacted known
     * request path if an opaque credential-like segment was masked.
     *
     * @return array{method:string,relative_path:string,path_sha256:string}
     */
    private function apiIdentity(string $method, string $path, string $key): array
    {
        // URL paths are diagnostic data only. Never persist a segment that
        // can be URL-decoded (even repeatedly or partially) into this key.
        // Preserve unrelated path segments for reconciliation.
        $redacted = implode('/', array_map(
            fn (string $segment): string => $this->containsCredentialEcho($segment, $key)
                ? '[REDACTED]' : $segment,
            explode('/', $path),
        ));
        // A credential can itself contain a literal slash and span segments;
        // retain only the fingerprint if segment-level masking cannot cover it.
        if ($this->containsCredentialEcho($redacted, $key)) {
            $redacted = '/[REDACTED]';
        }

        return [
            'method' => $method,
            'relative_path' => $redacted,
            'path_sha256' => hash('sha256', $path),
        ];
    }

    /**
     * A URL-encoded echo might encode only one character, mix uppercase and
     * lowercase hex digits, encode '+' as space, or nest %25 several times.
     * URL decoding converges: each valid %XX reduces length, and '+' becomes
     * space at most once. Compare before each step to retain both meanings.
     */
    private function containsCredentialEcho(string $text, string $key): bool
    {
        foreach ([false, true] as $formEncoding) {
            $candidate = $text;
            for ($pass = 0; $pass < self::DIAGNOSTIC_URL_DECODE_PASSES; $pass++) {
                if (str_contains($candidate, $key)) {
                    return true;
                }
                $next = $formEncoding ? urldecode($candidate) : rawurldecode($candidate);
                if ($next === $candidate) {
                    continue 2;
                }
                $candidate = $next;
            }
            // Deeply nested encodings are not reliably diagnosable. Mask the
            // field if another percent decoding could still change it.
            if (str_contains($candidate, $key) || preg_match('/%[0-9a-f]{2}/i', $candidate) === 1) {
                return true;
            }
        }

        return false;
    }

    private function redactCredentialEcho(string $text, string $key): string
    {
        // Provider IDs and response bodies are opaque. URL decoding alone
        // misses normal JSON string escapes (e.g. \/ and \u006d), which
        // become the original key on JSON decoding. Check both forms before
        // returning provider data or recording a persistent error excerpt.
        // Only this affected field is dropped; HTTP status, safe request ID,
        // method, path fingerprint and outcome evidence remain intact.
        return $this->containsCredentialEcho($text, $key)
            || $this->jsonContainsCredentialEcho($text, $key)
                ? '[REDACTED]' : $text;
    }

    /**
     * Inspect JSON documents and also escaped JSON-string content in opaque
     * provider headers. Recursive handling covers JSON embedded as a string
     * inside another JSON response, including encoded keys as well as values.
     * Fail closed if nested decoding cannot be safely exhausted.
     */
    private function jsonContainsCredentialEcho(string $text, string $key, int $depth = 0): bool
    {
        if ($depth >= 64) {
            return true;
        }

        // The entire provider field might itself have been URL-encoded.
        // Inspect JSON before and after each bounded URL decoding layer;
        // decoded JSON keys/values are checked for URL encodings in turn.
        foreach ([false, true] as $formEncoding) {
            $candidate = $text;
            for ($pass = 0; $pass < self::DIAGNOSTIC_URL_DECODE_PASSES; $pass++) {
                if ($this->jsonCandidateContainsCredentialEcho($candidate, $key, $depth)) {
                    return true;
                }
                $next = $formEncoding ? urldecode($candidate) : rawurldecode($candidate);
                if ($next === $candidate) {
                    break;
                }
                $candidate = $next;
            }
        }

        return false;
    }

    private function jsonCandidateContainsCredentialEcho(string $text, string $key, int $depth): bool
    {
        // Inspect every serialized JSON string token before normalizing to
        // a PHP array. Associative decoding can coerce numeric property names
        // to integer keys and discard earlier duplicate properties even
        // though their original escaped content remains in the raw body.
        if (str_contains($text, '\\')) {
            $count = preg_match_all('/"(?:\\\\.|[^"\\\\])*"/s', $text, $tokens);
            if ($count === false) {
                return true;
            }
            foreach ($tokens[0] as $token) {
                $string = json_decode($token, true);
                if (json_last_error() === JSON_ERROR_NONE && is_string($string)) {
                    if ($this->containsCredentialEcho($string, $key)
                        || $this->jsonContainsCredentialEcho($string, $key, $depth + 1)) {
                        return true;
                    }
                }
            }
        }

        $decoded = json_decode($text, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return $this->jsonValueContainsCredentialEcho($decoded, $key, $depth + 1);
        }

        // A request ID is not necessarily a JSON document, but can contain
        // JSON string escapes. Decode its contents as a quoted JSON string
        // without changing the actual upstream response or request URL.
        if (! str_contains($text, '\\')) {
            return false;
        }
        $unescaped = json_decode('"'.$text.'"', true);
        if (json_last_error() === JSON_ERROR_NONE && is_string($unescaped)) {
            return $unescaped !== $text
                && ($this->containsCredentialEcho($unescaped, $key)
                    || $this->jsonContainsCredentialEcho($unescaped, $key, $depth + 1));
        }

        // Malformed/too-deep JSON or an invalid opaque string containing
        // recognizable JSON escape syntax cannot be safely inspected.
        return preg_match('/\\\\(?:u[0-9a-f]{4}|["\\\\\/bfnrt])/i', $text) === 1;
    }

    private function jsonValueContainsCredentialEcho(mixed $value, string $key, int $depth): bool
    {
        if ($depth >= 64) {
            return true;
        }
        if (is_array($value)) {
            foreach ($value as $name => $part) {
                if (is_string($name)
                    && ($this->containsCredentialEcho($name, $key)
                        || $this->jsonContainsCredentialEcho($name, $key, $depth + 1))) {
                    return true;
                }
                if ($this->jsonValueContainsCredentialEcho($part, $key, $depth + 1)) {
                    return true;
                }
            }

            return false;
        }

        return is_string($value)
            && ($this->containsCredentialEcho($value, $key)
                || $this->jsonContainsCredentialEcho($value, $key, $depth + 1));
    }

    private function target(User $user, string $targetId, GatewayPermission $permission): ?Target
    {
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            return null;
        }

        return $this->access->scopeTargets(Target::query(), $user, $permission)
            ->where('connector_type', 'arvancloud')->where('target_id', $targetId)->first();
    }

    private function blockedReason(User $user, Target $target, GatewayPermission $permission): ?string
    {
        if (! $this->access->allows($user, $permission, $target)
            || ! $this->admission->allows($user)) {
            return 'forbidden';
        }

        return TargetOperationGate::isPaused($target) ? 'target_paused' : null;
    }

    private function config(Target $target): ?ArvanApiTargetConfig
    {
        return ArvanApiTargetConfig::query()->where('target_record_id', $target->getKey())->first();
    }

    private function credential(Target $target): ?TargetCredential
    {
        return TargetCredential::query()->where('target_record_id', $target->getKey())
            ->where('connector_type', 'arvancloud')
            ->where('purpose', ArvanApiTargetVault::PURPOSE)->first();
    }

    /** @param array<string,mixed> $details
     * @return array<string,mixed>
     */
    private function failed(string $operation, ?Target $target, string $code, array $details = [], bool $unknown = false): array
    {
        $reference = CorrelationId::current();
        $this->activity->record($reference, $operation, $unknown ? 'unknown' : 'failure', $target, $code, $details);

        return ['ok' => false, 'error' => [
            'code' => $code,
            'message' => $unknown
                ? 'ArvanCloud may have applied the change; inspect the remote state before retrying.'
                : 'ArvanCloud API operation could not complete.',
            'next_step' => ($code === 'catalog_unavailable' && ($details['source_error_code'] ?? null) === 'openapi_spec_url_missing')
                ? 'Configure an optional OpenAPI description URL in this Target settings, or call arvan-api-request with an explicit approved relative path.'
                : OperationDiagnostics::nextStep($code),
            'diagnostic_reference' => $reference,
        ]];
    }
}
