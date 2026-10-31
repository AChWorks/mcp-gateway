<?php

namespace App\Infrastructure\Mcp;

use App\Domain\Targets\Target;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use JsonException;

/**
 * Outbound request-only MCP wire transport for the AChrix-compatible
 * Streamable HTTP 2026-07-28 profile. No session, polling, replay or provider
 * authentication lifecycle is owned here.
 *
 * The calling connector MUST enforce the Gateway user/client/Target/operation
 * policy and acquire the real product-user credential before each use.
 */
final readonly class RequestOnlyMcpClient
{
    public const PROTOCOL_VERSION = '2026-07-28';

    public const MAX_REQUEST_BYTES = 65536;

    public const MAX_RESPONSE_BYTES = 1048576;

    public const MAX_CATALOG_PAGE_TOOLS = 128;

    public function __construct(private SafeHttpClient $http) {}

    /** @return array<string, mixed> */
    public function discover(Target $target, BoundMcpTarget $bound, string $correlationId): array
    {
        $result = $this->request($target, $bound, 'server/discover', [], false, $correlationId);
        $versions = $result['supportedVersions'] ?? null;
        if (! self::validCacheableResult($result) || ! is_array($versions) || ! array_is_list($versions)
            || $versions === [] || count(array_filter($versions, 'is_string')) !== count($versions)
            || ! is_array($result['capabilities'] ?? null)) {
            throw $this->failure('invalid_discovery', 'discovery', false, true);
        }
        if (! in_array(self::PROTOCOL_VERSION, $versions, true)) {
            throw $this->failure('unsupported_protocol', 'discovery', false, true);
        }

        return $result;
    }

    /**
     * One bounded catalog page; no implicit pagination, idle catalog refresh,
     * or trust in effect annotations as permission.
     *
     * @return array{tools:list<array<string,mixed>>,next_cursor:?string}
     */
    public function listTools(Target $target, BoundMcpTarget $bound, string $correlationId, ?string $cursor = null): array
    {
        $params = [];
        if ($cursor !== null) {
            if ($cursor === '' || strlen($cursor) > 256 || preg_match('/[\x00-\x1f\x7f]/', $cursor) === 1) {
                throw $this->failure('invalid_cursor', 'input', false);
            }
            $params['cursor'] = $cursor;
        }
        $result = $this->request($target, $bound, 'tools/list', $params, false, $correlationId);
        if (! self::validCacheableResult($result)) {
            throw $this->failure('invalid_catalog', 'catalog', false, true);
        }
        $tools = $result['tools'] ?? null;
        if (! is_array($tools) || ! array_is_list($tools) || count($tools) > self::MAX_CATALOG_PAGE_TOOLS) {
            throw $this->failure('invalid_catalog', 'catalog', false, true);
        }

        $names = [];
        foreach ($tools as $tool) {
            if (! is_array($tool) || ! self::validToolName($tool['name'] ?? null)
                || isset($names[$tool['name']])
                || ! is_array($tool['inputSchema'] ?? null)
                || ($tool['inputSchema']['type'] ?? null) !== 'object') {
                throw $this->failure('unsupported_tool_schema', 'catalog', false, true);
            }
            $names[$tool['name']] = true;
        }

        $next = $result['nextCursor'] ?? null;
        if ($next !== null && (! is_string($next) || $next === ''
            || strlen($next) > 256 || preg_match('/[\x00-\x1f\x7f]/', $next) === 1)) {
            throw $this->failure('invalid_catalog_cursor', 'catalog', false, true);
        }

        return ['tools' => $tools, 'next_cursor' => $next];
    }

    /**
     * Invoke one provider-advertised tool AFTER the owning connector's
     * authorization and schema/argument decision. Unknown compatible names
     * are not rejected merely because Gateway source has not seen them.
     *
     * @param  array<string, mixed>  $arguments
     * @return array<string, mixed> MCP CallToolResult, including structuredContent.
     */
    public function callTool(
        Target $target,
        BoundMcpTarget $bound,
        string $toolName,
        array $arguments,
        bool $mutationRisk,
        string $correlationId,
    ): array {
        if (! self::validToolName($toolName)) {
            throw $this->failure('unsupported_tool_name', 'input', false);
        }

        $result = $this->request($target, $bound, 'tools/call', [
            'name' => $toolName,
            'arguments' => $arguments === [] ? (object) [] : $arguments,
        ], $mutationRisk, $correlationId, $toolName);

        if (($result['resultType'] ?? null) !== 'complete') {
            // Request-only clients cannot complete an input_required roundtrip.
            throw $this->failure('unsupported_result_type', 'response', $mutationRisk, true);
        }
        if (! is_array($result['content'] ?? null) || ! array_is_list($result['content'])
            || (array_key_exists('isError', $result) && ! is_bool($result['isError']))) {
            throw $this->failure('invalid_tool_result', 'response', $mutationRisk, true);
        }
        foreach ($result['content'] as $block) {
            if (! self::validContentBlock($block)) {
                throw $this->failure('invalid_tool_result', 'response', $mutationRisk, true);
            }
        }
        // structuredContent can be any JSON value, including null and scalars.
        if (($result['isError'] ?? false) === true) {
            throw $this->toolFailure($result, $mutationRisk, $bound->authorizationHeader());
        }

        return $result;
    }

    /**
     * @param  array<string, mixed>  $params
     * @return array<string, mixed>
     */
    private function request(
        Target $target,
        BoundMcpTarget $bound,
        string $method,
        array $params,
        bool $mutationRisk,
        string $correlationId,
        ?string $toolName = null,
    ): array {
        if ($correlationId === '' || preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/D', $correlationId) !== 1) {
            throw $this->failure('invalid_correlation', 'input', false);
        }

        $bound->assertCurrentTarget($target);

        // Every 2026-07-28 request includes version/capabilities metadata.
        // MCP clientInfo and untrusted request IDs never assert product identity.
        $params['_meta'] = [
            'io.modelcontextprotocol/protocolVersion' => self::PROTOCOL_VERSION,
            'io.modelcontextprotocol/clientCapabilities' => (object) [],
            'io.modelcontextprotocol/clientInfo' => ['name' => 'mcp-gateway', 'version' => '1'],
        ];
        $rpcId = bin2hex(random_bytes(8));
        $payload = [
            'jsonrpc' => '2.0',
            'id' => $rpcId,
            'method' => $method,
            'params' => $params,
        ];

        try {
            $encoded = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new OutboundMcpFailure(
                'invalid_arguments', 'not_executed', 'input',
                'Downstream MCP input cannot be encoded as JSON.', [], null, null, $exception,
            );
        }
        if (strlen($encoded) > self::MAX_REQUEST_BYTES) {
            throw $this->failure('request_too_large', 'input', false);
        }

        $headers = [
            'Authorization' => $bound->authorizationHeader(),
            'Accept' => 'application/json, text/event-stream',
            'MCP-Protocol-Version' => self::PROTOCOL_VERSION,
            'Mcp-Method' => $method,
            'X-MCP-Gateway-Correlation-ID' => $correlationId,
        ];
        if ($toolName !== null) {
            $headers['Mcp-Name'] = $toolName;
        }

        try {
            // SafeHttpClient provides canonical HTTPS, public DNS pinning,
            // TLS validation, no redirects, timeouts and a bounded body.
            $response = $this->http->postJson($bound->resourceUrl, $payload, $headers, self::MAX_RESPONSE_BYTES);
        } catch (UnsafeOutboundTarget $exception) {
            throw new OutboundMcpFailure(
                'unsafe_target', 'not_executed', 'egress',
                'The bound MCP destination did not pass outbound security policy.', [], null, null, $exception,
            );
        } catch (OutboundRequestException $exception) {
            throw new OutboundMcpFailure(
                $exception->reason, $exception->preDispatch ? 'not_executed' : 'unknown', 'transport',
                'Downstream MCP transport failed; the request was not replayed.',
                array_filter([
                    'failure_stage' => $exception->details['failure_stage'] ?? null,
                    'phase' => $exception->details['phase'] ?? null,
                ], static fn (mixed $v): bool => is_string($v)),
                null, null, $exception,
            );
        }

        if ($response->status !== 200) {
            throw new OutboundMcpFailure(
                match ($response->status) {
                    401 => 'downstream_unauthenticated',
                    403 => 'downstream_forbidden',
                    400, 426 => 'downstream_protocol_rejected',
                    default => 'downstream_http_failure',
                },
                'unknown', 'http',
                'Downstream MCP rejected the request; no automatic replay occurred.',
                ['http_status' => $response->status],
                null, $this->safeId($response->header('X-Request-ID'), 128, $bound->authorizationHeader()),
            );
        }
        if ($response->header('Mcp-Session-Id') !== null
            || ! str_starts_with(strtolower($response->header('Content-Type') ?? ''), 'application/json')) {
            throw $this->failure('unsupported_response_profile', 'response', $mutationRisk, true);
        }

        try {
            $wire = $response->json();
        } catch (OutboundRequestException $exception) {
            throw new OutboundMcpFailure(
                'invalid_response_json', 'unknown', 'response',
                'Downstream MCP returned an invalid JSON response.', [], null, null, $exception,
            );
        }
        if (($wire['jsonrpc'] ?? null) !== '2.0' || ($wire['id'] ?? null) !== $rpcId
            || array_key_exists('result', $wire) === array_key_exists('error', $wire)) {
            throw $this->failure('invalid_rpc_envelope', 'response', $mutationRisk, true);
        }
        if (array_key_exists('error', $wire)) {
            $error = $wire['error'];
            $code = is_array($error) ? ($error['code'] ?? null) : null;

            throw new OutboundMcpFailure(
                'downstream_rpc_error', 'unknown', 'protocol',
                'Downstream MCP returned a JSON-RPC error.',
                is_int($code) ? ['rpc_code' => $code] : [],
                null, $this->safeId($response->header('X-Request-ID'), 128, $bound->authorizationHeader()),
            );
        }
        if (! is_array($wire['result'])) {
            throw $this->failure('invalid_rpc_result', 'response', $mutationRisk, true);
        }

        return $wire['result'];
    }

    /** @param array<string, mixed> $result */
    private function toolFailure(array $result, bool $mutationRisk, string $authorization): OutboundMcpFailure
    {
        $text = $result['content'][0]['text'] ?? null;
        $fault = is_string($text) ? json_decode($text, true, 16) : null;
        $fault = is_array($fault) ? $fault : [];

        // AChrix Bridge supplies an explicitly product-approved safe
        // projection here, not a wire-inferred effect status. Missing or
        // invalid provider evidence is always unknown after dispatch.
        $outcome = $fault['outcome'] ?? null;
        if (! in_array($outcome, ['not_executed', 'not_committed', 'succeeded', 'unknown'], true)) {
            $outcome = 'unknown';
        }

        $details = ['mutation_risk' => $mutationRisk];
        foreach (['code' => 'source_code', 'message' => 'source_message', 'action' => 'source_action'] as $key => $detail) {
            if (is_string($fault[$key] ?? null)
                && strlen($fault[$key]) <= ($key === 'code' ? 64 : 512)
                && preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $fault[$key]) !== 1) {
                $details[$detail] = str_replace(substr($authorization, 7), '[redacted]', $fault[$key]);
            }
        }

        return new OutboundMcpFailure(
            'downstream_tool_error', $outcome, 'operation',
            'Downstream MCP reported an application tool failure.',
            $details,
            $this->safeId($fault['reference'] ?? null, 256, $authorization),
            $this->safeId($fault['request_id'] ?? null, 128, $authorization),
        );
    }

    private function failure(string $reason, string $phase, bool $mutationRisk, bool $dispatched = false): OutboundMcpFailure
    {
        return new OutboundMcpFailure(
            $reason, $mutationRisk || $dispatched ? 'unknown' : 'not_executed', $phase,
            'Downstream MCP message is invalid or incompatible.',
        );
    }

    /** @param array<string, mixed> $result */
    private static function validCacheableResult(array $result): bool
    {
        return ($result['resultType'] ?? null) === 'complete'
            && in_array($result['cacheScope'] ?? null, ['private', 'public'], true)
            && is_int($result['ttlMs'] ?? null) && $result['ttlMs'] >= 0;
    }

    private static function validContentBlock(mixed $block): bool
    {
        if (! is_array($block)) {
            return false;
        }

        return match ($block['type'] ?? null) {
            'text' => is_string($block['text'] ?? null),
            'image', 'audio' => is_string($block['data'] ?? null) && is_string($block['mimeType'] ?? null),
            'resource_link' => is_string($block['name'] ?? null) && is_string($block['uri'] ?? null),
            'resource' => is_array($block['resource'] ?? null)
                && is_string($block['resource']['uri'] ?? null)
                && (is_string($block['resource']['text'] ?? null) || is_string($block['resource']['blob'] ?? null)),
            default => false,
        };
    }

    private static function validToolName(mixed $name): bool
    {
        // Modern header mirroring requires a safe plain-ASCII tool name.
        // Reject other names explicitly rather than inventing untested
        // Base64 header encoding or allowing CRLF injection.
        return is_string($name)
            && preg_match('~^[A-Za-z0-9_.:/-]{1,128}$~D', $name) === 1;
    }

    private function safeId(mixed $value, int $maxBytes = 128, string $authorization = ''): ?string
    {
        $token = str_starts_with($authorization, 'Bearer ') ? substr($authorization, 7) : '';

        return is_string($value) && $value !== '' && strlen($value) <= $maxBytes
            && preg_match('/[\x00-\x1f\x7f]/', $value) !== 1
            && ($token === '' || ! str_contains($value, $token)) ? $value : null;
    }
}
