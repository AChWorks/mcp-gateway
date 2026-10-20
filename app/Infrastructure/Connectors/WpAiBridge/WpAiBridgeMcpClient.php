<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Application\Operations\OperationalSettings;
use App\Application\Targets\TargetOperationGate;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Access\AbilityExecutionClass;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\Http\SafeHttpResponse;
use App\Support\OperationTiming;

final readonly class WpAiBridgeMcpClient
{
    private const PROTOCOL_VERSION = '2025-11-25';

    private const EXECUTE_TOOL = 'mcp-adapter-execute-ability';

    private const CATALOG_ABILITY = 'wp-ai-bridge/abilities-read';

    public function __construct(
        private SafeHttpClient $http,
        private WpAiBridgeTargetConnectionService $targetConnections,
        private OperationalSettings $settings,
    ) {}

    /** @return array<string, mixed> */
    public function readAbilities(
        Target $target,
        string $correlationId,
        ?string $ability = null,
        int $page = 1,
        int $perPage = 10,
        ?string $namespace = null,
        ?string $search = null,
        ?OperationTiming $timing = null,
    ): array {
        $parameters = $ability !== null
            ? ['action' => 'get', 'name' => $ability]
            : array_filter([
                'action' => 'list',
                'page' => $page,
                'per_page' => $perPage,
                'namespace' => $namespace,
                'search' => $search,
            ], static fn (mixed $value): bool => $value !== null);

        $result = $this->callAbility($target, self::CATALOG_ABILITY, $parameters, false, $correlationId, $timing);
        if (! is_array($result)) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an invalid ability catalog result.');
        }

        return $result;
    }

    /**
     * Probe the CURRENT stored access bearer against the protected WordPress
     * MCP catalog without invoking credential refresh or generation rotation.
     * Metadata reachability alone is never accepted as authorization proof.
     *
     * @param  array{resource_url:string,access_token:string}  $routing
     */
    public function verifyExistingAuthorization(array $routing, string $correlationId): void
    {
        $catalog = $this->callAbilityOnRouting(
            $routing, self::CATALOG_ABILITY,
            ['action' => 'list', 'page' => 1, 'per_page' => 1],
            false, $correlationId,
        );
        if (! is_array($catalog) || ! is_array($catalog['items'] ?? null)) {
            throw new WpAiBridgeMcpException('protocol_error', 'Authenticated WordPress catalog confirmation is invalid.');
        }
    }

    public function classifyAbility(
        Target $target,
        string $ability,
        string $correlationId,
    ): AbilityExecutionClass {
        return $this->abilityExecutionClass(
            $this->routingContext($target),
            $ability,
            $correlationId,
        );
    }

    /** @param array<string, mixed> $input */
    public function executeAbility(
        Target $target,
        string $ability,
        array $input,
        string $correlationId,
        ?AbilityExecutionClass $executionClass = null,
    ): mixed {
        $routing = $this->routingContext($target);
        $executionClass ??= $this->abilityExecutionClass($routing, $ability, $correlationId);

        return $this->callAbilityOnRouting(
            $routing,
            $ability,
            $input,
            $executionClass->hasMutationRisk(),
            $correlationId,
        );
    }

    /**
     * Execute under the SAME request-owned downstream session used for
     * classification. The caller must have resolved a bounded, request-local
     * permission snapshot before any downstream connection is opened.
     *
     * @param  array<string,mixed>  $input
     * @param  callable(AbilityExecutionClass):bool  $authorizeClass
     * @param  (callable(array<mixed,mixed>|null,AbilityExecutionClass):bool)|null  $verifyContract
     */
    public function executeAuthorizedAbility(
        Target $target,
        string $ability,
        array $input,
        string $correlationId,
        callable $authorizeClass,
        ?OperationTiming $timing = null,
        ?callable $verifyContract = null,
    ): mixed {
        $routing = $this->routingContext($target, $timing);

        return $this->withLegacySession($routing, $correlationId, function (string $url, array $headers) use ($target, $routing, $ability, $input, $correlationId, $authorizeClass, $verifyContract, $timing): mixed {
            $classifiedAt = $timing?->stamp() ?? 0;
            try {
                $contract = null;
                $executionClass = $this->abilityExecutionClass($routing, $ability, $correlationId, $headers, $timing, $contract);
            } finally {
                $timing?->finish('mcp_classification_ms', $classifiedAt);
            }
            // Only narrowly specified use cases require an exact provider
            // contract. Broad authorized dynamic execution is unchanged.
            if ($verifyContract !== null && ! $verifyContract($contract, $executionClass)) {
                throw new WpAiBridgeMcpException('forbidden', 'The required WordPress provider contract is unavailable.');
            }
            if (! $authorizeClass($executionClass)) {
                throw new WpAiBridgeMcpException('forbidden', 'The classified WordPress Ability is not authorized.');
            }

            if (TargetOperationGate::isPaused($target)) {
                throw new WpAiBridgeMcpException('target_paused', 'Gateway Target operations were paused before execution.');
            }

            $dispatchedAt = $timing?->stamp() ?? 0;
            try {
                return $this->callTool($url, $headers, $ability, $input, $executionClass->hasMutationRisk(), 3, $timing);
            } finally {
                $timing?->finish('mcp_execute_ms', $dispatchedAt);
            }
        }, $timing);
    }

    /**
     * @param  array{resource_url:string,access_token:string}  $routing
     * @param  array<string,string>|null  $sessionHeaders
     * @param  array<mixed,mixed>|null  $contract
     *
     * @param-out array<mixed,mixed>|null $contract
     */
    private function abilityExecutionClass(
        array $routing,
        string $ability,
        string $correlationId,
        ?array $sessionHeaders = null,
        ?OperationTiming $timing = null,
        ?array &$contract = null,
    ): AbilityExecutionClass {
        $catalog = $sessionHeaders === null
            ? $this->callAbilityOnRouting(
                $routing,
                self::CATALOG_ABILITY,
                ['action' => 'get', 'name' => $ability],
                false,
                $correlationId,
                null,
                $timing,
            )
            : $this->callTool($routing['resource_url'], $sessionHeaders, self::CATALOG_ABILITY, ['action' => 'get', 'name' => $ability], false, 2, $timing);

        // A failed catalog lookup is NOT an unclassified Ability. Preserve
        // the downstream error (network, auth, protocol, etc.) and do not
        // dispatch another tool call under the optional Unclassified grant.
        // Reserve Unclassified for successfully returned, incomplete effect
        // metadata; unknown names remain subject to the actual Bridge policy.
        if (! is_array($catalog)) {
            return AbilityExecutionClass::Unclassified;
        }

        $items = $catalog['items'] ?? null;
        if (! is_array($items) || count($items) !== 1 || ! is_array($items[0] ?? null)) {
            return AbilityExecutionClass::Unclassified;
        }

        $contract = $items[0];
        if (($contract['name'] ?? null) !== $ability
            || ($contract['mcp_type'] ?? null) !== 'tool'
            || ($contract['bridge_delegation'] ?? null) !== 'ability_specific') {
            return AbilityExecutionClass::Unclassified;
        }

        $annotations = $contract['annotations'] ?? null;
        if (! is_array($annotations)) {
            return AbilityExecutionClass::Unclassified;
        }

        $readonly = $annotations['readonly'] ?? null;
        $destructive = $annotations['destructive'] ?? null;

        if ($destructive === true) {
            return AbilityExecutionClass::Destructive;
        }

        if ($readonly === true && $destructive === false) {
            return AbilityExecutionClass::Readonly;
        }

        if ($readonly === false && $destructive === false) {
            return AbilityExecutionClass::Mutating;
        }

        return AbilityExecutionClass::Unclassified;
    }

    /** @param array<string, mixed> $input */
    private function callAbility(Target $target, string $ability, array $input, bool $mutationRisk, string $correlationId, ?OperationTiming $timing = null): mixed
    {
        return $this->callAbilityOnRouting(
            $this->routingContext($target, $timing),
            $ability,
            $input,
            $mutationRisk,
            $correlationId,
            $target,
            $timing,
        );
    }

    /**
     * @param  array{resource_url:string,access_token:string}  $routing
     * @param  array<string, mixed>  $input
     */
    private function callAbilityOnRouting(
        array $routing,
        string $ability,
        array $input,
        bool $mutationRisk,
        string $correlationId,
        ?Target $target = null,
        ?OperationTiming $timing = null,
    ): mixed {
        return $this->withLegacySession(
            $routing,
            $correlationId,
            function (string $url, array $headers) use ($target, $ability, $input, $mutationRisk, $timing): mixed {
                if ($target instanceof Target && TargetOperationGate::isPaused($target)) {
                    throw new WpAiBridgeMcpException('target_paused', 'Gateway Target operations were paused before dispatch.');
                }

                $calledAt = $timing?->stamp() ?? 0;
                try {
                    return $this->callTool($url, $headers, $ability, $input, $mutationRisk, 2, $timing);
                } finally {
                    $timing?->finish($ability === self::CATALOG_ABILITY ? 'mcp_catalog_ms' : 'mcp_execute_ms', $calledAt);
                }
            },
            $timing,
        );
    }

    /**
     * @param  array{resource_url:string,access_token:string}  $routing
     * @param  callable(string,array<string,string>):mixed  $operation
     */
    private function withLegacySession(array $routing, string $correlationId, callable $operation, ?OperationTiming $timing = null): mixed
    {
        $headers = [
            'Authorization' => 'Bearer '.$routing['access_token'],
            'Accept' => 'application/json, text/event-stream',
            'MCP-Protocol-Version' => self::PROTOCOL_VERSION,
            'X-MCP-Gateway-Correlation-ID' => $correlationId,
        ];

        $initializedAt = $timing?->stamp() ?? 0;
        try {
            $sessionId = $this->initialize($routing['resource_url'], $headers, $timing);
        } finally {
            $timing?->finish('mcp_initialize_ms', $initializedAt);
        }
        $headers['Mcp-Session-Id'] = $sessionId;

        try {
            return $operation($routing['resource_url'], $headers);
        } finally {
            $closedAt = $timing?->stamp() ?? 0;
            try {
                $this->closeSession($routing['resource_url'], $headers, $timing);
            } finally {
                $timing?->finish('mcp_close_ms', $closedAt);
            }
        }
    }

    /** @return array{resource_url:string,access_token:string} */
    private function routingContext(Target $target, ?OperationTiming $timing = null): array
    {
        if ($target->connector_type !== 'wp_ai_bridge') {
            throw new WpAiBridgeMcpException(
                'unsupported_connector',
                'Only an authorized WordPress Target can access this MCP connector.',
            );
        }

        if (TargetOperationGate::isPaused($target)) {
            throw new WpAiBridgeMcpException('target_paused', 'This Target is paused by the Gateway Owner.');
        }

        $credentialAt = $timing?->stamp() ?? 0;
        try {
            return $this->targetConnections->routingContextWithRecovery($target);
        } finally {
            $timing?->finish('credential_ms', $credentialAt);
        }
    }

    /** @param array<string, string> $headers */
    private function initialize(string $resourceUrl, array $headers, ?OperationTiming $timing = null): string
    {
        try {
            $response = $this->http->postJson($resourceUrl, [
                'jsonrpc' => '2.0',
                'id' => 1,
                'method' => 'initialize',
                'params' => [
                    'protocolVersion' => self::PROTOCOL_VERSION,
                    // MCP initialize requires a capabilities object, even when empty.
                    'capabilities' => (object) [],
                    'clientInfo' => ['name' => 'mcp-gateway', 'version' => '0.1.0'],
                ],
            ], $headers, null, $timing);
        } catch (OutboundRequestException $exception) {
            throw new WpAiBridgeMcpException($exception->reason, 'WP AI Bridge MCP initialization failed.', $exception, $exception->details);
        }

        $this->assertAuthenticationStatus($response);
        if ($response->status !== 200) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge rejected MCP initialization.');
        }

        try {
            $payload = $response->json();
        } catch (OutboundRequestException $exception) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an invalid MCP initialization response.', $exception, $exception->details);
        }

        if (($payload['jsonrpc'] ?? null) !== '2.0' || ($payload['id'] ?? null) !== 1 || ! is_array($payload['result'] ?? null)) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an incompatible MCP initialization response.');
        }

        $sessionId = $response->header('Mcp-Session-Id');
        if ($sessionId === null || strlen($sessionId) > 255) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge did not provide a valid MCP session identifier.');
        }

        return $sessionId;
    }

    /**
     * @param  array<string, string>  $headers
     * @param  array<string, mixed>  $input
     */
    private function callTool(string $resourceUrl, array $headers, string $ability, array $input, bool $mutationRisk, int $requestId = 2, ?OperationTiming $timing = null): mixed
    {
        try {
            $response = $this->http->postJson($resourceUrl, [
                'jsonrpc' => '2.0',
                'id' => $requestId,
                'method' => 'tools/call',
                'params' => [
                    'name' => self::EXECUTE_TOOL,
                    'arguments' => [
                        'ability_name' => $ability,
                        'parameters' => $input === [] ? (object) [] : $input,
                    ],
                ],
            ], $headers, $mutationRisk
                ? null
                : $this->settings->responseLimitBytes(true), $timing);
        } catch (OutboundRequestException $exception) {
            if (! $mutationRisk && $exception->reason === 'response_too_large') {
                throw new WpAiBridgeMcpException(
                    'response_too_large',
                    'The downstream read is larger than the Gateway response limit. Use a targeted/paginated read or adjust the bounded read limit.',
                    $exception,
                    [...$exception->details, 'failure_origin' => 'gateway_response'],
                );
            }

            $reason = $mutationRisk ? 'outcome_unknown' : $exception->reason;
            $message = $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge could not complete the downstream read.';
            throw new WpAiBridgeMcpException($reason, $message, $exception, [
                ...$exception->details,
                'failure_origin' => $exception->reason === 'response_too_large'
                    ? 'gateway_response' : 'gateway_transport',
                'retry_safe' => false,
            ]);
        }

        $this->assertAuthenticationStatus($response);
        if ($response->status !== 200) {
            $evidence = [
                'failure_origin' => 'downstream_http',
                'failure_stage' => 'remote_http',
                'http_status' => $response->status,
                'retry_safe' => false,
            ];
            if ($mutationRisk && ($response->status === 408 || $response->status === 429 || $response->status >= 500)) {
                throw new WpAiBridgeMcpException('outcome_unknown', 'The downstream mutation result is unknown and was not retried.', null, $evidence);
            }
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an unexpected MCP HTTP status.', null, $evidence);
        }

        try {
            $payload = $response->json();
        } catch (OutboundRequestException $exception) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            $message = $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned invalid MCP JSON.';
            throw new WpAiBridgeMcpException($reason, $message, $exception, [
                ...$exception->details,
                'failure_origin' => 'downstream_mcp',
                'failure_stage' => 'response_body',
                'retry_safe' => false,
            ]);
        }

        if (($payload['jsonrpc'] ?? null) !== '2.0' || ($payload['id'] ?? null) !== $requestId) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned a mismatched MCP response.');
        }

        if (isset($payload['error'])) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            $observed = is_array($payload['error']) ? $payload['error'] : [];
            $evidence = [
                'failure_origin' => 'downstream_mcp',
                'failure_stage' => 'operation',
                'effect_unconfirmed' => $mutationRisk,
                'retry_safe' => false,
            ];
            if (is_string($observed['code'] ?? null) || is_int($observed['code'] ?? null)) {
                $evidence['source_error_code'] = $this->redactBearerCredential(
                    $observed['code'], $headers['Authorization'] ?? null,
                );
            }
            if (is_string($observed['message'] ?? null)) {
                $evidence['source_error_message'] = $this->redactBearerCredential(
                    $observed['message'], $headers['Authorization'] ?? null,
                );
            }
            if (array_key_exists('data', $observed)) {
                $evidence['source_error_details'] = $this->redactBearerCredential(
                    $observed['data'], $headers['Authorization'] ?? null,
                );
            }
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned an MCP protocol error.', null, $evidence);
        }

        $result = $payload['result'] ?? null;
        if (! is_array($result)) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned an invalid MCP tool result.');
        }

        $authorization = $headers['Authorization'] ?? null;
        if (($result['isError'] ?? false) === true) {
            // Keep the original authenticated downstream error fields where
            // present. A provider WP_Error code may already be missing in the
            // upstream Adapter; do not manufacture it by parsing prose.
            $observedMessage = $this->observedToolErrorMessage($result, $authorization);
            $structured = is_array($result['structuredContent'] ?? null)
                ? $result['structuredContent'] : [];
            $remoteError = is_array($structured['error'] ?? null)
                ? $structured['error'] : [];
            $nativeCode = $this->redactBearerCredential(
                $remoteError['code'] ?? $structured['error_code'] ?? null, $authorization,
            );
            $nativeMessage = $this->redactBearerCredential(
                $remoteError['message'] ?? $structured['error'] ?? null, $authorization,
            );
            $nativeData = $remoteError['data'] ?? $structured['error_data'] ?? null;
            $details = [
                'failure_origin' => 'downstream_mcp',
                'failure_stage' => 'operation',
                // Authenticated MCP-level error identity need not be the original
                // provider/WordPress WP_Error identity (Adapter can strip it).
                'provider_cause_unknown' => true,
                'effect_unconfirmed' => $mutationRisk,
                'retry_safe' => false,
            ];
            if (is_string($nativeCode) || is_int($nativeCode)) {
                $details['source_error_code'] = $nativeCode;
            }
            if (is_string($observedMessage) || is_string($nativeMessage)) {
                $details['source_error_message'] = $observedMessage ?? $nativeMessage;
            }
            if (is_string($nativeMessage) && $nativeMessage !== $observedMessage) {
                $details['source_error_structured_message'] = $nativeMessage;
            }
            if (array_key_exists('data', $remoteError) || array_key_exists('error_data', $structured)) {
                $details['source_error_details'] = $this->redactBearerCredential($nativeData, $authorization);
            }
            throw new WpAiBridgeMcpException(
                'downstream_rejected',
                $observedMessage ?? (is_string($nativeMessage) ? $nativeMessage : 'WP AI Bridge rejected the Ability request.'),
                null,
                $details,
            );
        }

        $structured = $result['structuredContent'] ?? null;
        if (! is_array($structured) || ($structured['success'] ?? null) !== true || ! array_key_exists('data', $structured)) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned an incompatible Ability execution result.');
        }

        return $this->redactBearerCredential($structured['data'], $authorization);
    }

    /** @param array<string, string> $headers */
    private function closeSession(string $resourceUrl, array $headers, ?OperationTiming $timing = null): void
    {
        try {
            $this->http->delete($resourceUrl, $headers, $timing);
        } catch (OutboundRequestException) {
            // Session cleanup is best-effort and never retries or masks the authoritative tool result.
        }
    }

    private function assertAuthenticationStatus(SafeHttpResponse $response): void
    {
        if ($response->status === 401 || $response->status === 403) {
            throw new WpAiBridgeMcpException('downstream_auth', 'WP AI Bridge rejected the selected site credential.', null, [
                'failure_origin' => 'downstream_http',
                'failure_stage' => 'remote_http',
                'http_status' => $response->status,
                'retry_safe' => false,
            ]);
        }
    }

    /** @param array<string, mixed> $result */
    private function observedToolErrorMessage(array $result, ?string $authorization): ?string
    {
        $content = $result['content'] ?? null;
        if (! is_array($content)) {
            return null;
        }

        $texts = [];
        foreach ($content as $block) {
            if (! is_array($block) || ($block['type'] ?? null) !== 'text' || ! is_string($block['text'] ?? null)) {
                continue;
            }

            // Preserve the exact received wording and useful multi-block
            // diagnostics; remove only the known Gateway credential here.
            $message = $this->redactBearerCredential($block['text'], $authorization);
            if (is_string($message) && trim($message) !== '') {
                $texts[] = $message;
            }
        }

        return $texts === [] ? null : implode("\n", $texts);
    }

    private function redactBearerCredential(mixed $value, ?string $authorization): mixed
    {
        if (! is_string($authorization) || ! str_starts_with($authorization, 'Bearer ')) {
            return $value;
        }

        $token = substr($authorization, 7);
        if ($token === '') {
            return $value;
        }

        if (is_string($value)) {
            return str_replace([$authorization, $token], '[redacted]', $value);
        }

        if (! is_array($value)) {
            return $value;
        }

        $redacted = [];
        foreach ($value as $key => $item) {
            $safeKey = is_string($key)
                ? str_replace([$authorization, $token], '[redacted]', $key)
                : $key;
            $redacted[$safeKey] = $this->redactBearerCredential($item, $authorization);
        }

        return $redacted;
    }
}
