<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Application\Sites\SiteConnectionService;
use App\Domain\Sites\Site;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\Http\SafeHttpResponse;

final readonly class WpAiBridgeMcpClient
{
    private const PROTOCOL_VERSION = '2025-11-25';

    private const EXECUTE_TOOL = 'mcp-adapter-execute-ability';

    private const CATALOG_ABILITY = 'wp-native-builder/abilities-read';

    public function __construct(
        private SiteConnectionService $connections,
        private SafeHttpClient $http,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function readAbilities(
        Site $site,
        string $correlationId,
        ?string $ability = null,
        int $page = 1,
        int $perPage = 25,
        ?string $namespace = null,
        ?string $search = null,
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

        $result = $this->callAbility(
            $site,
            self::CATALOG_ABILITY,
            $parameters,
            false,
            $correlationId,
        );

        if (! is_array($result)) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an invalid ability catalog result.');
        }

        return $result;
    }

    public function executeAbility(Site $site, string $ability, array $input, string $correlationId): mixed
    {
        return $this->callAbility($site, $ability, $input, true, $correlationId);
    }

    private function callAbility(
        Site $site,
        string $ability,
        array $input,
        bool $mutationRisk,
        string $correlationId,
    ): mixed {
        if ($site->connector_type !== (string) config('bridge.connector_type', 'wp_ai_bridge')) {
            throw new WpAiBridgeMcpException('unsupported_connector', 'The selected site does not use the WP AI Bridge connector.');
        }

        $accessToken = $this->connections->accessToken($site);
        $headers = [
            'Authorization' => 'Bearer '.$accessToken,
            'Accept' => 'application/json, text/event-stream',
            'MCP-Protocol-Version' => self::PROTOCOL_VERSION,
            'X-MCP-Gateway-Correlation-ID' => $correlationId,
        ];

        $sessionId = $this->initialize($site, $headers);
        $headers['Mcp-Session-Id'] = $sessionId;

        try {
            return $this->callTool($site, $headers, $ability, $input, $mutationRisk);
        } finally {
            $this->closeSession($site, $headers);
        }
    }

    /** @param array<string, string> $headers */
    private function initialize(Site $site, array $headers): string
    {
        try {
            $response = $this->http->postJson($site->mcp_resource_url, [
                'jsonrpc' => '2.0',
                'id' => 1,
                'method' => 'initialize',
                'params' => [
                    'protocolVersion' => self::PROTOCOL_VERSION,
                    'clientInfo' => [
                        'name' => 'mcp-gateway',
                        'version' => '0.1.0',
                    ],
                ],
            ], $headers);
        } catch (OutboundRequestException $exception) {
            throw new WpAiBridgeMcpException($exception->reason, 'WP AI Bridge MCP initialization failed.', $exception);
        }

        $this->assertAuthenticationStatus($response);
        if ($response->status !== 200) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge rejected MCP initialization.');
        }

        try {
            $payload = $response->json();
        } catch (OutboundRequestException $exception) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an invalid MCP initialization response.', $exception);
        }

        if (($payload['jsonrpc'] ?? null) !== '2.0'
            || ($payload['id'] ?? null) !== 1
            || ! is_array($payload['result'] ?? null)) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an incompatible MCP initialization response.');
        }

        $sessionId = $response->header('Mcp-Session-Id');
        if ($sessionId === null || strlen($sessionId) > 255) {
            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge did not provide a valid MCP session identifier.');
        }

        return $sessionId;
    }

    /** @param array<string, string> $headers */
    private function callTool(
        Site $site,
        array $headers,
        string $ability,
        array $input,
        bool $mutationRisk,
    ): mixed {
        try {
            $response = $this->http->postJson($site->mcp_resource_url, [
                'jsonrpc' => '2.0',
                'id' => 2,
                'method' => 'tools/call',
                'params' => [
                    'name' => self::EXECUTE_TOOL,
                    'arguments' => [
                        'ability_name' => $ability,
                        'parameters' => $input,
                    ],
                ],
            ], $headers);
        } catch (OutboundRequestException $exception) {
            $reason = $mutationRisk ? 'outcome_unknown' : $exception->reason;
            $message = $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge could not complete the downstream read.';

            throw new WpAiBridgeMcpException($reason, $message, $exception);
        }

        $this->assertAuthenticationStatus($response);

        if ($response->status !== 200) {
            if ($mutationRisk && ($response->status === 408 || $response->status === 429 || $response->status >= 500)) {
                throw new WpAiBridgeMcpException('outcome_unknown', 'The downstream mutation result is unknown and was not retried.');
            }

            throw new WpAiBridgeMcpException('protocol_error', 'WP AI Bridge returned an unexpected MCP HTTP status.');
        }

        try {
            $payload = $response->json();
        } catch (OutboundRequestException $exception) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            $message = $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned invalid MCP JSON.';

            throw new WpAiBridgeMcpException($reason, $message, $exception);
        }

        if (($payload['jsonrpc'] ?? null) !== '2.0' || ($payload['id'] ?? null) !== 2) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned a mismatched MCP response.');
        }

        if (isset($payload['error'])) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned an MCP protocol error.');
        }

        $result = $payload['result'] ?? null;
        if (! is_array($result)) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned an invalid MCP tool result.');
        }

        if (($result['isError'] ?? false) === true) {
            throw new WpAiBridgeMcpException('downstream_rejected', $this->boundedToolErrorMessage($result));
        }

        $structured = $result['structuredContent'] ?? null;
        if (! is_array($structured) || ($structured['success'] ?? null) !== true || ! array_key_exists('data', $structured)) {
            $reason = $mutationRisk ? 'outcome_unknown' : 'protocol_error';
            throw new WpAiBridgeMcpException($reason, $mutationRisk
                ? 'The downstream mutation result is unknown and was not retried.'
                : 'WP AI Bridge returned an incompatible Ability execution result.');
        }

        return $structured['data'];
    }

    /** @param array<string, string> $headers */
    private function closeSession(Site $site, array $headers): void
    {
        try {
            $this->http->delete($site->mcp_resource_url, $headers);
        } catch (OutboundRequestException) {
            // Session cleanup is best-effort and never retries or masks the authoritative tool result.
        }
    }

    private function assertAuthenticationStatus(SafeHttpResponse $response): void
    {
        if ($response->status === 401 || $response->status === 403) {
            throw new WpAiBridgeMcpException('downstream_auth', 'WP AI Bridge rejected the selected site credential.');
        }
    }

    /** @param array<string, mixed> $result */
    private function boundedToolErrorMessage(array $result): string
    {
        $content = $result['content'] ?? null;
        if (! is_array($content)) {
            return 'WP AI Bridge rejected the Ability request.';
        }

        foreach ($content as $block) {
            if (! is_array($block) || ($block['type'] ?? null) !== 'text' || ! is_string($block['text'] ?? null)) {
                continue;
            }

            $message = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', trim($block['text']));
            if (! is_string($message) || $message === '') {
                continue;
            }

            return mb_substr($message, 0, 512);
        }

        return 'WP AI Bridge rejected the Ability request.';
    }
}
