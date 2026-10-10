<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\TargetMcpToolHandlers;
use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use App\Models\User;
use Illuminate\Http\Request;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server;
use Mcp\Server\Session\FileSessionStore;
use Mcp\Server\Transport\Http\Middleware\CorsMiddleware;
use Mcp\Server\Transport\Http\Middleware\DnsRebindingProtectionMiddleware;
use Mcp\Server\Transport\StreamableHttpTransport;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

final readonly class GatewayMcpEndpoint
{
    public function __construct(
        private TargetMcpToolHandlers $handlers,
        private WordpressTargetMcpToolHandlers $wordpress,
        private SshCommandMcpToolHandlers $sshCommands,
    ) {}

    public function handle(Request $request): Response
    {
        // Expose only operationally implemented tool families. Connector
        // execution tools will be enabled after their runtime/credentials land.
        $server = Server::builder()
            ->setServerInfo(
                name: 'mcp-gateway',
                version: (string) config('app.release_version'),
                description: 'Authenticated Target-aware MCP Gateway.',
            )
            ->setSession(new FileSessionStore(
                directory: storage_path('framework/mcp-sessions'),
                ttl: max(60, (int) config('oauth.mcp.session_ttl_seconds')),
            ))
            ->addTool(
                handler: fn (
                    ?string $cursor = null,
                    int $limit = 100,
                    ?string $search = null,
                    ?string $connection_state = null,
                    ?string $connector_type = null,
                ): array => $this->handlers->targetsList(
                    $this->user($request),
                    $cursor,
                    $limit,
                    $search,
                    $connection_state,
                    $connector_type,
                ),
                name: 'targets-list',
                description: 'List authorized registered Targets without fetching remote data.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'cursor' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 100],
                        'search' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 160],
                        'connection_state' => [
                            'type' => 'string',
                            'enum' => ['disconnected', 'pending', 'connected', 'reassigning', 'reconnect_required', 'error'],
                        ],
                        'connector_type' => [
                            'type' => 'string',
                            'enum' => ['wp_ai_bridge', 'ssh_direct'],
                        ],
                    ],
                    'required' => [],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id): array => $this->handlers->targetContext(
                    $this->user($request),
                    $target_id,
                ),
                name: 'target-context',
                description: 'Inspect safe stored context for one authorized Target.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                    ],
                    'required' => ['target_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id,
                    ?string $ability = null,
                    int $page = 1,
                    int $per_page = 10,
                    ?string $namespace = null,
                    ?string $search = null,
                ): array => $this->wordpress->read(
                    $this->user($request), $target_id, $ability, $page, $per_page, $namespace, $search,
                ),
                name: 'wordpress-abilities-read',
                description: 'Read WordPress Ability metadata for an explicitly authorized Target.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'ability' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                        'page' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1],
                        'per_page' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 10],
                        'namespace' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                        'search' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                    ],
                    'required' => ['target_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $ability, array $input = []): array => $this->wordpress->execute($this->user($request), $target_id, $ability, $input),
                name: 'wordpress-ability-execute',
                description: 'Execute one explicitly authorized WordPress Ability with runtime safety-class enforcement.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'ability' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                        // MCP SDK normalizes an empty JSON object to an
                        // empty PHP array during schema validation. Admit only
                        // that zero-item array representation, not arbitrary
                        // JSON arrays, and keep the downstream object shape.
                        'input' => [
                            'anyOf' => [
                                ['type' => 'object'],
                                ['type' => 'array', 'maxItems' => 0],
                            ],
                        ],
                    ],
                    'required' => ['target_id', 'ability'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $command, int $timeout_seconds = 10): array => $this->sshCommands->run(
                    $this->user($request), $target_id, $command, $timeout_seconds,
                ),
                name: 'ssh-command-run',
                description: 'Run one arbitrary non-interactive OS-account command on an explicitly authorized, host-key-pinned SSH Target. sudo/root privileges are controlled by the remote OS, not sandboxed by Gateway. No automatic retry.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'command' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 8192],
                        'timeout_seconds' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 15, 'default' => 10],
                    ],
                    'required' => ['target_id', 'command'],
                    'additionalProperties' => false,
                ],
            )
            ->build();

        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        if (! is_string($host) || $host === '') {
            return new Response('Gateway MCP resource host is misconfigured.', 503);
        }

        $psrRequest = (new PsrHttpFactory)->createRequest($request);
        $transport = new StreamableHttpTransport(
            request: $psrRequest,
            middleware: [
                new CorsMiddleware,
                new DnsRebindingProtectionMiddleware([$host]),
            ],
            maxBodyBytes: max(1024, (int) config('oauth.mcp.max_body_bytes')),
        );
        $psrResponse = $server->run($transport);

        return (new HttpFoundationFactory)->createResponse($psrResponse, true);
    }

    private function user(Request $request): User
    {
        $user = $request->attributes->get('oauth_user');
        if (! $user instanceof User) {
            abort(401);
        }

        return $user;
    }
}
