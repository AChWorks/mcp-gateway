<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\TargetMcpToolHandlers;
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
    public function __construct(private TargetMcpToolHandlers $handlers) {}

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
