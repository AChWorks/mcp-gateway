<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\PendingGatewayToolHandlers;
use App\Models\User;
use Illuminate\Http\Request;
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
    public function __construct(private PendingGatewayToolHandlers $handlers) {}

    public function handle(Request $request): Response
    {
        $server = Server::builder()
            ->setServerInfo(
                name: 'mcp-gateway',
                version: '0.1.0',
                description: 'Authenticated multi-site MCP Gateway.',
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
                ): array => $this->handlers->sitesList(
                    $this->user($request),
                    $cursor,
                    $limit,
                    $search,
                    $connection_state,
                ),
                name: 'sites-list',
                description: 'List configured Gateway sites without exposing credentials.',
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'cursor' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 100],
                        'search' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 160],
                        'connection_state' => [
                            'type' => 'string',
                            'enum' => [
                                'disconnected',
                                'pending',
                                'connected',
                                'reassigning',
                                'reconnect_required',
                                'error',
                            ],
                        ],
                    ],
                    'required' => [],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $site_id): array => $this->handlers->siteContext(
                    $this->user($request),
                    $site_id,
                ),
                name: 'site-context',
                description: 'Inspect the context and connection state of one explicit site.',
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'site_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 128],
                    ],
                    'required' => ['site_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $site_id,
                    ?string $ability = null,
                    int $page = 1,
                    int $per_page = 10,
                    ?string $namespace = null,
                    ?string $search = null,
                ): array => $this->handlers->siteAbilitiesRead(
                    $this->user($request),
                    $site_id,
                    $ability,
                    $page,
                    $per_page,
                    $namespace,
                    $search,
                ),
                name: 'site-abilities-read',
                description: 'List or inspect current WP AI Bridge Ability contracts for one explicit site.',
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'site_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 128],
                        'ability' => ['type' => ['string', 'null'], 'minLength' => 1, 'maxLength' => 255],
                        'page' => ['type' => 'integer', 'minimum' => 1, 'default' => 1],
                        'per_page' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 10],
                        'namespace' => ['type' => ['string', 'null'], 'minLength' => 1, 'maxLength' => 255],
                        'search' => ['type' => ['string', 'null'], 'minLength' => 1, 'maxLength' => 255],
                    ],
                    'required' => ['site_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $site_id, string $ability, array $input): array => $this->handlers
                    ->siteAbilityExecute($this->user($request), $site_id, $ability, $input),
                name: 'site-ability-execute',
                description: 'Execute one exact downstream Ability against one explicit site.',
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'site_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 128],
                        'ability' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                        'input' => [
                            'oneOf' => [
                                ['type' => 'object'],
                                ['type' => 'array', 'maxItems' => 0],
                            ],
                        ],
                    ],
                    'required' => ['site_id', 'ability', 'input'],
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
