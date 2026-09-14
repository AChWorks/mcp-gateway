<?php

namespace App\Infrastructure\Mcp;

use Illuminate\Http\Request;
use Mcp\Server;
use Mcp\Server\Session\FileSessionStore;
use Mcp\Server\Transport\StreamableHttpTransport;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

final class BootstrapMcpEndpoint
{
    public function handle(Request $request): Response
    {
        if (config('app.env') !== 'testing' || ! config('mcp.bootstrap_fixture.enabled')) {
            return new Response('Not Found', 404);
        }

        $expectedToken = config('mcp.bootstrap_fixture.token');

        if (! is_string($expectedToken) || $expectedToken === '') {
            return new Response('MCP bootstrap fixture is misconfigured.', 503);
        }

        $presentedToken = $request->bearerToken();

        if (! is_string($presentedToken) || ! hash_equals($expectedToken, $presentedToken)) {
            return new Response('Unauthorized', 401, ['WWW-Authenticate' => 'Bearer']);
        }

        $server = Server::builder()
            ->setServerInfo(
                name: 'mcp-gateway-bootstrap',
                version: '0.1.0',
                description: 'MCP Gateway bootstrap compatibility fixture.',
            )
            ->setSession(new FileSessionStore(
                directory: storage_path('framework/mcp-sessions'),
                ttl: max(60, (int) config('mcp.server.session_ttl_seconds')),
            ))
            ->addTool(
                handler: static fn (): array => ['status' => 'ok'],
                name: 'gateway.bootstrap.ping',
                description: 'Return a deterministic bootstrap response.',
                inputSchema: [
                    'type' => 'object',
                    'properties' => [],
                    'required' => [],
                ],
                outputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'status' => ['type' => 'string'],
                    ],
                    'required' => ['status'],
                    'additionalProperties' => false,
                ],
            )
            ->build();

        $psrRequest = (new PsrHttpFactory)->createRequest($request);
        $psrResponse = $server->run(new StreamableHttpTransport($psrRequest));

        return (new HttpFoundationFactory)->createResponse($psrResponse, true);
    }
}
