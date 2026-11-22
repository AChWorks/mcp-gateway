<?php

namespace App\Infrastructure\Mcp;

use Illuminate\Http\Request;
use Mcp\Server;
use Mcp\Server\Session\FileSessionStore;
use Mcp\Server\Transport\Http\Middleware\CorsMiddleware;
use Mcp\Server\Transport\Http\Middleware\DnsRebindingProtectionMiddleware;
use Mcp\Server\Transport\StreamableHttpTransport;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

/** Transport and verified session boundary; tool registration is delegated. */
final readonly class GatewayMcpEndpoint
{
    public function handle(Request $request): Response
    {
        $builder = Server::builder()
            ->setServerInfo(
                name: 'mcp-gateway',
                version: (string) config('app.release_version'),
                description: 'Authenticated Target-aware MCP Gateway.',
            )
            ->setSession(new FileSessionStore(
                directory: storage_path('framework/mcp-sessions'),
                ttl: max(60, (int) config('oauth.mcp.session_ttl_seconds')),
            ));

        // Preserve the verified v2 ordering and dynamic tool schemas. A future
        // discovery strategy cannot alter the actual operation executors.
        // Laravel caches route-controller instances in a long-lived Router.
        // Resolve registrars on each invocation rather than in its constructor:
        // otherwise their request-scoped OperationalSettings may be stale on
        // subsequent requests. Keep the direct handle(Request) contract too.
        app(TargetMcpToolRegistrar::class)->register($builder, $request);
        app(WordpressMcpToolRegistrar::class)->register($builder, $request);
        app(ArvanMcpToolRegistrar::class)->register($builder, $request);
        app(FileTransferMcpToolRegistrar::class)->register($builder, $request);
        app(SshMcpToolRegistrar::class)->register($builder, $request);
        app(TargetBatchMcpToolRegistrar::class)->register($builder, $request);

        $server = $builder->build();

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
}
