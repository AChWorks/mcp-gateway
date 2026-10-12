<?php

namespace App\Http\Middleware;

use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class EnsureCorrelationId
{
    public function handle(Request $request, Closure $next): Response
    {
        $correlationId = CorrelationId::current();
        $request->attributes->set(CorrelationId::ATTRIBUTE, $correlationId);

        $response = $next($request);
        $response->headers->set(CorrelationId::HEADER, $correlationId);

        // Catch otherwise unclassified 5xx responses without logging a second
        // time on MCP routes that also install this middleware locally.
        if ($response->getStatusCode() >= 500 && ! $request->attributes->get('gateway_error_logged')) {
            $request->attributes->set('gateway_error_logged', true);
            OperationDiagnostics::failure('http-response', 'server_error', null, [
                'http_status' => $response->getStatusCode(),
            ]);
        }

        return $response;
    }
}
