<?php

namespace App\Http\Middleware;

use App\Support\CorrelationId;
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

        return $response;
    }
}
