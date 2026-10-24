<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class SecureAdminResponses
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if ($request->is('admin', 'admin/*')) {
            $response->headers->set('Cache-Control', 'private, no-store');
            $response->headers->set('X-Content-Type-Options', 'nosniff');
            $response->headers->set('X-Frame-Options', 'DENY');
            $response->headers->set('Referrer-Policy', 'no-referrer');
            // Frame, object and form restrictions without breaking the
            // existing inline form JS. This is not a full XSS policy.
            $response->headers->set(
                'Content-Security-Policy',
                "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'",
            );
        }

        return $response;
    }
}
