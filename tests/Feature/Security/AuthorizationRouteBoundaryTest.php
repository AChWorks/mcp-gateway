<?php

namespace Tests\Feature\Security;

use App\Http\Middleware\CorrelatedAdminFeedback;
use App\Http\Middleware\EnsureCorrelationId;
use App\Http\Middleware\EnsureLocalUserAccessEnabled;
use App\Http\Middleware\RequireMcpAccessToken;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

/**
 * Future Admin and MCP entrypoints cannot bypass the shared principal gate.
 * These are route-level invariants; operation-specific grants are verified by
 * AccessControl and endpoint authorization tests, not by route names alone.
 */
final class AuthorizationRouteBoundaryTest extends TestCase
{
    public function test_every_authenticated_admin_route_keeps_local_session_disabled_user_and_feedback_boundaries(): void
    {
        $covered = 0;
        foreach (Route::getRoutes() as $route) {
            if (($route->uri() !== 'admin' && ! str_starts_with($route->uri(), 'admin/'))
                || $route->uri() === 'admin/login') {
                continue;
            }
            $covered++;
            $middleware = $route->gatherMiddleware();
            self::assertContains('auth', $middleware, $route->uri());
            self::assertContains(EnsureLocalUserAccessEnabled::class, $middleware, $route->uri());
            self::assertContains('throttle:admin-mutation', $middleware, $route->uri());
            self::assertContains(CorrelatedAdminFeedback::class, $middleware, $route->uri());
        }
        self::assertGreaterThan(50, $covered, 'The Admin boundary scan must include actual mounted routes.');
    }

    public function test_every_target_capable_mcp_route_requires_verified_bearer_and_rate_limits(): void
    {
        $covered = 0;
        foreach (Route::getRoutes() as $route) {
            if ($route->uri() !== 'mcp' && ! str_starts_with($route->uri(), 'mcp/')
                && ! str_contains($route->getActionName(), 'App\\Http\\Controllers\\Mcp\\')
                && ! str_contains($route->getActionName(), 'GatewayMcpEndpoint')) {
                continue;
            }
            $covered++;
            $middleware = $route->gatherMiddleware();
            self::assertContains(RequireMcpAccessToken::class, $middleware, $route->uri());
            self::assertContains('throttle:mcp-edge', $middleware, $route->uri());
            self::assertContains('throttle:mcp', $middleware, $route->uri());
            self::assertContains(EnsureCorrelationId::class, $middleware, $route->uri());
        }
        self::assertGreaterThanOrEqual(3, $covered, 'The MCP boundary scan must include registered tools and whole-file edges.');
    }
}
