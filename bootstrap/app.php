<?php

use App\Application\Admin\AdminLoginDestination;
use App\Application\Admin\AdminNavigation;
use App\Http\Middleware\EnsureCorrelationId;
use App\Http\Middleware\SecureAdminResponses;
use App\Models\User;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function (): void {
            Route::middleware([])->group(base_path('routes/mcp.php'));
        },
    )
    ->withCommands()
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->redirectUsersTo(static function (Request $request): string {
            $user = $request->user();

            return $user instanceof User
                ? app(AdminLoginDestination::class)->afterAuthentication($request, $user)
                : route('login');
        });
        // Only exact proxy addresses from config/trustedproxy.php are trusted.
        // In particular, never let Forwarded, X-Forwarded-Host or attacker
        // chosen Host headers alter the rate-limit client-IP boundary.
        $middleware->trustProxies(
            headers: Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_PROTO,
        );
        // Admin, OAuth, MCP and future HTTP routes share a request reference.
        // Existing MCP-local middleware reuses the attribute already set.
        $middleware->append(EnsureCorrelationId::class);
        // Enclose route matching, web CSRF and Admin authorization/throttles.
        // Appends inside the web group miss early 419/auth rejections.
        $middleware->prepend(SecureAdminResponses::class);
        // MCP routes are registered outside the stateful web middleware group.
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(static function (HttpExceptionInterface $exception, Request $request) {
            $user = $request->user();
            if ($exception->getStatusCode() !== 403 || ! $request->is('admin', 'admin/*')
                || $request->expectsJson() || ! $user instanceof User || ! $user->access_enabled) {
                return null;
            }

            return response()->view('admin.access-denied', [
                'recoveryUrl' => app(AdminNavigation::class)->landingUrl($user),
            ], 403);
        });
        // SSH secrets are not session-flashed after failed validation.
        $exceptions->dontFlash([
            'password', 'password_confirmation', 'current_password',
            'ssh_password', 'ssh_private_key', 'ssh_passphrase',
        ]);
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
