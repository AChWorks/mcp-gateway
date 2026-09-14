<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Concrete OAuth/MCP services are constructor-injected and autowired.
    }

    public function boot(): void
    {
        RateLimiter::for('oauth-token', static function (Request $request): Limit {
            return Limit::perMinute(30)->by('oauth-token:'.$request->ip());
        });

        RateLimiter::for('oauth-browser', static function (Request $request): Limit {
            $actor = $request->user()?->getAuthIdentifier() ?? $request->ip();

            return Limit::perMinute(30)->by('oauth-browser:'.$actor);
        });

        RateLimiter::for('mcp-edge', static function (Request $request): Limit {
            return Limit::perMinute(240)->by('mcp-edge:'.$request->ip());
        });

        RateLimiter::for('mcp', static function (Request $request): Limit {
            $client = (string) $request->attributes->get('oauth_client_id', 'unauthenticated');
            $user = (string) $request->attributes->get('oauth_user_id', 'unknown');

            return Limit::perMinute(120)->by('mcp:'.$client.':'.$user);
        });
    }
}
