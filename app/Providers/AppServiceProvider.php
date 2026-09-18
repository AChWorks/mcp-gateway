<?php

namespace App\Providers;

use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\SystemDnsResolver;
use App\Support\CorrelationId;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(DnsResolver::class, SystemDnsResolver::class);
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

        RateLimiter::for('admin-login', static function (Request $request) {
            $email = Str::lower(trim((string) $request->input('email', '')));
            $identity = hash('sha256', (string) $request->ip()."\0".$email);

            return [
                Limit::perMinute(20)->by('admin-login-ip:'.$request->ip()),
                Limit::perMinute(5)->by('admin-login-identity:'.$identity),
            ];
        });

        RateLimiter::for('mcp-edge', function (Request $request): array {
            return $this->mcpRateLimits(
                (int) config('mcp.rate_limits.edge.burst_per_second', 120),
                (int) config('mcp.rate_limits.edge.per_minute', 1200),
                'mcp-edge:'.$request->ip(),
                'mcp_edge_rate_limited',
            );
        });

        RateLimiter::for('mcp', function (Request $request) {
            $client = $request->attributes->get('oauth_client_id');
            $user = $request->attributes->get('oauth_user_id');

            if (! is_string($client)
                || $client === ''
                || (! is_string($user) && ! is_int($user))
                || (string) $user === '') {
                return Limit::none();
            }

            return $this->mcpRateLimits(
                (int) config('mcp.rate_limits.principal.burst_per_second', 60),
                (int) config('mcp.rate_limits.principal.per_minute', 600),
                'mcp:'.$client.':'.(string) $user,
                'mcp_principal_rate_limited',
            );
        });
    }

    /**
     * @return array<int, Limit>
     */
    private function mcpRateLimits(
        int $burstPerSecond,
        int $perMinute,
        string $key,
        string $errorCode,
    ): array {
        $burstPerSecond = max(1, $burstPerSecond);
        $perMinute = max(1, $perMinute);
        $response = static function (Request $request, array $headers) use ($errorCode) {
            $correlationId = CorrelationId::current();
            app(ActivityRecorder::class)->record(
                $correlationId,
                'mcp-rate-limit',
                'failure',
                null,
                $errorCode,
            );

            $id = $request->input('id');
            if (! is_int($id) && ! is_string($id)) {
                $id = null;
            }

            return response()->json([
                'jsonrpc' => '2.0',
                'id' => $id,
                'error' => [
                    'code' => -32000,
                    'message' => 'MCP request rate limit exceeded. Retry after the advertised delay.',
                    'data' => [
                        'reason' => $errorCode,
                        'correlation_id' => $correlationId,
                    ],
                ],
            ], 429, $headers)->header('Cache-Control', 'no-store');
        };

        return [
            Limit::perSecond($burstPerSecond)
                ->by($key.':burst')
                ->response($response),
            Limit::perMinute($perMinute)
                ->by($key.':sustained')
                ->response($response),
        ];
    }
}
