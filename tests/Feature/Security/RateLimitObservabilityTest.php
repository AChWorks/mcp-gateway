<?php

namespace Tests\Feature\Security;

use App\Support\CorrelationId;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Cache\RateLimiting\Unlimited;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Tests\TestCase;

final class RateLimitObservabilityTest extends TestCase
{
    use RefreshDatabase;

    public function test_mcp_edge_rate_limit_is_burst_aware_json_rpc_correlated_and_recorded(): void
    {
        $definition = RateLimiter::limiter('mcp-edge');
        self::assertIsCallable($definition);

        $probe = Request::create('/mcp', 'POST');
        $productionLimits = $definition($probe);
        self::assertIsArray($productionLimits);
        self::assertCount(2, $productionLimits);
        self::assertContainsOnlyInstancesOf(Limit::class, $productionLimits);
        self::assertSame(120, $productionLimits[0]->maxAttempts);
        self::assertSame(1, $productionLimits[0]->decaySeconds);
        self::assertSame(1200, $productionLimits[1]->maxAttempts);
        self::assertSame(60, $productionLimits[1]->decaySeconds);
        self::assertIsCallable($productionLimits[0]->responseCallback);
        self::assertIsCallable($productionLimits[1]->responseCallback);

        $responseCallback = $productionLimits[1]->responseCallback;
        RateLimiter::for('mcp-edge', static function (Request $request) use ($responseCallback): Limit {
            return Limit::perMinute(1)
                ->by('mcp-edge-test:'.$request->ip())
                ->response($responseCallback);
        });

        $payload = [
            'jsonrpc' => '2.0',
            'id' => 7,
            'method' => 'tools/list',
        ];

        $this->postJson('/mcp', $payload)->assertUnauthorized();

        $limited = $this->postJson('/mcp', $payload)
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertHeader(CorrelationId::HEADER)
            ->assertJsonPath('jsonrpc', '2.0')
            ->assertJsonPath('id', 7)
            ->assertJsonPath('error.data.reason', 'mcp_edge_rate_limited');

        $correlationId = (string) $limited->headers->get(CorrelationId::HEADER);
        self::assertTrue(Str::isUuid($correlationId));
        self::assertSame($correlationId, $limited->json('error.data.correlation_id'));

        self::assertDatabaseHas('activity_events', [
            'correlation_id' => $correlationId,
            'operation' => 'mcp-rate-limit',
            'outcome' => 'failure',
            'error_code' => 'mcp_edge_rate_limited',
        ]);
    }

    public function test_authenticated_mcp_limiter_allows_bursts_and_keeps_diagnostic_reason(): void
    {
        $definition = RateLimiter::limiter('mcp');
        self::assertIsCallable($definition);

        $request = Request::create('/mcp', 'POST', [
            'jsonrpc' => '2.0',
            'id' => 'principal-limit',
            'method' => 'tools/list',
        ]);
        $request->attributes->set('oauth_client_id', 'https://chatgpt.com/oauth/client.json');
        $request->attributes->set('oauth_user_id', '42');
        $this->app->instance('request', $request);

        $limits = $definition($request);
        self::assertIsArray($limits);
        self::assertCount(2, $limits);
        self::assertContainsOnlyInstancesOf(Limit::class, $limits);
        self::assertSame(60, $limits[0]->maxAttempts);
        self::assertSame(1, $limits[0]->decaySeconds);
        self::assertSame(600, $limits[1]->maxAttempts);
        self::assertSame(60, $limits[1]->decaySeconds);
        self::assertIsCallable($limits[0]->responseCallback);
        self::assertIsCallable($limits[1]->responseCallback);

        $response = ($limits[1]->responseCallback)($request, [
            'Retry-After' => 30,
            'X-RateLimit-Limit' => 600,
            'X-RateLimit-Remaining' => 0,
        ]);

        self::assertSame(429, $response->getStatusCode());
        self::assertSame('30', $response->headers->get('Retry-After'));

        $payload = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('mcp_principal_rate_limited', $payload['error']['data']['reason'] ?? null);
        self::assertTrue(Str::isUuid((string) ($payload['error']['data']['correlation_id'] ?? '')));

        self::assertDatabaseHas('activity_events', [
            'operation' => 'mcp-rate-limit',
            'outcome' => 'failure',
            'error_code' => 'mcp_principal_rate_limited',
        ]);
    }

    public function test_unauthenticated_options_bypasses_principal_limiter_but_keeps_edge_protection(): void
    {
        $principalDefinition = RateLimiter::limiter('mcp');
        self::assertIsCallable($principalDefinition);
        self::assertInstanceOf(
            Unlimited::class,
            $principalDefinition(Request::create('/mcp', 'OPTIONS')),
        );

        $edgeDefinition = RateLimiter::limiter('mcp-edge');
        self::assertIsCallable($edgeDefinition);

        $productionLimits = $edgeDefinition(Request::create('/mcp', 'OPTIONS'));
        self::assertIsArray($productionLimits);
        self::assertCount(2, $productionLimits);

        $responseCallback = $productionLimits[1]->responseCallback;
        self::assertIsCallable($responseCallback);

        RateLimiter::for('mcp-edge', static function (Request $request) use ($responseCallback): Limit {
            return Limit::perMinute(1)
                ->by('mcp-edge-options-test:'.$request->ip())
                ->response($responseCallback);
        });

        $first = $this->call('OPTIONS', '/mcp');
        self::assertNotSame(429, $first->getStatusCode());

        $this->call('OPTIONS', '/mcp')
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertJsonPath('error.data.reason', 'mcp_edge_rate_limited');
    }

    public function test_mcp_rate_limit_configuration_cannot_disable_protection_with_zero_values(): void
    {
        config()->set('mcp.rate_limits.edge.burst_per_second', 0);
        config()->set('mcp.rate_limits.edge.per_minute', 0);

        $definition = RateLimiter::limiter('mcp-edge');
        self::assertIsCallable($definition);

        $limits = $definition(Request::create('/mcp', 'POST'));
        self::assertIsArray($limits);
        self::assertCount(2, $limits);
        self::assertSame(1, $limits[0]->maxAttempts);
        self::assertSame(1, $limits[1]->maxAttempts);
    }

    public function test_oauth_token_throttle_is_correlated_recorded_and_does_not_store_token_input(): void
    {
        RateLimiter::for('oauth-token', static function (Request $request): Limit {
            return Limit::perMinute(1)->by('oauth-token-test:'.$request->ip());
        });

        $secretRefreshToken = 'refresh-secret-must-not-be-retained';
        $payload = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $secretRefreshToken,
        ];

        $first = $this->post('/oauth/token', $payload)
            ->assertStatus(400)
            ->assertHeader(CorrelationId::HEADER);
        self::assertTrue(Str::isUuid((string) $first->headers->get(CorrelationId::HEADER)));

        $limited = $this->post('/oauth/token', $payload)
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertHeader(CorrelationId::HEADER);

        $correlationId = (string) $limited->headers->get(CorrelationId::HEADER);
        self::assertTrue(Str::isUuid($correlationId));

        self::assertDatabaseHas('activity_events', [
            'correlation_id' => $correlationId,
            'operation' => 'oauth-token-refresh',
            'outcome' => 'failure',
            'error_code' => 'rate_limited',
        ]);

        $serialized = json_encode(DB::table('activity_events')->get()->all(), JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString($secretRefreshToken, $serialized);
        self::assertStringNotContainsString('refresh_token', $serialized);
        self::assertStringNotContainsString('client_assertion', $serialized);
    }
}
