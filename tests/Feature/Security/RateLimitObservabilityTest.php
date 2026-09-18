<?php

namespace Tests\Feature\Security;

use App\Infrastructure\Activity\ActivityRecorder;
use App\Support\CorrelationId;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Tests\TestCase;

final class RateLimitObservabilityTest extends TestCase
{
    use RefreshDatabase;

    public function test_mcp_edge_rate_limit_is_json_rpc_correlated_and_recorded(): void
    {
        $definition = RateLimiter::limiter('mcp-edge');
        self::assertIsCallable($definition);

        $probe = Request::create('/mcp', 'POST');
        $productionLimit = $definition($probe);
        self::assertInstanceOf(Limit::class, $productionLimit);
        self::assertSame(240, $productionLimit->maxAttempts);
        self::assertIsCallable($productionLimit->responseCallback);

        $responseCallback = $productionLimit->responseCallback;
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

    public function test_authenticated_mcp_limiter_keeps_current_bound_and_diagnostic_reason(): void
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

        $limit = $definition($request);
        self::assertInstanceOf(Limit::class, $limit);
        self::assertSame(120, $limit->maxAttempts);
        self::assertIsCallable($limit->responseCallback);

        $response = ($limit->responseCallback)($request, [
            'Retry-After' => 30,
            'X-RateLimit-Limit' => 120,
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
