<?php

namespace Tests\Feature\OAuth;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

final class ClientEdgeProxyRateLimitTest extends TestCase
{
    protected function tearDown(): void
    {
        TrustProxies::flushState();
        parent::tearDown();
    }

    public function test_untrusted_forwarded_values_and_spoofed_host_cannot_choose_a_rate_limit_ip(): void
    {
        Route::get('/_test/client-ip', static fn (Request $request) => response()->json([
            'ip' => $request->ip(),
            'host' => $request->getHost(),
        ]))->middleware('web');

        self::assertSame([], config('trustedproxy.proxies'));

        $this->withServerVariables(['REMOTE_ADDR' => '10.75.20.5', 'HTTP_HOST' => 'spoofed.on-forge.com'])
            ->withHeaders([
                'Host' => 'spoofed.on-forge.com',
                'X-Forwarded-For' => '198.51.100.77',
                'Forwarded' => 'for=203.0.113.42',
                'X-Forwarded-Host' => 'untrusted.example.test',
            ])
            ->get('/_test/client-ip')->assertOk()
            ->assertJsonPath('ip', '10.75.20.5')
            ->assertJsonPath('host', 'spoofed.on-forge.com');
    }

    public function test_explicit_proxy_only_trusts_the_exact_configured_forwarder(): void
    {
        Route::get('/_test/client-ip', static fn (Request $request) => response()->json([
            'ip' => $request->ip(),
            'secure' => $request->isSecure(),
            'host' => $request->getHost(),
        ]))->middleware('web');
        TrustProxies::at(['10.75.20.5']);

        $this->withServerVariables(['REMOTE_ADDR' => '10.75.20.5', 'HTTP_HOST' => 'gateway.example.test'])
            ->withHeaders([
                'Host' => 'gateway.example.test',
                'X-Forwarded-For' => '203.0.113.42',
                'X-Forwarded-Proto' => 'https',
                'X-Forwarded-Host' => 'spoofed.invalid',
                'Forwarded' => 'for=198.51.100.10',
            ])
            ->get('/_test/client-ip')->assertOk()
            ->assertJsonPath('ip', '203.0.113.42')
            ->assertJsonPath('secure', true)
            ->assertJsonPath('host', 'gateway.example.test');

        $this->withServerVariables(['REMOTE_ADDR' => '10.75.20.6'])
            ->get('/_test/client-ip')->assertOk()
            ->assertJsonPath('ip', '10.75.20.6');
    }

    public function test_authenticated_rate_limits_are_bound_to_profile_client_and_user_not_headers(): void
    {
        $limiter = RateLimiter::limiter('mcp');
        self::assertNotNull($limiter);

        $request = static function (string $profile, string $client, int $user): Request {
            $request = Request::create('/mcp', 'POST', server: [
                'REMOTE_ADDR' => '192.0.2.5',
                'HTTP_X_FORWARDED_FOR' => '203.0.113.88',
            ]);
            $request->attributes->set('oauth_client_profile_key', $profile);
            $request->attributes->set('oauth_client_id', $client);
            $request->attributes->set('oauth_user_id', $user);

            return $request;
        };
        $chat = $limiter($request('chatgpt', 'https://chatgpt.com/oauth/client.json', 7));
        $fixture = $limiter($request('fixture', 'https://agent.example.test/oauth/client.json', 7));
        $otherUser = $limiter($request('chatgpt', 'https://chatgpt.com/oauth/client.json', 8));
        $repeat = $limiter($request('chatgpt', 'https://chatgpt.com/oauth/client.json', 7));

        self::assertCount(2, $chat);
        self::assertSame($chat[0]->key, $repeat[0]->key);
        self::assertNotSame($chat[0]->key, $fixture[0]->key);
        self::assertNotSame($chat[0]->key, $otherUser[0]->key);

        $missing = $request('chatgpt', 'https://chatgpt.com/oauth/client.json', 7);
        $missing->attributes->remove('oauth_client_profile_key');
        $fallback = $limiter($missing);
        self::assertNotSame($chat[0]->key, $fallback->key);
        self::assertSame(1, $fallback->maxAttempts);
    }
}
