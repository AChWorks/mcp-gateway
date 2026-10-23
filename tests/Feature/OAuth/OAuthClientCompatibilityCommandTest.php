<?php

namespace Tests\Feature\OAuth;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

final class OAuthClientCompatibilityCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
    }

    public function test_diagnostic_distinguishes_sanitized_upstream_http_404_from_503(): void
    {
        foreach ([404, 503] as $status) {
            $client = new Client(['handler' => HandlerStack::create(new MockHandler([
                new Response($status, ['Content-Type' => 'text/plain'], 'raw-secret-body-not-for-logs'),
            ]))]);
            $this->app->instance(ChatGptClientMetadata::class, new ChatGptClientMetadata($client));
            self::assertSame(1, Artisan::call('gateway:oauth-client-check', ['--refresh' => true]));

            $output = Artisan::output();
            self::assertStringContainsString('upstream HTTP '.$status, $output);
            self::assertStringNotContainsString('raw-secret-body', $output);
            self::assertStringNotContainsString('https://chatgpt.com', $output);
        }
    }

    public function test_diagnostic_classifies_transport_errors_without_echoing_private_request_details(): void
    {
        $client = new Client(['handler' => HandlerStack::create(new MockHandler([
            new ConnectException('private-proxy-information', new Request('GET',
                'https://chatgpt.com/oauth/client.json?test_secret=do-not-log')),
        ]))]);
        $this->app->instance(ChatGptClientMetadata::class, new ChatGptClientMetadata($client));

        self::assertSame(1, Artisan::call('gateway:oauth-client-check', ['--refresh' => true]));
        self::assertStringContainsString('upstream transport unavailable', Artisan::output());
        self::assertStringNotContainsString('do-not-log', Artisan::output());
        self::assertStringNotContainsString('private-proxy-information', Artisan::output());
    }
}
