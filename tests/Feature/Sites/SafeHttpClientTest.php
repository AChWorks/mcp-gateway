<?php

namespace Tests\Feature\Sites;

use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

final class SafeHttpClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                return ['1.1.1.1'];
            }
        });
        Http::preventStrayRequests();
    }

    public function test_redirects_are_not_followed(): void
    {
        Http::fake(fn (Request $request) => Http::response('', 302, [
            'Location' => 'https://other.example.test/metadata',
        ]));

        /** @var SafeHttpClient $client */
        $client = app(SafeHttpClient::class);

        try {
            $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
            self::fail('Redirect was followed or accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('unsafe_redirect', $exception->reason);
        }

        Http::assertSentCount(1);
    }

    public function test_tls_connection_failure_is_classified_without_retry(): void
    {
        Http::fake(['*' => Http::failedConnection('SSL certificate problem')]);
        /** @var SafeHttpClient $client */
        $client = app(SafeHttpClient::class);

        try {
            $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
            self::fail('TLS failure was accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('tls_failure', $exception->reason);
        }
        Http::assertSentCount(1);
    }

    public function test_network_connection_failure_is_classified_without_retry(): void
    {
        Http::fake(['*' => Http::failedConnection('Connection refused')]);
        /** @var SafeHttpClient $client */
        $client = app(SafeHttpClient::class);

        try {
            $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
            self::fail('Network failure was accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('network_failure', $exception->reason);
        }
        Http::assertSentCount(1);
    }

    public function test_response_body_is_bounded(): void
    {
        config()->set('bridge.http.max_response_bytes', 1024);
        Http::fake(fn (Request $request) => Http::response(str_repeat('x', 1025), 200));

        /** @var SafeHttpClient $client */
        $client = app(SafeHttpClient::class);

        try {
            $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
            self::fail('Oversize response was accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('response_too_large', $exception->reason);
        }
    }
}
