<?php

namespace Tests\Feature\Sites;

use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use GuzzleHttp\Exception\ResponseException as GuzzleResponseException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response as Psr7Response;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\RequestInterface;
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

    public function test_response_limit_is_normalized_across_success_and_error_statuses(): void
    {
        config()->set('bridge.http.max_response_bytes', 1024);

        foreach ([200, 404, 413, 500] as $status) {
            Http::swap(new OversizeTransportHttpFactory($status));

            /** @var SafeHttpClient $client */
            $client = app(SafeHttpClient::class);

            try {
                $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
                self::fail(sprintf('Oversize HTTP %d response was accepted.', $status));
            } catch (OutboundRequestException $exception) {
                self::assertSame('response_too_large', $exception->reason, 'Unexpected size-limit normalization for HTTP '.$status);
            }
        }
    }

    public function test_at_or_below_limit_http_errors_keep_their_existing_response_contract(): void
    {
        config()->set('bridge.http.max_response_bytes', 1024);

        foreach ([404, 500] as $status) {
            Http::swap(new Factory);
            Http::preventStrayRequests();
            Http::fake(fn (Request $request) => Http::response('small-'.$status, $status));

            /** @var SafeHttpClient $client */
            $client = app(SafeHttpClient::class);
            $response = $client->get('https://wp.example.test/.well-known/oauth-protected-resource');

            self::assertSame($status, $response->status);
            self::assertSame('small-'.$status, $response->body);
        }
    }

    public function test_policy_requests_disable_ambient_proxy_while_retaining_dns_pin(): void
    {
        config()->set('bridge.http.max_response_bytes', 1024);

        $factory = new CapturingHttpFactory;
        Http::swap($factory);
        $factory->preventStrayRequests();
        $factory->fake(fn (Request $request) => Factory::response(['ok' => true], 200));

        $previousHttpsProxy = getenv('HTTPS_PROXY');
        $previousLowerHttpsProxy = getenv('https_proxy');
        putenv('HTTPS_PROXY=http://proxy.example.test:8080');
        putenv('https_proxy=http://proxy.example.test:8080');

        try {
            /** @var SafeHttpClient $client */
            $client = app(SafeHttpClient::class);
            $response = $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
            self::assertSame(200, $response->status);
        } finally {
            $this->restoreEnvironmentVariable('HTTPS_PROXY', $previousHttpsProxy);
            $this->restoreEnvironmentVariable('https_proxy', $previousLowerHttpsProxy);
        }

        self::assertSame('', $factory->lastOptions[RequestOptions::PROXY] ?? null);
        self::assertFalse($factory->lastOptions[RequestOptions::STREAM] ?? false);
        self::assertArrayHasKey('curl', $factory->lastOptions);
        self::assertSame(
            ['wp.example.test:443:1.1.1.1'],
            $factory->lastOptions['curl'][CURLOPT_RESOLVE] ?? null,
        );
        $progress = $factory->lastOptions[RequestOptions::PROGRESS] ?? null;
        self::assertIsCallable($progress);
        self::assertFalse($progress(0, 1024, 0, 0));
        self::assertTrue($progress(0, 1025, 0, 0));
    }

    private function restoreEnvironmentVariable(string $name, string|false $value): void
    {
        if ($value === false) {
            putenv($name);

            return;
        }

        putenv($name.'='.$value);
    }
}

final class OversizeTransportHttpFactory extends Factory
{
    public function __construct(private readonly int $status)
    {
        parent::__construct();
    }

    protected function newPendingRequest(): PendingRequest
    {
        $request = parent::newPendingRequest();
        $status = $this->status;

        $request->setHandler(static function (RequestInterface $request, array $options) use ($status) {
            $sink = $options[RequestOptions::SINK] ?? null;
            if (! is_resource($sink)) {
                throw new \RuntimeException('Expected SafeHttpClient to provide a resource sink.');
            }

            @fwrite($sink, str_repeat('x', 1025));

            return Create::rejectionFor(new GuzzleResponseException(
                'Simulated response-body transport abort.',
                $request,
                new Psr7Response($status, ['Content-Type' => 'text/plain']),
            ));
        });

        return $request;
    }
}
final class CapturingHttpFactory extends Factory
{
    /** @var array<string, mixed> */
    public array $lastOptions = [];

    protected function newPendingRequest(): PendingRequest
    {
        $request = parent::newPendingRequest();
        $request->beforeSending(function (Request $request, array $options): void {
            $this->lastOptions = $options;
        });

        return $request;
    }
}
