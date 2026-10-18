<?php

namespace Tests\Feature\Sites;

use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use GuzzleHttp\Exception\NetworkTimeoutException as GuzzleNetworkTimeoutException;
use GuzzleHttp\Exception\ResponseException as GuzzleResponseException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response as Psr7Response;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Assert;
use Psr\Http\Message\RequestInterface;
use Tests\Support\PrivatePhpTempSpoolInspector;
use Tests\TestCase;

final class SafeHttpClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return ['1.1.1.1'];
            }
        });
        Http::preventStrayRequests();
    }

    public function test_chatgpt_signed_file_url_retains_private_query_and_bounded_integrity(): void
    {
        $bytes = "synthetic file bytes\0\xff";
        $url = 'https://files.oaiusercontent.com/private/file_123?sig=temporary%2Fopaque%3D&exp=123';
        Http::fake(fn (Request $request) => Http::response($bytes, 200));
        $received = app(SafeHttpClient::class)->getChatgptFile($url, 1024);
        self::assertSame(200, $received->status);
        self::assertSame($bytes, $received->body);
        Http::assertSent(fn (Request $request) => $request->url() === $url
            && $request->hasHeader('Accept', '*/*'));
    }

    public function test_chatgpt_streamed_file_uses_separate_bounded_disk_backed_budget(): void
    {
        // Deliberately larger than the shared 8-MiB in-memory response ceiling.
        $content = str_repeat("streamed\0binary\xff", 630000);
        $url = 'https://files.oaiusercontent.com/private/large?signature=opaque';
        Http::fake(fn (Request $request) => Http::response($content, 200, [
            'Content-Length' => (string) strlen($content),
        ]));
        $sink = fopen('php://temp/maxmemory:65536', 'w+b');
        self::assertIsResource($sink);
        try {
            $result = app(SafeHttpClient::class)->streamChatgptFile($url, strlen($content), $sink, 30);
            self::assertSame(200, $result->status);
            self::assertSame('', $result->body, 'The streamed path must not materialize the entire file in a JSON response.');
            self::assertSame(strlen($content), ftell($sink));
            self::assertSame(0, fseek($sink, 0));
            $digest = hash_init('sha256');
            self::assertGreaterThan(0, hash_update_stream($digest, $sink));
            self::assertSame(hash('sha256', $content), hash_final($digest));
            Http::assertSent(fn (Request $request) => $request->url() === $url
                && $request->hasHeader('Accept-Encoding', 'identity'));
        } finally {
            fclose($sink);
        }
    }

    public function test_chatgpt_http_transport_spills_directly_to_exactly_one_private_caller_spool(): void
    {
        // An actual Linux php://temp spill is measured DURING the HTTP
        // response, not only after SafeHttpClient closes internal resources.
        // The old HTTP-buffer-then-copy path would fail the sink-identity
        // check even though its post-download FD count looked correct.
        $payload = str_repeat('signed-file'.chr(0).chr(255), 25000);
        $url = 'https://files.oaiusercontent.com/private/direct?sig=opaque';
        $sink = fopen('php://temp/maxmemory:65536', 'w+b');
        self::assertIsResource($sink);
        $baseline = PrivatePhpTempSpoolInspector::openDiskSpools();
        $factory = new SingleSpoolTransportHttpFactory($payload, $sink, $baseline);

        // This exact-path Guzzle handler is a transport fixture, not a
        // Laravel facade fake. It cannot open a real outbound connection.
        Http::swap($factory);

        try {
            $result = app(SafeHttpClient::class)->streamChatgptFile($url, strlen($payload), $sink, 30);
            self::assertSame(200, $result->status);
            self::assertSame('', $result->body);
            self::assertTrue($factory->usedExactCallerSink, 'HTTP must write through the caller spool, not a second response spool.');
            self::assertGreaterThanOrEqual(2, count($factory->capturedDiskSpools), 'Multiple network body chunks must be observed.');
            foreach ($factory->capturedDiskSpools as $sample) {
                self::assertCount(1, $sample, 'No independent HTTP file copy may be open while the caller spool spills.');
                self::assertLessThanOrEqual(strlen($payload), array_sum($sample));
            }
            $open = PrivatePhpTempSpoolInspector::additionalSince($baseline);
            self::assertCount(1, $open);
            self::assertSame(strlen($payload), array_sum($open));
            self::assertSame(strlen($payload), ftell($sink));
            rewind($sink);
            self::assertSame(hash('sha256', $payload), hash('sha256', stream_get_contents($sink)));
        } finally {
            fclose($sink);
        }
        self::assertSame($baseline, PrivatePhpTempSpoolInspector::openDiskSpools(),
            'The borrowed spool must be fully released by its actual caller.');
    }

    public function test_chatgpt_streamed_file_rejects_short_body_and_encoded_payload(): void
    {
        $url = 'https://files.oaiusercontent.com/private/test?sig=x';
        $client = app(SafeHttpClient::class);
        foreach ([
            ['abc', ['Content-Length' => '5'], 'file_download_incomplete'],
            ['abc', ['Content-Encoding' => 'gzip'], 'unsupported_content_encoding'],
            ['not-found', [], 'file_download_unavailable', 404],
        ] as $case) {
            [$body, $headers, $expected] = $case;
            $status = $case[3] ?? 200;
            Http::swap(new Factory);
            Http::preventStrayRequests();
            Http::fake(fn (Request $request) => Http::response($body, $status, $headers));
            $sink = fopen('php://temp/maxmemory:65536', 'w+b');
            self::assertIsResource($sink);
            try {
                $client->streamChatgptFile($url, 1024, $sink, 5);
                self::fail('The incomplete, encoded or unavailable file was accepted.');
            } catch (OutboundRequestException $exception) {
                self::assertSame($expected, $exception->reason);
            } finally {
                fclose($sink);
            }
        }
    }

    public function test_chatgpt_streamed_file_refuses_oversize_and_untrusted_origin(): void
    {
        $client = app(SafeHttpClient::class);
        Http::fake(fn (Request $request) => Http::response(str_repeat('z', 1025), 200));
        $sink = fopen('php://temp/maxmemory:65536', 'w+b');
        self::assertIsResource($sink);
        try {
            $client->streamChatgptFile('https://files.oaiusercontent.com/private/large?sig=x', 1024, $sink, 5);
            self::fail('An oversized file was accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('response_too_large', $exception->reason);
        } finally {
            fclose($sink);
        }
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => Http::response('should never fetch'));
        $sink = fopen('php://temp/maxmemory:65536', 'w+b');
        self::assertIsResource($sink);
        try {
            $client->streamChatgptFile('https://evil.example.test/payload?sig=x', 1024, $sink, 5);
            self::fail('An untrusted file URL was accepted.');
        } catch (\Throwable) {
            Http::assertNothingSent();
        } finally {
            fclose($sink);
        }
    }

    public function test_chatgpt_signed_file_url_rejects_untrusted_hosts_before_http_dispatch(): void
    {
        Http::fake(fn (Request $request) => Http::response('should-not-arrive'));
        $client = app(SafeHttpClient::class);
        foreach ([
            'https://files.oaiusercontent.com.evil.example.test/x?sig=z',
            'https://files.oaiusercontent.com@evil.example.test/x?sig=z',
            'https://files.oaiusercontent.com:444/x?sig=z',
            'http://files.oaiusercontent.com/x?sig=z',
            'https://files.oaiusercontent.com/../private?sig=z',
            'https://files.oaiusercontent.com/x?sig=z#fragment',
        ] as $url) {
            $rejected = false;
            try {
                $client->getChatgptFile($url, 1024);
            } catch (\Throwable) {
                $rejected = true;
            }
            self::assertTrue($rejected, 'Untrusted file URL must be denied without dispatch.');
        }
        Http::assertNothingSent();
    }

    public function test_chatgpt_file_url_redirect_and_oversize_are_denied(): void
    {
        Http::fake(fn (Request $request) => Http::response('', 302, ['Location' => 'https://evil.example.test/']));
        $client = app(SafeHttpClient::class);
        try {
            $client->getChatgptFile('https://files.oaiusercontent.com/x?sig=z', 1024);
            self::fail('Redirect was accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('unsafe_redirect', $exception->reason);
        }
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => Http::response(str_repeat('z', 1030), 200));
        try {
            $client->getChatgptFile('https://files.oaiusercontent.com/x?sig=z', 1024);
            self::fail('An oversized file was accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('response_too_large', $exception->reason);
        }
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
            self::assertSame('tls_handshake', $exception->details['failure_stage']);
            self::assertTrue($exception->preDispatch, 'TLS setup failure could not transmit HTTP.');
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
            self::assertSame('tcp_connect', $exception->details['failure_stage']);
            self::assertTrue($exception->preDispatch, 'TCP refusal could not transmit HTTP.');
        }
        Http::assertSentCount(1);
    }

    public function test_post_send_network_timeout_remains_ambiguous_even_when_no_response_arrives(): void
    {
        Http::fake(static function (Request $request) {
            // Guzzle distinguishes an uncertain network transfer from
            // ConnectException: a previous HTTP request may have completed.
            return Create::rejectionFor(new GuzzleNetworkTimeoutException(
                'Operation timed out after sending request bytes.',
                $request->toPsrRequest(),
            ));
        });

        $client = app(SafeHttpClient::class);
        try {
            $client->postForm('https://wp.example.test/wp-json/wp-ai-bridge/v1/oauth/token', [
                'grant_type' => 'refresh_token',
            ]);
            self::fail('An uncertain token-exchange transfer must not be accepted.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('network_failure', $exception->reason);
            self::assertSame('request_timeout', $exception->details['failure_stage']);
            self::assertFalse($exception->preDispatch);
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
            self::assertSame(1024, $exception->details['limit_bytes']);
            self::assertContains($exception->details['phase'], ['decoded_body', 'content_length', 'collected_body', 'wire_progress']);
            self::assertArrayNotHasKey('body', $exception->details);
        }
    }

    public function test_readonly_tool_budget_is_distinct_from_the_base_metadata_budget(): void
    {
        config()->set('bridge.http.max_response_bytes', 1024);
        $body = str_repeat('a', 2048);
        Http::fake(fn (Request $request) => Http::response($body, 200));

        /** @var SafeHttpClient $client */
        $client = app(SafeHttpClient::class);
        $response = $client->postJson('https://wp.example.test/wp-json/wp-ai-bridge/v1/mcp', [], [], 4096);

        self::assertSame($body, $response->body);

        try {
            $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
            self::fail('Base metadata budget was unexpectedly raised by the tool override.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('response_too_large', $exception->reason);
            self::assertSame(1024, $exception->details['limit_bytes']);
        }
    }

    public function test_operator_config_cannot_disable_the_absolute_response_size_ceiling(): void
    {
        config()->set('bridge.http.max_response_bytes', PHP_INT_MAX);
        Http::fake(fn (Request $request) => Http::response(str_repeat('z', SafeHttpClient::ABSOLUTE_MAX_RESPONSE_BYTES + 1), 200));

        /** @var SafeHttpClient $client */
        $client = app(SafeHttpClient::class);

        try {
            $client->get('https://wp.example.test/.well-known/oauth-protected-resource');
            self::fail('Absolute response safety ceiling was bypassed.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('response_too_large', $exception->reason);
            self::assertSame(SafeHttpClient::ABSOLUTE_MAX_RESPONSE_BYTES, $exception->details['limit_bytes']);
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
                self::assertSame(1024, $exception->details['limit_bytes']);
                self::assertSame('decoded_body', $exception->details['phase']);
                self::assertSame(1025, $exception->details['observed_bytes']);
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

    public function test_outbound_https_transport_uses_remaining_request_budget_after_dns(): void
    {
        config()->set('bridge.http.connect_timeout_seconds', 2);
        config()->set('bridge.http.request_timeout_seconds', 2);
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                Assert::assertNotNull($deadlineNs);
                usleep(120_000);

                return ['1.1.1.1'];
            }
        });

        $factory = new CapturingHttpFactory;
        Http::swap($factory);
        $factory->preventStrayRequests();
        $factory->fake(fn (Request $request) => Factory::response(['ok' => true], 200));

        $client = app(SafeHttpClient::class);
        self::assertSame(200, $client->get('https://wp.example.test/mcp')->status);

        $remaining = $factory->lastOptions[RequestOptions::TIMEOUT] ?? null;
        $connect = $factory->lastOptions[RequestOptions::CONNECT_TIMEOUT] ?? null;
        self::assertIsFloat($remaining);
        self::assertGreaterThan(1, $remaining);
        self::assertLessThan(1.95, $remaining);
        self::assertLessThanOrEqual($remaining, $connect);
        self::assertSame(['wp.example.test:443:1.1.1.1'], $factory->lastOptions['curl'][CURLOPT_RESOLVE]);
    }

    public function test_expired_dns_budget_does_not_dispatch_a_remote_http_request(): void
    {
        config()->set('bridge.http.connect_timeout_seconds', 1);
        config()->set('bridge.http.request_timeout_seconds', 1);
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                usleep(1_070_000);

                return ['1.1.1.1'];
            }
        });

        Http::fake(fn (Request $request) => self::fail('No HTTP dispatch is permitted after DNS deadline.'));
        $client = app(SafeHttpClient::class);
        try {
            $client->postJson('https://wp.example.test/mcp', ['mutation' => true]);
            self::fail('Expired DNS budget was ignored.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('network_failure', $exception->reason);
            self::assertTrue($exception->preDispatch);
        }
        Http::assertNothingSent();
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

/**
 * The real Guzzle sink option is inspected at the network-writing boundary.
 * This fixture avoids any actual outbound request and writes multiple binary
 * chunks large enough for php://temp to spill to disk.
 */
final class SingleSpoolTransportHttpFactory extends Factory
{
    public bool $usedExactCallerSink = false;

    /** @var list<array<string,int>> */
    public array $capturedDiskSpools = [];

    /**
     * @param  resource  $expectedSink
     * @param  array<string,int>  $baseline
     */
    public function __construct(
        private readonly string $body,
        private $expectedSink,
        private readonly array $baseline,
    ) {
        parent::__construct();
    }

    protected function newPendingRequest(): PendingRequest
    {
        $request = parent::newPendingRequest();

        $request->setHandler(function (RequestInterface $request, array $options) {
            $sink = $options[RequestOptions::SINK] ?? null;
            if (! is_resource($sink)) {
                throw new \RuntimeException('The streaming request must supply a private resource sink.');
            }
            $this->usedExactCallerSink = $sink === $this->expectedSink;
            for ($offset = 0; $offset < strlen($this->body); $offset += 125000) {
                $chunk = substr($this->body, $offset, 125000);
                if (fwrite($sink, $chunk) !== strlen($chunk)) {
                    throw new \RuntimeException('Synthetic network sink write failed.');
                }
                $this->capturedDiskSpools[] = PrivatePhpTempSpoolInspector::additionalSince($this->baseline);
            }

            return Create::promiseFor(new Psr7Response(200,
                ['Content-Length' => (string) strlen($this->body)]));
        });

        return $request;
    }
}
