<?php

namespace Tests\Feature\Mcp;

use App\Domain\Targets\Target;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Mcp\BoundMcpTarget;
use App\Infrastructure\Mcp\OutboundMcpFailure;
use App\Infrastructure\Mcp\RequestOnlyMcpClient;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use Tests\TestCase;

final class RequestOnlyDownstreamMcpTest extends TestCase
{
    use RefreshDatabase;

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

    public function test_modern_bridge_wire_discover_catalog_and_unfamiliar_compatible_tool(): void
    {
        $target = $this->target('bridge-one');
        $bound = $this->bound($target);
        $observed = [];

        Http::fake(function (Request $request) use (&$observed) {
            $json = $request->data();
            $method = $json['method'] ?? null;
            $observed[] = [$method, $request->url()];
            self::assertSame('https://bridge-one.example.test/mcp', $request->url());
            self::assertTrue($request->hasHeader('Authorization', 'Bearer scoped-product-user-one'));
            self::assertTrue($request->hasHeader('Accept', 'application/json, text/event-stream'));
            self::assertTrue($request->hasHeader('MCP-Protocol-Version', RequestOnlyMcpClient::PROTOCOL_VERSION));
            self::assertTrue($request->hasHeader('Mcp-Method', $method));
            self::assertTrue($request->hasHeader('X-MCP-Gateway-Correlation-ID', 'request-123'));
            self::assertSame('2.0', $json['jsonrpc']);
            self::assertSame('2026-07-28', $json['params']['_meta']['io.modelcontextprotocol/protocolVersion']);
            self::assertEquals((object) [], $json['params']['_meta']['io.modelcontextprotocol/clientCapabilities']);
            self::assertArrayNotHasKey('actor', $json['params']);
            self::assertFalse($request->hasHeader('Mcp-Session-Id'));

            $result = match ($method) {
                'server/discover' => [
                    'resultType' => 'complete',
                    'supportedVersions' => ['2025-11-25', '2026-07-28'],
                    'capabilities' => ['tools' => []],
                ],
                'tools/list' => ['tools' => [[
                    'name' => 'notes.unfamiliar_new_operation',
                    'inputSchema' => ['type' => 'object', 'properties' => ['text' => ['type' => 'string']]],
                    'annotations' => ['readOnlyHint' => false],
                ]]],
                'tools/call' => ['content' => [], 'structuredContent' => [
                    'text' => $json['params']['arguments']['text'] ?? null,
                    'subject' => 'product-user-one',
                ]],
                default => throw new \LogicException('Unexpected MCP method'),
            };
            if ($method === 'tools/call') {
                self::assertTrue($request->hasHeader('Mcp-Name', 'notes.unfamiliar_new_operation'));
                self::assertSame('notes.unfamiliar_new_operation', $json['params']['name']);
            }

            return $this->rpc($request, $result);
        });

        $client = app(RequestOnlyMcpClient::class);
        self::assertContains('2026-07-28', $client->discover($target, $bound, 'request-123')['supportedVersions']);
        $tools = $client->listTools($target, $bound, 'request-123');
        self::assertCount(1, $tools['tools']);
        self::assertNull($tools['next_cursor']);
        $result = $client->callTool($target, $bound, 'notes.unfamiliar_new_operation', ['text' => 'hello'], true, 'request-123');
        self::assertSame('hello', $result['structuredContent']['text']);
        self::assertSame('product-user-one', $result['structuredContent']['subject']);
        self::assertSame([
            ['server/discover', 'https://bridge-one.example.test/mcp'],
            ['tools/list', 'https://bridge-one.example.test/mcp'],
            ['tools/call', 'https://bridge-one.example.test/mcp'],
        ], $observed);
        Http::assertSentCount(3);
    }

    public function test_target_identity_pause_and_disconnected_fences_reject_before_http(): void
    {
        $target = $this->target('bridge-a');
        $other = $this->target('bridge-b');
        $bound = $this->bound($target);
        Http::fake(fn (Request $request) => $this->rpc($request, ['tools' => []]));
        $client = app(RequestOnlyMcpClient::class);

        foreach ([
            fn () => $client->listTools($other, $bound, 'corr-one'),
            function () use ($client, $target, $bound): void {
                $target->forceFill(['operations_paused' => true])->save();
                $client->listTools($target, $bound, 'corr-one');
            },
        ] as $action) {
            try {
                $action();
                self::fail('Unbound or paused Target was accepted.');
            } catch (OutboundMcpFailure $exception) {
                self::assertSame('not_executed', $exception->outcome);
                self::assertSame('admission', $exception->phase);
            }
        }

        $target->forceFill(['operations_paused' => false, 'connection_state' => 'disconnected'])->save();
        try {
            $client->listTools($target, $bound, 'corr-one');
            self::fail('Disconnected Target was accepted.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('target_unavailable', $exception->reason);
        }
        Http::assertNothingSent();
    }

    public function test_wrong_resource_and_invalid_product_token_are_not_silently_rebound(): void
    {
        $target = $this->target('bridge-one');
        $bound = $this->bound($target);
        Http::fake(function (Request $request) {
            self::assertSame('https://bridge-one.example.test/mcp', $request->url());
            self::assertTrue($request->hasHeader('Authorization', 'Bearer scoped-product-user-one'));

            return Http::response(['code' => 'invalid_token'], 401, ['Content-Type' => 'application/json']);
        });

        try {
            app(RequestOnlyMcpClient::class)->callTool($target, $bound, 'notes.write', ['text' => 'once'], true, 'corr-one');
            self::fail('Wrong-resource credential was accepted.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('downstream_unauthenticated', $exception->reason);
            self::assertSame('unknown', $exception->outcome, 'An HTTP status alone does not prove mutation nonexecution.');
            self::assertSame('http', $exception->phase);
            self::assertSame(401, $exception->details['http_status']);
        }
        Http::assertSentCount(1);
    }

    public function test_uncertain_lost_response_is_not_replayed_and_retains_transport_cause(): void
    {
        $target = $this->target('bridge-one');
        $count = 0;
        Http::fake(function (Request $request) use (&$count) {
            $count++;

            throw new ConnectionException('Synthetic response lost after dispatch');
        });

        try {
            app(RequestOnlyMcpClient::class)->callTool($target, $this->bound($target), 'notes.write', ['text' => 'attempt'], true, 'corr-one');
            self::fail('Unknown write result was accepted.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('unknown', $exception->outcome);
            self::assertSame('transport', $exception->phase);
            self::assertSame('network_failure', $exception->reason);
            self::assertInstanceOf(\Throwable::class, $exception->getPrevious());
        }
        self::assertSame(1, $count, 'The transport must attempt a potentially effectful request only once.');
    }

    public function test_upstream_bridge_fault_retains_explicit_outcome_reference_and_safe_guidance(): void
    {
        $target = $this->target('bridge-one');
        Http::fake(fn (Request $request) => $this->rpc($request, [
            'isError' => true,
            'content' => [[
                'type' => 'text',
                'text' => json_encode([
                    'code' => 'revision_conflict',
                    'message' => 'Expected revision differs from the current resource.',
                    'action' => 'Reload the resource before attempting another change.',
                    'outcome' => 'not_committed',
                    'reference' => 'note-123',
                    'request_id' => 'upstream-request-1',
                ], JSON_THROW_ON_ERROR),
            ]],
        ]));

        try {
            app(RequestOnlyMcpClient::class)->callTool($target, $this->bound($target), 'notes.write', ['text' => 'attempt'], true, 'corr-one');
            self::fail('An MCP tool error was accepted as success.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('downstream_tool_error', $exception->reason);
            self::assertSame('not_committed', $exception->outcome);
            self::assertSame('note-123', $exception->reference);
            self::assertSame('upstream-request-1', $exception->upstreamRequestId);
            self::assertSame('revision_conflict', $exception->details['source_code']);
            self::assertStringContainsString('Reload', $exception->details['source_action']);
        }
        Http::assertSentCount(1);
    }

    public function test_server_error_malformed_response_and_session_profile_cannot_succeed_or_retry(): void
    {
        $target = $this->target('bridge-one');
        $cases = [
            [fn (Request $r) => Http::response('unavailable', 503), 'downstream_http_failure'],
            [fn (Request $r) => Http::response(['jsonrpc' => '2.0', 'id' => 'wrong-id', 'result' => []]), 'invalid_rpc_envelope'],
            [fn (Request $r) => $this->rpc($r, [], ['Mcp-Session-Id' => 'legacy-not-supported']), 'unsupported_response_profile'],
        ];

        foreach ($cases as [$fake, $reason]) {
            Http::swap(new Factory);
            Http::preventStrayRequests();
            Http::fake($fake);
            try {
                app(RequestOnlyMcpClient::class)->callTool($target, $this->bound($target), 'notes.write', ['text' => 'once'], true, 'corr-one');
                self::fail('Uncertain response was accepted.');
            } catch (OutboundMcpFailure $exception) {
                self::assertSame($reason, $exception->reason);
                self::assertSame('unknown', $exception->outcome);
            }
            Http::assertSentCount(1);
        }
    }

    public function test_unsafe_schema_and_catalog_cursor_are_rejected_without_calling_tools(): void
    {
        $target = $this->target('bridge-one');
        Http::fake(fn (Request $request) => $this->rpc($request, [
            'tools' => [['name' => 'notes.write', 'inputSchema' => ['type' => 'string']]],
        ]));
        try {
            app(RequestOnlyMcpClient::class)->listTools($target, $this->bound($target), 'corr-one');
            self::fail('Unsupported tool schema was accepted.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('unsupported_tool_schema', $exception->reason);
        }
        Http::assertSentCount(1);

        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->rpc($request, ['tools' => []]));
        try {
            app(RequestOnlyMcpClient::class)->listTools($target, $this->bound($target), 'corr-one', str_repeat('x', 257));
            self::fail('Unbounded cursor was accepted.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('invalid_cursor', $exception->reason);
        }
        Http::assertNothingSent();
    }

    public function test_oversized_input_and_header_injection_never_dispatch(): void
    {
        $target = $this->target('bridge-one');
        Http::fake(fn (Request $request) => $this->rpc($request, ['content' => []]));
        $client = app(RequestOnlyMcpClient::class);

        foreach ([
            fn () => $client->callTool($target, $this->bound($target), 'notes.write', ['text' => str_repeat('a', RequestOnlyMcpClient::MAX_REQUEST_BYTES)], true, 'corr-one'),
            fn () => $client->callTool($target, $this->bound($target), "notes.write\nInjected: yes", [], true, 'corr-one'),
            fn () => $client->callTool($target, $this->bound($target), 'notes.write', [], true, "corr-one\r\nInjected: yes"),
        ] as $action) {
            try {
                $action();
                self::fail('Unbounded or unsafe payload was dispatched.');
            } catch (OutboundMcpFailure $exception) {
                self::assertSame('not_executed', $exception->outcome);
            }
        }
        Http::assertNothingSent();
    }

    public function test_bounded_response_and_unsafe_destination_fail_closed_without_replay(): void
    {
        $target = $this->target('bridge-one');
        $client = app(RequestOnlyMcpClient::class);

        Http::fake(fn (Request $request) => Http::response(
            str_repeat('x', RequestOnlyMcpClient::MAX_RESPONSE_BYTES + 1),
            200,
            ['Content-Type' => 'application/json'],
        ));
        try {
            $client->callTool($target, $this->bound($target), 'notes.write', ['text' => 'once'], true, 'corr-one');
            self::fail('Oversized write response was accepted.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('response_too_large', $exception->reason);
            self::assertSame('unknown', $exception->outcome);
            self::assertSame('transport', $exception->phase);
        }
        Http::assertSentCount(1);

        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => Http::response('unexpected remote dispatch'));
        try {
            $client->listTools($target, BoundMcpTarget::forRegisteredTarget(
                $target, 'https://127.0.0.1/mcp', 'scoped-product-user-one',
            ), 'corr-one');
            self::fail('Loopback DNS bypassed public egress validation.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('unsafe_target', $exception->reason);
            self::assertSame('not_executed', $exception->outcome);
        }
        Http::assertNothingSent();
    }

    public function test_approved_remote_fault_can_never_echo_actual_bearer_into_diagnostics(): void
    {
        $target = $this->target('bridge-one');
        Http::fake(fn (Request $request) => $this->rpc($request, [
            'isError' => true,
            'content' => [[
                'type' => 'text',
                'text' => json_encode([
                    'code' => 'invalid_precondition',
                    'message' => 'Unexpected downstream credential scoped-product-user-one was echoed.',
                    'action' => 'Contact the owner of scoped-product-user-one.',
                    'outcome' => 'not_executed',
                ], JSON_THROW_ON_ERROR),
            ]],
        ]));

        try {
            app(RequestOnlyMcpClient::class)->callTool($target, $this->bound($target), 'notes.read', [], false, 'corr-one');
            self::fail('Remote tool error was accepted.');
        } catch (OutboundMcpFailure $exception) {
            self::assertSame('not_executed', $exception->outcome);
            self::assertSame('invalid_precondition', $exception->details['source_code']);
            self::assertStringNotContainsString('scoped-product-user-one', json_encode($exception->details, JSON_THROW_ON_ERROR));
            self::assertStringContainsString('[redacted]', $exception->details['source_message']);
        }
    }

    public function test_target_bearer_does_not_serialize_or_allow_malformed_credentials(): void
    {
        $target = $this->target('bridge-one');
        $bound = $this->bound($target);
        self::assertStringNotContainsString('scoped-product-user-one', print_r($bound, true));
        try {
            serialize($bound);
            self::fail('A bearer binding was serialized.');
        } catch (\LogicException) {
            // Expected: the transient product-user token must not enter a cache.
        }
        try {
            BoundMcpTarget::forRegisteredTarget($target, 'https://bridge-one.example.test/mcp', "bad\r\nheader");
            self::fail('Unsafe credential was accepted.');
        } catch (InvalidArgumentException) {
            // Expected.
        }
    }

    private function target(string $slug): Target
    {
        return Target::query()->create([
            'target_id' => $slug,
            'display_name' => 'Synthetic Bridge '.$slug,
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => 'connected',
        ]);
    }

    private function bound(Target $target): BoundMcpTarget
    {
        return BoundMcpTarget::forRegisteredTarget(
            $target, 'https://bridge-one.example.test/mcp', 'scoped-product-user-one',
        );
    }

    /** @param array<string, mixed> $result
     * @param  array<string, string>  $headers
     */
    private function rpc(Request $request, array $result, array $headers = []): PromiseInterface
    {
        return Http::response([
            'jsonrpc' => '2.0',
            'id' => $request->data()['id'],
            'result' => $result,
        ], 200, ['Content-Type' => 'application/json', ...$headers]);
    }
}
