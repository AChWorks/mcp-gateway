<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\Relay\ConnectionRelayUnavailable;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundRequestException;
use App\Support\OperationDiagnostics;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use Tests\TestCase;

final class WpAiBridgeTargetRegistrationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });

        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->metadata($request));
    }

    public function test_registration_is_disconnected_atomic_and_connector_scoped(): void
    {
        $ssh = Target::query()->create([
            'target_id' => 'ssh-at-same-host',
            'display_name' => 'SSH',
            'connector_type' => 'ssh_direct',
        ]);

        $wp = app(WpAiBridgeTargetRegistration::class)->register(
            'wp-at-same-host', 'WP Site', 'https://alpha.example.test/',
        );

        self::assertSame(TargetConnectionState::Disconnected, $wp->connection_state);
        self::assertSame('wp_ai_bridge', $wp->connector_type);
        self::assertNull($wp->getAttribute('base_url'));
        self::assertSame('ssh_direct', $ssh->connector_type);
        self::assertSame(2, Target::query()->count());
        self::assertSame(0, TargetCredential::query()->count());

        $config = WpAiBridgeTargetConfig::query()->sole();
        self::assertSame($wp->getKey(), $config->target_record_id);
        self::assertSame('https://alpha.example.test', $config->base_url);
        self::assertSame(hash('sha256', $config->base_url), $config->base_url_hash);
        self::assertSame('https://alpha.example.test/wp-json/wp-ai-bridge/v1/mcp', $config->mcp_resource_url);
        self::assertSame(0, DB::table('wp_ai_bridge_target_reservations')->count());
    }

    public function test_duplicate_canonical_endpoint_or_public_id_fails_without_partial_writes(): void
    {
        $registration = app(WpAiBridgeTargetRegistration::class);
        $registration->register('alpha', 'Alpha', 'https://alpha.example.test');

        foreach ([['beta', 'https://alpha.example.test/'], ['alpha', 'https://beta.example.test']] as [$id, $url]) {
            try {
                $registration->register($id, 'Collision', $url);
                self::fail('Duplicate Target unexpectedly registered.');
            } catch (InvalidArgumentException $expected) {
                self::assertStringContainsString('already registered', $expected->getMessage());
            }

            self::assertSame(1, Target::query()->count());
            self::assertSame(1, WpAiBridgeTargetConfig::query()->count());
            self::assertSame(0, DB::table('wp_ai_bridge_target_reservations')->count());
        }
    }

    public function test_existing_connector_reservation_blocks_competing_registration_without_corruption(): void
    {
        $base = 'https://alpha.example.test';
        $hash = hash('sha256', $base);

        DB::table('wp_ai_bridge_target_reservations')->insert([
            'target_hash' => $hash,
            'target_url' => $base,
            'owner_target_id' => 'pending-other-owner',
            'target_record_id' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        try {
            app(WpAiBridgeTargetRegistration::class)->register('new-target', 'WP', $base);
            self::fail('A reserved WordPress endpoint was registered concurrently.');
        } catch (InvalidArgumentException $expected) {
            self::assertStringContainsString('already registered', $expected->getMessage());
        }

        self::assertSame(0, Target::query()->count());
        self::assertSame(0, WpAiBridgeTargetConfig::query()->count());
        self::assertSame('pending-other-owner', DB::table('wp_ai_bridge_target_reservations')
            ->where('target_hash', $hash)->value('owner_target_id'));
    }

    public function test_bad_target_id_and_bad_remote_metadata_are_rejected_before_persistence(): void
    {
        foreach (['invalid slug', str_repeat('a', 65)] as $invalidId) {
            try {
                app(WpAiBridgeTargetRegistration::class)->register($invalidId, 'WP', 'https://alpha.example.test');
                self::fail('Invalid ID accepted.');
            } catch (InvalidArgumentException) {
                // Must fail before initiating any remote request.
            }
        }

        Http::assertNothingSent();

        try {
            app(WpAiBridgeTargetRegistration::class)->register('missing', 'WP', 'https://missing.example.test');
            self::fail('Missing bridge metadata accepted.');
        } catch (BridgeDiscoveryException $expected) {
            self::assertSame('missing_bridge', $expected->reason);
        }

        self::assertSame(0, Target::query()->count());
        self::assertSame(0, WpAiBridgeTargetConfig::query()->count());
        self::assertSame(0, DB::table('wp_ai_bridge_target_reservations')->count());
    }

    public function test_metadata_rejection_preserves_specific_policy_details_without_leaking_untrusted_urls(): void
    {
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'blocked.example.test' ? ['127.0.0.1'] : ['1.1.1.1'];
            }
        });
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(function (Request $request): PromiseInterface {
            $host = (string) parse_url($request->url(), PHP_URL_HOST);
            if ((string) parse_url($request->url(), PHP_URL_PATH) === '/.well-known/oauth-protected-resource') {
                $base = 'https://'.$host;
                $resource = match ($host) {
                    'cross.example.test' => 'https://other.example.test/wp-json/wp-ai-bridge/v1/mcp',
                    'blocked-meta.example.test' => 'https://blocked.example.test/wp-json/wp-ai-bridge/v1/mcp',
                    default => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                };

                return Http::response([
                    'resource' => $resource,
                    'authorization_servers' => $host === 'plain-meta.example.test' ? [] : [$base],
                    'scopes_supported' => ['mcp:use'],
                    'bearer_methods_supported' => ['header'],
                ]);
            }

            return $this->metadata($request);
        });
        foreach ([
            'cross.example.test' => ['origin_mismatch', 'different origin'],
            'blocked-meta.example.test' => ['dns_non_public', '127.0.0.1'],
            'plain-meta.example.test' => [null, 'incompatible'],
        ] as $host => [$reason, $hint]) {
            try {
                app(WpAiBridgeTargetRegistration::class)
                    ->register('wp-'.str_replace('.', '-', $host), 'Rejected', 'https://'.$host);
                self::fail('Untrusted metadata was accepted: '.$host);
            } catch (BridgeDiscoveryException $exception) {
                self::assertSame('incompatible_metadata', $exception->reason);
                $details = $exception->diagnostics;
                if ($reason !== null) {
                    self::assertSame($reason, $details['outbound_rejection_reason'] ?? null);
                } else {
                    self::assertArrayNotHasKey('outbound_rejection_reason', $details);
                }
                self::assertStringContainsString($hint,
                    OperationDiagnostics::summary($exception->reason, $details));
                self::assertNotSame('', OperationDiagnostics::nextStep($exception->reason, $details));
                self::assertStringNotContainsString('other.example.test',
                    json_encode($details, JSON_THROW_ON_ERROR));
            }
        }

        self::assertSame(0, Target::query()->count());
        self::assertSame(0, WpAiBridgeTargetConfig::query()->count());
        self::assertSame(0, TargetCredential::query()->count());
    }

    public function test_one_enabled_relay_can_register_several_wordpress_targets_without_changing_dns_tls_metadata_contract(): void
    {
        $relay = ConnectionRelay::query()->create([
            'relay_id' => 'iran-wp', 'display_name' => 'Shared Iran WP Relay',
            'control_host' => '193.111.235.101', 'control_port' => 22,
            'control_user' => 'mcp-relay',
            'control_host_key' => 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('c', 32)),
            'local_socks_port' => 46081,
        ]);
        DB::table('connection_relays')->where('id', $relay->getKey())->update(['enabled' => true]);

        $first = app(WpAiBridgeTargetRegistration::class)->register(
            'wp-through-iran-1', 'First WP', 'https://first.example.test', relayId: 'iran-wp',
        );
        $second = app(WpAiBridgeTargetRegistration::class)->register(
            'wp-through-iran-2', 'Second WP', 'https://second.example.test', relayId: 'iran-wp',
        );

        self::assertSame((string) $relay->getKey(), $first->getAttribute('relay_record_id'));
        self::assertSame((string) $relay->getKey(), $second->getAttribute('relay_record_id'));
        self::assertSame(1, $first->relay_binding_revision);
        self::assertSame(1, $second->relay_binding_revision);
        self::assertSame(46081, app(ConnectionRelayRoutes::class)->httpRouteForTarget($first)?->loopbackPort);
        self::assertSame(TargetConnectionState::Disconnected, $first->connection_state);
        self::assertSame('https://first.example.test',
            WpAiBridgeTargetConfig::query()->where('target_record_id', $first->getKey())->sole()->base_url);
        Http::assertSentCount(4);

        DB::table('connection_relays')->where('id', $relay->getKey())->update(['enabled' => false]);
        try {
            app(ConnectionRelayRoutes::class)->httpRouteForTarget($first);
            self::fail('Disabled Relay must not automatically fall back to Direct.');
        } catch (OutboundRequestException $exception) {
            self::assertTrue($exception->preDispatch);
            self::assertSame('network_failure', $exception->reason);
        }
    }

    public function test_disabled_wordpress_relay_fails_before_discovery_or_target_insert(): void
    {
        $relay = ConnectionRelay::query()->create([
            'relay_id' => 'iran-offline', 'display_name' => 'Not ready',
            'control_host' => '193.111.235.101', 'control_port' => 22,
            'control_user' => 'mcp-relay',
            'control_host_key' => 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('c', 32)),
            'local_socks_port' => 46082,
        ]);

        try {
            app(WpAiBridgeTargetRegistration::class)->register(
                'wp-rejected-relay', 'Offline WP', 'https://offline.example.test',
                relayId: 'iran-offline',
            );
            self::fail('Disabled Relay accepted WordPress discovery.');
        } catch (ConnectionRelayUnavailable) {
            self::assertSame(0, Target::query()->count());
            Http::assertNothingSent();
        }
    }

    private function metadata(Request $request): PromiseInterface
    {
        $host = (string) parse_url($request->url(), PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($request->url(), PHP_URL_PATH);

        if ($host === 'missing.example.test') {
            return Http::response([], 404);
        }
        if ($path === '/.well-known/oauth-protected-resource') {
            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
            ]);
        }
        if ($path === '/.well-known/oauth-authorization-server') {
            return Http::response([
                'issuer' => $base,
                'authorization_endpoint' => $base.'/wp-ai-bridge/oauth/authorize',
                'token_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
                'revocation_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
                'client_id_metadata_document_supported' => true,
                'authorization_response_iss_parameter_supported' => true,
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'response_types_supported' => ['code'],
                'code_challenge_methods_supported' => ['S256'],
                'scopes_supported' => ['mcp:use', 'offline_access'],
            ]);
        }

        return Http::response([], 404);
    }
}
