<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Infrastructure\Http\DnsResolver;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
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
            public function resolve(string $host): array
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
