<?php

namespace Tests\Feature\Targets;

use App\Application\Operations\OperationalSettings;
use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetVault;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\OAuth\GatewayBridgeClientIdentity;
use App\Models\User;
use GuzzleHttp\Exception\ConnectTimeoutException as GuzzleConnectTimeoutException;
use GuzzleHttp\Exception\NetworkTimeoutException as GuzzleNetworkTimeoutException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Tests\TestCase;

final class WpAiBridgeTargetConnectionTest extends TestCase
{
    use RefreshDatabase;

    private bool $failRevocation = false;

    /** @var list<string> Only in-memory test fixture, never logs. */
    private array $revocationTokenAttempts = [];

    private ?string $revokeFailureMode = null;

    private bool $tryConcurrentRevoke = false;

    private bool $concurrentRevokeBlocked = false;

    private bool $allowProtectedCatalogProbe = false;

    private bool $rejectProtectedCatalogProbe = false;

    private int $catalogProbeCalls = 0;

    private bool $failTokenExchange = false;

    private bool $failRefresh = false;

    private bool $failRefreshOnce = false;

    private bool $failClientAuthentication = false;

    private bool $temporarilyUnavailable400Once = false;

    private int $refreshTokenTtl = 7200;

    private bool $rejectRefresh = false;

    private bool $malformedRefresh = false;

    private int $refreshCalls = 0;

    // A transport attempt is not proof that the remote token endpoint
    // accepted an HTTP request. Track actual fixture-side processing apart.
    private int $refreshHandledByBridge = 0;

    private ?string $refreshTransportFailure = null;

    private bool $attemptConcurrentDisconnect = false;

    private bool $sawCallbackFence = false;

    /** @var list<int> */
    private array $outboundTransactionLevels = [];

    protected function setUp(): void
    {
        parent::setUp();
        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.name', 'Gateway Test');
        // Breaking Target release advertises an exact new connector redirect.
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/targets/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');
        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });

        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->bridgeResponse($request));
    }

    public function test_old_site_callback_is_not_advertised_or_routable_in_breaking_target_release(): void
    {
        $this->get('/oauth/sites/callback')->assertNotFound();
        self::assertSame(
            'https://gateway.example.test/oauth/targets/callback',
            (string) config('bridge.client.redirect_uri'),
        );
    }

    public function test_two_targets_have_isolated_encrypted_oauth_and_exact_issuer_bound_replay_safe_callback(): void
    {
        $alpha = $this->target('alpha');
        $beta = $this->target('beta');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $url = $service->begin($alpha);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);

        self::assertSame('S256', $args['code_challenge_method']);
        self::assertSame(config('bridge.client.redirect_uri'), $args['redirect_uri']);
        self::assertSame(TargetConnectionState::Pending, $alpha->refresh()->connection_state);
        self::assertSame(1, DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $alpha->getKey())->count());

        try {
            $service->completeCallback($args['state'], 'alpha-code', 'https://evil.example.test', null);
            self::fail('Mismatched issuer was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('issuer_mismatch', $exception->reason);
        }
        self::assertNull(DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $alpha->getKey())->value('consumed_at'));

        $service->completeCallback($args['state'], 'alpha-code', 'https://alpha.example.test', null);
        self::assertSame(TargetConnectionState::Connected, $alpha->refresh()->connection_state);
        self::assertSame('alpha-access', $service->accessToken($alpha));
        self::assertSame('beta-access', $this->pair($beta));
        self::assertSame(0, DB::table('wp_ai_bridge_oauth_flows')->count());

        $alphaCredential = $this->credential($alpha);
        $betaCredential = $this->credential($beta);
        self::assertNotSame($alphaCredential->encrypted_payload, $betaCredential->encrypted_payload);
        self::assertStringNotContainsString('alpha-access', $alphaCredential->encrypted_payload);
        self::assertStringNotContainsString('alpha-refresh', $alphaCredential->encrypted_payload);
        self::assertSame('wordpress_oauth', $alphaCredential->purpose);
        $secret = app(WpAiBridgeTargetVault::class)->openCredential($alpha, $alphaCredential);
        self::assertSame('alpha-refresh', $secret['refresh_token']);
        self::assertSame('mcp:use', $secret['scopes'][0]);

        try {
            $service->completeCallback($args['state'], 'alpha-code', 'https://alpha.example.test', null);
            self::fail('OAuth callback state replay was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('invalid_state', $exception->reason);
        }

        // A copied ciphertext may never act as authorization for a different Target.
        DB::table('target_credentials')->where('id', $betaCredential->getKey())
            ->update(['encrypted_payload' => $alphaCredential->encrypted_payload]);
        try {
            $service->accessToken($beta);
            self::fail('Cross-Target encrypted credential replay was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('credential_unavailable', $exception->reason);
        }
    }

    public function test_admin_wordpress_disconnect_reports_precise_safe_transport_stage_and_preserves_revocation_intent(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->actingAs($this->user('owner', 'all'));

        // Replacing HTTP stubs after authorization simulates an actual
        // connection refusal at the WordPress revocation endpoint.
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(static fn (Request $request) => Http::failedConnection(
            'cURL error 7: Connection refused PRIVATE_OAUTH_TOKEN_SHOULD_NEVER_LOG',
        ));

        Log::spy();
        $result = $this->post('/admin/targets/alpha/disconnect')
            ->assertRedirect('/admin/targets/alpha')
            ->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'network_failure')
            ->assertSessionHas('diagnostic_stage', 'tcp_connect');
        $reference = (string) session('diagnostic_reference');
        self::assertTrue(Str::isUuid($reference));
        $result->assertHeader('X-Correlation-ID', $reference);

        $this->assertDatabaseHas('wp_ai_bridge_revocation_intents', [
            'target_record_id' => $target->getKey(),
            'kind' => 'disconnect',
        ]);
        self::assertSame(1, TargetCredential::query()->where('target_record_id', $target->getKey())->count());
        self::assertSame(TargetConnectionState::Error, $target->fresh()->connection_state);
        self::assertSame('network_failure', $target->fresh()->last_error_code);

        $this->get('/admin/targets/alpha')->assertOk()
            ->assertSee('Credential revocation is pending')
            ->assertSee('network_failure')
            ->assertSee('tcp_connect')
            ->assertSee($reference)
            ->assertSee('What to check');

        Log::shouldHaveReceived('warning')->once()->withArgs(
            static function (string $message, array $context) use ($reference): bool {
                return $message === 'Gateway operation failure.'
                    && ($context['correlation_id'] ?? null) === $reference
                    && ($context['operation'] ?? null) === 'target-disconnect'
                    && ($context['error_code'] ?? null) === 'network_failure'
                    && ($context['failure_stage'] ?? null) === 'tcp_connect'
                    && ($context['request_not_sent'] ?? null) === true
                    && ! str_contains(json_encode($context, JSON_THROW_ON_ERROR), 'PRIVATE_OAUTH_TOKEN');
            },
        );
    }

    public function test_uncertain_disconnect_cannot_replay_and_requires_wordpress_side_attestation(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($alpha);
        $baselineLevel = DB::transactionLevel();
        $this->failRevocation = true;

        try {
            $service->disconnect($alpha);
            self::fail('Failed remote revocation was treated as successful.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('revocation_failed', $exception->reason);
        }

        self::assertSame(TargetConnectionState::Error, $alpha->refresh()->connection_state);
        self::assertSame('revocation_failed', $alpha->last_error_code);
        self::assertSame(1, DB::table('wp_ai_bridge_revocation_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        $service->testConnection($alpha);
        self::assertSame('revocation_failed', $alpha->refresh()->last_error_code,
            'A successful metadata probe must not mask unresolved credential revocation.');
        try {
            $service->accessToken($alpha);
            self::fail('Revocation-pending credential was used.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('revocation_pending', $exception->reason);
        }
        try {
            $service->begin($alpha);
            self::fail('Revocation-pending credential was reauthorized.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('revocation_pending', $exception->reason);
        }

        $this->failRevocation = false;
        $intentId = (string) DB::table('wp_ai_bridge_revocation_intents')->value('id');
        $attempts = $this->revocationTokenAttempts;
        try {
            $service->disconnect($alpha, $intentId);
            self::fail('A WordPress HTTP 400 revoke was blindly replayed.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('revocation_uncertain', $exception->reason);
        }
        self::assertSame($attempts, $this->revocationTokenAttempts);
        // This models the Owner's separate saved WordPress client-approval
        // removal. The Gateway intentionally cannot verify that change.
        DB::table('wp_ai_bridge_revocation_intents')->where('id', $intentId)
            ->update(['updated_at' => now()->subMinutes(3)]);
        $service->reconcileRevokedDisconnect($alpha, $intentId, static function (Target $locked): void {
            app(ActivityRecorder::class)
                ->recordRequired((string) Str::uuid(), 'wordpress-disconnect-remote-revocation-attested',
                    'operator-attested', $locked);
        });
        self::assertSame(TargetConnectionState::Disconnected, $alpha->refresh()->connection_state);
        self::assertSame(0, DB::table('wp_ai_bridge_revocation_intents')->count());
        self::assertSame(0, DB::table('target_credentials')->count());
        self::assertSame(0, DB::table('wp_ai_bridge_credential_metadata')->count());
        self::assertTrue($this->outboundTransactionLevels !== []);
        foreach ($this->outboundTransactionLevels as $level) {
            self::assertSame($baselineLevel, $level, 'Network I/O occurred while another DB transaction was held.');
        }
    }

    public function test_authoritative_denial_consumes_state_but_missing_issuer_does_not(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $url = $service->begin($alpha);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);

        try {
            $service->completeCallback($args['state'], null, null, 'access_denied');
            self::fail('Unsigned denial was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('issuer_mismatch', $exception->reason);
        }
        self::assertSame(TargetConnectionState::Pending, $alpha->refresh()->connection_state);

        try {
            $service->completeCallback($args['state'], null, 'https://alpha.example.test', 'access_denied');
            self::fail('OAuth denial became success.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('authorization_denied', $exception->reason);
        }
        self::assertSame(TargetConnectionState::Disconnected, $alpha->refresh()->connection_state);
        self::assertSame('oauth_access_denied', $alpha->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_oauth_flows')->count());
    }

    public function test_admin_callback_and_access_gates_operate_on_target_not_old_site_routes(): void
    {
        $owner = $this->user('owner', 'all');
        $operator = $this->user('operator', 'selected');
        $alpha = $this->target('alpha');
        $beta = $this->target('beta');

        $this->actingAs($operator)->post('/admin/targets/beta/connect')->assertForbidden();
        $this->post('/admin/targets/beta/disconnect')->assertForbidden();
        $this->actingAs($owner)->get('/admin/targets/alpha')->assertOk()
            ->assertSee('Authorize WordPress');
        $response = $this->post('/admin/targets/alpha/connect');
        $response->assertStatus(303);
        $handoffUrl = (string) $response->headers->get('Location');
        self::assertStringStartsWith('/admin/targets/alpha/external-authorization/', (string) parse_url($handoffUrl, PHP_URL_PATH));
        self::assertStringNotContainsString('state=', $handoffUrl);

        $handoff = $this->get($handoffUrl)->assertOk()
            ->assertHeader('Referrer-Policy', 'no-referrer');
        self::assertStringContainsString("form-action 'self'", (string) $handoff->headers->get('Content-Security-Policy'));
        $html = html_entity_decode($handoff->getContent(), ENT_QUOTES | ENT_HTML5);
        self::assertSame(1, preg_match('/<meta http-equiv="refresh" content="0;url=([^"]+)">/', $html, $matches));
        $url = $matches[1];
        self::assertStringStartsWith('https://alpha.example.test/wp-ai-bridge/oauth/authorize?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);
        self::assertArrayHasKey('state', $args);

        // The handoff is consumed, and refreshing its GET cannot issue OAuth
        // again or replay the original Admin POST.
        $this->get($handoffUrl)->assertRedirect('/admin/targets/alpha')
            ->assertSessionHasErrors('target');
        self::assertSame(1, DB::table('wp_ai_bridge_oauth_flows')->count());

        $this->get('/oauth/targets/callback?'.http_build_query([
            'state' => $args['state'],
            'code' => 'alpha-code',
            'iss' => 'https://alpha.example.test',
        ]))->assertRedirect('/admin/targets/alpha');

        $this->get('/admin/targets/alpha')->assertOk()
            ->assertSee('Reauthorize')
            ->assertSee('Disconnect WordPress')
            ->assertDontSee('alpha-refresh');
        self::assertSame(TargetConnectionState::Connected, $alpha->refresh()->connection_state);
        self::assertSame(TargetConnectionState::Disconnected, $beta->refresh()->connection_state);

        $this->post('/admin/targets/alpha/disconnect')->assertRedirect('/admin/targets/alpha');
        $this->get('/admin/targets/alpha')->assertOk()->assertSee('Authorize WordPress');
        self::assertSame(TargetConnectionState::Disconnected, $alpha->refresh()->connection_state);
    }

    public function test_authorization_handoff_is_bound_to_admin_identity_and_expires_without_restarting_oauth(): void
    {
        $owner = $this->user('owner', 'all');
        $other = $this->user('viewer', 'all');
        $alpha = $this->target('alpha');

        $this->actingAs($owner);
        $first = (string) $this->post('/admin/targets/alpha/connect')
            ->assertStatus(303)->headers->get('Location');
        self::assertSame(1, DB::table('wp_ai_bridge_oauth_flows')->count());
        self::assertSame(TargetConnectionState::Pending, $alpha->fresh()->connection_state);

        // Changing the authenticated principal does not transfer the URL,
        // even if the session still carries the one-time handoff value.
        $this->actingAs($other)->get($first)
            ->assertRedirect('/admin/targets/alpha')->assertSessionHasErrors('target');
        $this->actingAs($owner)->get($first)->assertRedirect('/admin/targets/alpha');

        $second = (string) $this->post('/admin/targets/alpha/connect')
            ->assertStatus(303)->headers->get('Location');
        $this->travel(121)->seconds();
        $this->get($second)->assertRedirect('/admin/targets/alpha')
            ->assertSessionHasErrors('target');
        self::assertSame(1, DB::table('wp_ai_bridge_oauth_flows')->count());
    }

    public function test_restart_of_pending_admin_authorization_rotates_state_without_duplicate_flow_or_post_replay(): void
    {
        $alpha = $this->target('alpha');
        $this->actingAs($this->user('owner', 'all'));
        $firstGet = (string) $this->post('/admin/targets/alpha/connect')
            ->assertStatus(303)->headers->get('Location');
        $firstHtml = html_entity_decode($this->get($firstGet)->assertOk()->getContent(), ENT_QUOTES | ENT_HTML5);
        self::assertSame(1, preg_match('/<meta http-equiv="refresh" content="0;url=([^"]+)">/', $firstHtml, $firstMatch));
        parse_str((string) parse_url($firstMatch[1], PHP_URL_QUERY), $firstArgs);

        $secondGet = (string) $this->post('/admin/targets/alpha/connect')
            ->assertStatus(303)->headers->get('Location');
        $secondHtml = html_entity_decode($this->get($secondGet)->assertOk()->getContent(), ENT_QUOTES | ENT_HTML5);
        self::assertSame(1, preg_match('/<meta http-equiv="refresh" content="0;url=([^"]+)">/', $secondHtml, $secondMatch));
        parse_str((string) parse_url($secondMatch[1], PHP_URL_QUERY), $secondArgs);

        self::assertNotSame($firstArgs['state'], $secondArgs['state']);
        self::assertSame(1, DB::table('wp_ai_bridge_oauth_flows')->count());
        self::assertSame(TargetConnectionState::Pending, $alpha->fresh()->connection_state);

        try {
            app(WpAiBridgeTargetConnectionService::class)
                ->completeCallback($firstArgs['state'], 'old-code', 'https://alpha.example.test', null);
            self::fail('Superseded authorization state was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('invalid_state', $exception->reason);
        }

        $this->get('/oauth/targets/callback?'.http_build_query([
            'state' => $secondArgs['state'], 'code' => 'alpha-code', 'iss' => 'https://alpha.example.test',
        ]))->assertRedirect('/admin/targets/alpha');
        self::assertSame(TargetConnectionState::Connected, $alpha->fresh()->connection_state);
        self::assertSame(0, DB::table('wp_ai_bridge_oauth_flows')->count());
    }

    public function test_connected_target_reconnect_uses_the_same_secure_browser_handoff(): void
    {
        $alpha = $this->target('alpha');
        $this->pair($alpha);
        $this->actingAs($this->user('owner', 'all'));
        $handoff = (string) $this->post('/admin/targets/alpha/reconnect')
            ->assertStatus(303)->headers->get('Location');
        self::assertStringContainsString('/admin/targets/alpha/external-authorization/', $handoff);
        $html = html_entity_decode($this->get($handoff)->assertOk()->getContent(), ENT_QUOTES | ENT_HTML5);
        self::assertSame(1, preg_match('/<meta http-equiv="refresh" content="0;url=([^"]+)">/', $html, $matches));
        parse_str((string) parse_url($matches[1], PHP_URL_QUERY), $args);
        self::assertSame('S256', $args['code_challenge_method']);
        self::assertSame(TargetConnectionState::Pending, $alpha->fresh()->connection_state);
        self::assertSame(0, TargetCredential::query()->where('target_record_id', $alpha->getKey())->count());
        self::assertSame(1, DB::table('wp_ai_bridge_oauth_flows')->count());
    }

    public function test_external_authorization_get_rechecks_current_permission_and_cannot_be_opened_anonymously(): void
    {
        $owner = $this->user('owner', 'all');
        $this->target('alpha');
        $this->get('/admin/targets/alpha/external-authorization/'.str_repeat('a', 32))
            ->assertRedirect('/admin/login');

        $this->actingAs($owner);
        $handoff = (string) $this->post('/admin/targets/alpha/connect')
            ->assertStatus(303)->headers->get('Location');

        // If the user's role is reduced after POST, the subsequent GET
        // must not expose the provider URL or bypass the new access policy.
        $owner->forceFill(['role' => 'viewer'])->save();
        $this->get($handoff)->assertForbidden();
        $this->get($handoff)->assertRedirect('/admin/targets/alpha')
            ->assertSessionHasErrors('target');
    }

    public function test_changed_connector_endpoints_cannot_receive_an_existing_oauth_secret(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($alpha);
        $config = DB::table('wp_ai_bridge_target_configs')->where('target_record_id', $alpha->getKey());

        $config->update(['oauth_revocation_url' => 'https://evil.example.test/collect']);
        try {
            $service->disconnect($alpha);
            self::fail('Credential tokens were sent to another origin.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('target_changed', $exception->reason);
        }
        Http::assertNotSent(static fn (Request $request): bool => str_contains($request->url(), 'evil.example.test'));
        self::assertSame(0, DB::table('wp_ai_bridge_revocation_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());

        $config->update([
            'oauth_revocation_url' => 'https://alpha.example.test/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'mcp_resource_url' => 'https://evil.example.test/mcp',
        ]);
        try {
            $service->accessToken($alpha);
            self::fail('Credential from another resource was used.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('target_changed', $exception->reason);
        }
        $config->update(['mcp_resource_url' => 'https://alpha.example.test/wp-json/wp-ai-bridge/v1/mcp']);
        self::assertSame('alpha-access', $service->accessToken($alpha));
        $service->disconnect($alpha);
        self::assertSame(0, DB::table('target_credentials')->count());
    }

    public function test_unimplemented_non_wordpress_connector_cannot_enter_wordpress_oauth_flow(): void
    {
        $owner = $this->user('owner', 'all');
        $ssh = Target::query()->create([
            'target_id' => 'ssh-only',
            'display_name' => 'SSH machine',
            'connector_type' => 'ssh_direct',
        ]);

        $this->actingAs($owner)->post('/admin/targets/ssh-only/connect')
            ->assertRedirect('/admin/targets/ssh-only')
            ->assertSessionHasErrors('target');
        self::assertSame(0, DB::table('wp_ai_bridge_oauth_flows')->count());
        self::assertSame(0, DB::table('target_credentials')->count());
        self::assertSame('ssh_direct', $ssh->refresh()->connector_type);
        Http::assertNothingSent();
    }

    public function test_pending_unconsumed_callback_can_be_cancelled_without_issuing_tokens(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $url = $service->begin($alpha);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);

        $service->disconnect($alpha);
        self::assertSame(TargetConnectionState::Disconnected, $alpha->refresh()->connection_state);
        self::assertSame(0, DB::table('wp_ai_bridge_oauth_flows')->count());

        try {
            $service->completeCallback($args['state'], 'alpha-code', 'https://alpha.example.test', null);
            self::fail('Cancelled callback state was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('invalid_state', $exception->reason);
        }
    }

    public function test_failed_token_exchange_consumes_state_without_storing_secret_and_allows_fresh_authorization(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $url = $service->begin($alpha);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);
        $this->failTokenExchange = true;

        try {
            $service->completeCallback($args['state'], 'alpha-code', 'https://alpha.example.test', null);
            self::fail('Rejected token exchange was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('token_exchange_failed', $exception->reason);
        }

        self::assertSame(TargetConnectionState::ReconnectRequired, $alpha->refresh()->connection_state);
        self::assertSame(0, DB::table('target_credentials')->count());
        self::assertSame(0, DB::table('wp_ai_bridge_oauth_flows')->count());
        try {
            $service->completeCallback($args['state'], 'alpha-code', 'https://alpha.example.test', null);
            self::fail('Failed exchange state was replayed.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('invalid_state', $exception->reason);
        }

        $this->failTokenExchange = false;
        $this->pair($alpha);
        self::assertSame(TargetConnectionState::Connected, $alpha->refresh()->connection_state);
    }

    public function test_callback_in_flight_is_fenced_against_disconnect(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $url = $service->begin($alpha);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);
        $this->attemptConcurrentDisconnect = true;

        $service->completeCallback($args['state'], 'alpha-code', 'https://alpha.example.test', null);
        self::assertTrue($this->sawCallbackFence);
        self::assertSame(TargetConnectionState::Connected, $alpha->refresh()->connection_state);
        self::assertSame('alpha-access', $service->accessToken($alpha));
    }

    public function test_target_refresh_rotates_expired_credentials_with_generation_fencing_and_no_network_under_lock(): void
    {
        $alpha = $this->target('alpha');
        $beta = $this->target('beta');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($alpha);
        $this->pair($beta);
        $this->expire($alpha);
        $baseline = DB::transactionLevel();

        self::assertSame('alpha-rotated-access', $service->accessToken($alpha));
        self::assertSame('alpha-rotated-access', $service->accessToken($alpha));
        self::assertSame('beta-access', $service->accessToken($beta));
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($alpha)->getKey())->value('generation'));
        self::assertSame(1, (int) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($beta)->getKey())->value('generation'));
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame('alpha-rotated-refresh', app(WpAiBridgeTargetVault::class)
            ->openCredential($alpha, $this->credential($alpha))['refresh_token']);

        foreach ($this->outboundTransactionLevels as $level) {
            self::assertSame($baseline, $level, 'Refresh performed remote I/O inside a database transaction.');
        }
    }

    public function test_tcp_refusal_on_initial_refresh_is_definitively_unconsumed(): void
    {
        $this->assertFirstConnectionFailureDefersRefresh('connect');
    }

    public function test_tls_certificate_failure_on_initial_refresh_is_definitively_unconsumed(): void
    {
        $this->assertFirstConnectionFailureDefersRefresh('tls');
    }

    public function test_connection_timeout_on_initial_refresh_is_definitively_unconsumed(): void
    {
        $this->assertFirstConnectionFailureDefersRefresh('connect_timeout');
    }

    public function test_uncertain_network_timeout_does_not_clear_first_refresh_intent(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->refreshTransportFailure = 'network_timeout';

        try {
            $service->accessToken($target);
            self::fail('An uncertain post-send timeout must not clear the rotating-token intent.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        self::assertSame(1, $this->refreshCalls);
        self::assertSame(0, $this->refreshHandledByBridge);
        self::assertSame(1, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame('refresh_ambiguous', $target->last_error_code);
        self::assertSame(1, DB::table('target_credentials')->count());
    }

    public function test_connection_refusal_during_one_shot_recovery_does_not_clear_prior_ambiguity(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->failRefreshOnce = true;

        try {
            $service->accessToken($target);
            self::fail('An ambiguous original refresh cannot count as completed.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        DB::table('wp_ai_bridge_refresh_intents')
            ->update(['created_at' => now()->subSeconds(20)]);
        $this->refreshTransportFailure = 'connect';

        try {
            $service->accessToken($target);
            self::fail('A connection failure on recovery cannot erase a possibly rotated predecessor.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        self::assertSame(2, $this->refreshCalls);
        self::assertSame(1, $this->refreshHandledByBridge);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame(1, DB::table('target_credentials')->count());
        $this->refreshTransportFailure = null;

        try {
            $service->accessToken($target);
            self::fail('A third attempt must remain fenced even after TCP recovers.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(2, $this->refreshCalls);
    }

    public function test_mixed_dns_policy_on_first_refresh_preserves_grant_and_rejects_http_dispatch(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $before = app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target));

        $dns = $this->installSwitchablePrivateDnsFixture();
        $dns->reject = true;
        $service = app(WpAiBridgeTargetConnectionService::class);
        Log::spy();

        try {
            $service->routingContextWithRecovery($target);
            self::fail('Private DNS must be rejected before the token exchange.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        }

        self::assertSame(0, $this->refreshCalls);
        self::assertSame(0, $this->refreshHandledByBridge);
        Log::shouldHaveReceived('warning')->withArgs(static fn (string $message, array $context): bool => $message === 'WordPress OAuth refresh failed before dispatch.'
            && ($context['cause_code'] ?? null) === 'unsafe_target'
        )->once();
        $this->assertDeferredFirstRefreshIsUnconsumed($target, $before['refresh_token']);

        $dns->reject = false;
        $this->makeRefreshDueNow($target);
        self::assertSame('alpha-rotated-access', $service->accessToken($target));
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, $this->refreshHandledByBridge);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
    }

    public function test_unavailable_signing_key_on_first_refresh_preserves_grant_and_retries_after_repair(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $before = app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target));
        $originalKeyPath = (string) config('bridge.keys.private');
        config()->set('bridge.keys.private', sys_get_temp_dir().'/absent-gateway-key-'.Str::random(20));
        $service = app(WpAiBridgeTargetConnectionService::class);

        try {
            $service->routingContextWithRecovery($target);
            self::fail('Missing signing material must not leave an orphan refresh intent.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        } finally {
            config()->set('bridge.keys.private', $originalKeyPath);
        }

        self::assertSame(0, $this->refreshCalls);
        $this->assertDeferredFirstRefreshIsUnconsumed($target, $before['refresh_token']);
        $this->makeRefreshDueNow($target);
        self::assertSame('alpha-rotated-access', $service->accessToken($target));
        self::assertSame(1, $this->refreshHandledByBridge);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
    }

    public function test_mismatched_signing_key_on_first_refresh_is_unconsumed_and_recoverable(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $before = app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target));

        // Generate an unrelated *test-only* RSA private key, never touch the
        // currently configured Gateway signing material or real credentials.
        $unrelated = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($unrelated);
        self::assertTrue(openssl_pkey_export($unrelated, $unrelatedPem));
        $temporary = tempnam(sys_get_temp_dir(), 'mcp-gateway-key-fixture-');
        self::assertNotFalse($temporary);
        $original = (string) config('bridge.keys.private');
        try {
            self::assertNotFalse(file_put_contents($temporary, $unrelatedPem));
            config()->set('bridge.keys.private', $temporary);
            $service = app(WpAiBridgeTargetConnectionService::class);
            try {
                $service->accessToken($target);
                self::fail('A mismatched RSA keypair must not leave a remote token attempt or an orphan intent.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_unavailable', $exception->reason);
            }
        } finally {
            config()->set('bridge.keys.private', $original);
            unlink($temporary);
        }

        self::assertSame(0, $this->refreshCalls);
        $this->assertDeferredFirstRefreshIsUnconsumed($target, $before['refresh_token']);
        $this->makeRefreshDueNow($target);
        self::assertSame('alpha-rotated-access', app(WpAiBridgeTargetConnectionService::class)->accessToken($target));
        self::assertSame(1, $this->refreshHandledByBridge);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
    }

    public function test_weak_but_matching_rsa_key_jwt_domain_exception_does_not_orphan_first_refresh(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $credential = $this->credential($target);
        $credentialId = (string) $credential->getKey();
        $ciphertext = (string) $credential->getRawOriginal('encrypted_payload');
        $secret = app(WpAiBridgeTargetVault::class)->openCredential($target, $credential);
        $service = app(WpAiBridgeTargetConnectionService::class);
        Log::spy();

        $this->withMatchingWeakRsaSigningKeys(function () use ($service, $target): void {
            // Exercise the actual locked firebase/php-jwt RSA 2048-bit policy.
            // The Gateway's earlier parse/match checks must all succeed.
            $this->assertJwtRejectsWeakButMatchingKey();

            try {
                $service->accessToken($target);
                self::fail('A locally rejected JWT must not orphan an unused offline refresh.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_unavailable', $exception->reason);
            }
        });

        self::assertSame(0, $this->refreshCalls, 'Signing happens before any outbound token HTTP.');
        self::assertSame(0, $this->refreshHandledByBridge);
        self::assertSame($credentialId, (string) $this->credential($target)->getKey());
        self::assertSame($ciphertext, (string) $this->credential($target)->getRawOriginal('encrypted_payload'));
        $this->assertDeferredFirstRefreshIsUnconsumed($target, $secret['refresh_token']);

        $recordId = (string) $target->getKey();
        Log::shouldHaveReceived('warning')->withArgs(static fn (string $message, array $context): bool => $message === 'WordPress OAuth refresh failed before dispatch.'
            && array_keys($context) === ['target_record_id', 'cause_code']
            && ($context['target_record_id'] ?? null) === $recordId
            && ($context['cause_code'] ?? null) === 'client_assertion_unavailable'
        )->once();

        try {
            $service->accessToken($target);
            self::fail('A restored signing key must honor the bounded retry deadline.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        }
        self::assertSame(0, $this->refreshCalls);

        $this->makeRefreshDueNow($target);
        self::assertSame('alpha-rotated-access', $service->accessToken($target));
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, $this->refreshHandledByBridge);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
    }

    public function test_weak_matching_rsa_key_domain_exception_on_recovery_never_reopens_old_refresh(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $credential = $this->credential($target);
        $credentialId = (string) $credential->getKey();
        $ciphertext = (string) $credential->getRawOriginal('encrypted_payload');
        $refreshToken = app(WpAiBridgeTargetVault::class)->openCredential($target, $credential)['refresh_token'];
        $service = app(WpAiBridgeTargetConnectionService::class);

        $this->failRefreshOnce = true;
        try {
            $service->accessToken($target);
            self::fail('An ambiguous original refresh must not be considered successful.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        $intent = DB::table('wp_ai_bridge_refresh_intents')->first();
        self::assertNotNull($intent);
        self::assertSame(1, (int) $intent->attempts);
        DB::table('wp_ai_bridge_refresh_intents')->where('id', $intent->id)
            ->update(['created_at' => now()->subSeconds(20)]);
        Log::spy();

        $this->withMatchingWeakRsaSigningKeys(function () use ($service, $target): void {
            $this->assertJwtRejectsWeakButMatchingKey();

            try {
                $service->accessToken($target);
                self::fail('Second-attempt local JWT rejection must not clear the first uncertain rotation.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_ambiguous', $exception->reason);
            }
        });

        self::assertSame(1, $this->refreshCalls, 'A local signing failure cannot issue the second HTTP POST.');
        self::assertSame(1, $this->refreshHandledByBridge);
        $after = DB::table('wp_ai_bridge_refresh_intents')->first();
        self::assertNotNull($after);
        self::assertSame((string) $intent->id, (string) $after->id);
        self::assertSame(2, (int) $after->attempts);
        self::assertSame($credentialId, (string) $this->credential($target)->getKey());
        self::assertSame($ciphertext, (string) $this->credential($target)->getRawOriginal('encrypted_payload'));
        self::assertSame($refreshToken, app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target))['refresh_token']);
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame('refresh_ambiguous', $target->last_error_code);
        $recordId = (string) $target->getKey();
        Log::shouldHaveReceived('warning')->withArgs(static fn (string $message, array $context): bool => $message === 'WordPress OAuth refresh transport outcome ambiguous.'
            && array_keys($context) === ['target_record_id', 'cause_code']
            && ($context['target_record_id'] ?? null) === $recordId
            && ($context['cause_code'] ?? null) === 'client_assertion_unavailable'
        )->once();

        try {
            $service->accessToken($target);
            self::fail('Even after restoring the key, a third token exchange must stay fenced.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
    }

    public function test_mixed_dns_policy_during_recovery_keeps_prior_unknown_rotation_fenced(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->failRefreshOnce = true;
        try {
            $service->accessToken($target);
            self::fail('Original rotation must remain uncertain.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        $this->failRefreshOnce = false;
        DB::table('wp_ai_bridge_refresh_intents')
            ->update(['created_at' => now()->subSeconds(20)]);

        $dns = $this->installSwitchablePrivateDnsFixture();
        $dns->reject = true;
        $recover = app(WpAiBridgeTargetConnectionService::class);
        try {
            $recover->accessToken($target);
            self::fail('A blocked second attempt cannot clear the unknown first rotation.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        self::assertSame(1, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame(1, DB::table('target_credentials')->count());
        $dns->reject = false;
        try {
            $recover->accessToken($target);
            self::fail('Unsafe DNS recovery must not permit a third request.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
    }

    public function test_missing_signing_key_during_recovery_keeps_prior_unknown_rotation_fenced(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->failRefreshOnce = true;
        try {
            $service->accessToken($target);
            self::fail('Original rotation must remain uncertain.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        DB::table('wp_ai_bridge_refresh_intents')
            ->update(['created_at' => now()->subSeconds(20)]);

        $original = (string) config('bridge.keys.private');
        config()->set('bridge.keys.private', sys_get_temp_dir().'/missing-gateway-key-'.Str::random(20));
        try {
            $service->accessToken($target);
            self::fail('Missing assertion on recovery cannot clear a potentially used predecessor.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        } finally {
            config()->set('bridge.keys.private', $original);
        }

        self::assertSame(1, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame(1, DB::table('target_credentials')->count());
        try {
            $service->accessToken($target);
            self::fail('A third request after unprepared recovery must be rejected.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
    }

    public function test_first_refresh_dns_pre_dispatch_failure_preserves_offline_credential_and_retries_later(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $before = app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target));
        $dns = new class implements DnsResolver
        {
            public bool $fail = true;

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                if ($this->fail) {
                    throw new OutboundRequestException('network_failure', 'Synthetic pre-dispatch DNS timeout.', [], true);
                }

                return ['1.1.1.1'];
            }
        };
        $this->app->instance(DnsResolver::class, $dns);
        $service = app(WpAiBridgeTargetConnectionService::class);

        try {
            $service->routingContextWithRecovery($target);
            self::fail('Unsent refresh exchange must be deferred rather than retried immediately.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        }

        self::assertSame(0, $this->refreshCalls, 'Pre-dispatch DNS failure must not reach the token endpoint.');
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame('refresh_unavailable', $target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame($before['refresh_token'], app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target))['refresh_token']);

        try {
            $service->routingContextWithRecovery($target);
            self::fail('Backoff is required instead of spinning on another failed lookup.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        }
        self::assertSame(0, $this->refreshCalls);

        // Restore the disposable DNS fixture after the server-side bounded backoff.
        $dns->fail = false;
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['refresh_due_at' => now()->subSecond()]);

        self::assertSame('alpha-rotated-access', $service->accessToken($target));
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
    }

    public function test_pre_dispatch_failure_during_single_use_recovery_preserves_uncertain_first_rotation(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $dns = new class implements DnsResolver
        {
            public bool $fail = false;

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                if ($this->fail) {
                    throw new OutboundRequestException('network_failure', 'Synthetic recovery DNS failure.', [], true);
                }

                return ['1.1.1.1'];
            }
        };
        $this->app->instance(DnsResolver::class, $dns);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->failRefreshOnce = true;

        try {
            $service->accessToken($target);
            self::fail('Original remote rotation must remain uncertain.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
        DB::table('wp_ai_bridge_refresh_intents')
            ->update(['created_at' => now()->subSeconds(20)]);

        $dns->fail = true;
        try {
            $service->routingContext($target);
            self::fail('Recovery DNS failure cannot undo prior uncertain rotation.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        self::assertSame(1, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame('refresh_ambiguous', $target->last_error_code);
        self::assertSame(1, DB::table('target_credentials')->count());

        $dns->fail = false;
        try {
            $service->accessToken($target);
            self::fail('Unknown successor cannot permit a third blind refresh.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
    }

    public function test_owner_network_timeout_changes_cannot_shorten_inflight_refresh_recovery_fence(): void
    {
        $owner = $this->user('owner', 'all');
        $settings = app(OperationalSettings::class);
        $settings->save($owner, [
            'wp_response_kib' => null,
            'wp_readonly_response_kib' => null,
            'wp_connect_timeout_seconds' => 10,
            'wp_request_timeout_seconds' => 30,
        ], 0);

        $alpha = $this->target('alpha');
        $this->pair($alpha);
        $this->expire($alpha);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->failRefresh = true;
        try {
            $service->accessToken($alpha);
            self::fail('First lost response must be uncertain.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        self::assertSame(30, (int) DB::table('wp_ai_bridge_refresh_intents')
            ->value('request_timeout_seconds'));
        self::assertSame(35, $service->refreshRecoveryMinimumAge(
            DB::table('wp_ai_bridge_refresh_intents')->first()));

        // A new Owner edit may shorten *subsequent* HTTP requests, never
        // the admission fence of the already-possibly-sent refresh.
        $settings->save($owner, [
            'wp_response_kib' => null,
            'wp_readonly_response_kib' => null,
            'wp_connect_timeout_seconds' => 1,
            'wp_request_timeout_seconds' => 2,
        ], 1);
        self::assertSame(['connect' => 1, 'request' => 2],
            (new OperationalSettings)->httpTimeoutsSeconds());

        DB::table('wp_ai_bridge_refresh_intents')
            ->update(['created_at' => now()->subSeconds(20)]);
        try {
            $service->accessToken($alpha);
            self::fail('Owner reset must not permit an overlap with the old 30s request.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        DB::table('wp_ai_bridge_refresh_intents')
            ->update(['created_at' => now()->subSeconds(38)]);
        $this->failRefresh = false;
        self::assertSame('alpha-rotated-access', $service->accessToken($alpha));
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());

        // Pre-upgrade nullable rows must not let a later Owner override
        // shorten the original source-config request fence.
        $legacy = (object) ['request_timeout_seconds' => null];
        self::assertSame(12, $service->refreshRecoveryMinimumAge($legacy));
        $corrupt = (object) ['request_timeout_seconds' => 0];
        self::assertGreaterThanOrEqual(45, $service->refreshRecoveryMinimumAge($corrupt));
    }

    public function test_pre_upgrade_null_refresh_snapshot_preserves_original_effective_connect_deadline_after_owner_override(): void
    {
        // Before this migration the HTTP transport used max(connect, request),
        // so connect=15/request=5 could keep the original rotation in flight
        // for a full 15 seconds. The persisted intent is simulated as a
        // historical, pre-upgrade row with a NULL timeout snapshot.
        config()->set('bridge.http.connect_timeout_seconds', 15);
        config()->set('bridge.http.request_timeout_seconds', 5);
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->failRefresh = true;
        try {
            $service->accessToken($target);
            self::fail('The first ambiguous old-token refresh must be fenced.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(15, (int) DB::table('wp_ai_bridge_refresh_intents')
            ->value('request_timeout_seconds'));
        DB::table('wp_ai_bridge_refresh_intents')
            ->update(['request_timeout_seconds' => null]);

        $settings = app(OperationalSettings::class);
        $settings->save($this->user('owner', 'all'), [
            'wp_response_kib' => null,
            'wp_readonly_response_kib' => null,
            'wp_connect_timeout_seconds' => 1,
            'wp_request_timeout_seconds' => 2,
        ], 0);
        self::assertSame(['connect' => 1, 'request' => 2], $settings->httpTimeoutsSeconds());
        $intent = DB::table('wp_ai_bridge_refresh_intents')->first();
        self::assertNotNull($intent);
        self::assertNull($intent->request_timeout_seconds);
        self::assertSame(20, $service->refreshRecoveryMinimumAge($intent));

        foreach ([12, 19] as $ageSeconds) {
            DB::table('wp_ai_bridge_refresh_intents')->update([
                'created_at' => now()->subSeconds($ageSeconds),
            ]);
            try {
                $service->accessToken($target);
                self::fail('A pre-migration old refresh request must not overlap at '.$ageSeconds.' seconds.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_pending', $exception->reason);
            }
            self::assertSame(1, $this->refreshCalls);
            self::assertSame(1, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        }

        // No additional remote request is dispatched until after the full
        // legacy effective deadline, still inside the existing 45s window.
        DB::table('wp_ai_bridge_refresh_intents')->update([
            'created_at' => now()->subSeconds(24),
        ]);
        $this->failRefresh = false;
        self::assertSame('alpha-rotated-access', $service->accessToken($target));
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame('alpha-rotated-access', $service->accessToken($target));
        self::assertSame(2, $this->refreshCalls, 'A third old-token recovery request is forbidden.');
    }

    public function test_pre_upgrade_null_refresh_snapshot_fences_manual_revocation_settling_with_legacy_connect_deadline(): void
    {
        config()->set('bridge.http.connect_timeout_seconds', 15);
        config()->set('bridge.http.request_timeout_seconds', 5);
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->failRefresh = true;
        try {
            $service->accessToken($target);
            self::fail('Ambiguous old-token refresh must be recorded.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        DB::table('wp_ai_bridge_refresh_intents')->update([
            'request_timeout_seconds' => null,
            'created_at' => now()->subSeconds(85),
        ]);
        $settings = app(OperationalSettings::class);
        $settings->save($this->user('owner', 'all'), [
            'wp_response_kib' => null,
            'wp_readonly_response_kib' => null,
            'wp_connect_timeout_seconds' => 1,
            'wp_request_timeout_seconds' => 2,
        ], 0);
        $intent = DB::table('wp_ai_bridge_refresh_intents')->first();
        self::assertNotNull($intent);
        self::assertSame(20, $service->refreshRecoveryMinimumAge($intent));
        $auditRecorded = false;
        try {
            $service->reconcileRevokedRefresh($target, (string) $intent->id, static function () use (&$auditRecorded): void {
                $auditRecorded = true;
            });
            self::fail('Manual reconciliation cannot settle before 60 + 15 + 15 seconds.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_settling', $exception->reason);
        }
        self::assertFalse($auditRecorded);
        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame(1, $this->refreshCalls);

        DB::table('wp_ai_bridge_refresh_intents')->update([
            'created_at' => now()->subSeconds(96),
        ]);
        $service->reconcileRevokedRefresh($target, (string) $intent->id, static function () use (&$auditRecorded): void {
            $auditRecorded = true;
        });
        self::assertTrue($auditRecorded);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(0, DB::table('target_credentials')->count());
        self::assertSame(TargetConnectionState::Disconnected, $target->refresh()->connection_state);
        self::assertSame(1, $this->refreshCalls);
    }

    public function test_rollback_refuses_to_discard_unresolved_original_http_timeout_snapshot(): void
    {
        $alpha = $this->target('alpha');
        $this->pair($alpha);
        $this->expire($alpha);
        $this->failRefresh = true;
        try {
            app(WpAiBridgeTargetConnectionService::class)->accessToken($alpha);
            self::fail('Lost refresh response must be ambiguous.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertNotNull(DB::table('wp_ai_bridge_refresh_intents')->value('request_timeout_seconds'));
        $migration = require database_path('migrations/2026_10_12_000000_snapshot_wordpress_refresh_http_timeout.php');
        try {
            $migration->down();
            self::fail('Schema rollback must not discard an unresolved possibly sent refresh timeout fence.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('snapshotted refresh intents remain unresolved', $exception->getMessage());
        }
        self::assertTrue(Schema::hasColumn('wp_ai_bridge_refresh_intents', 'request_timeout_seconds'));
        self::assertTrue(Schema::hasColumn('operational_settings', 'wp_request_timeout_seconds'));
        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, $this->refreshCalls);
    }

    public function test_lost_refresh_response_fences_disconnect_and_supports_only_one_bounded_recovery(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($alpha);
        $this->expire($alpha);
        $this->failRefresh = true;

        try {
            $service->accessToken($alpha);
            self::fail('Failed first refresh was treated as success.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $alpha->refresh()->connection_state);

        try {
            $service->disconnect($alpha);
            self::fail('Unknown rotating successor was silently disconnected.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        $service->testConnection($alpha);
        self::assertSame('refresh_ambiguous', $alpha->refresh()->last_error_code);
        try {
            $service->accessToken($alpha);
            self::fail('An in-flight refresh was replayed concurrently.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);

        // Simulate passage of the configured request timeout, still inside
        // WordPress's fixed 60-second one-shot recovery envelope.
        DB::table('wp_ai_bridge_refresh_intents')->update(['created_at' => now()->subSeconds(20)]);
        $this->failRefresh = false;
        self::assertSame('alpha-rotated-access', $service->accessToken($alpha));
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(TargetConnectionState::Connected, $alpha->refresh()->connection_state);
    }

    public function test_definitively_rejected_refresh_blocks_remote_replay_and_requires_reconciliation(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($alpha);
        $this->expire($alpha);
        $this->rejectRefresh = true;

        try {
            $service->accessToken($alpha);
            self::fail('Rejected refresh was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_rejected', $exception->reason);
        }
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        DB::table('wp_ai_bridge_refresh_intents')->update(['created_at' => now()->subSeconds(20)]);
        try {
            $service->accessToken($alpha);
            self::fail('Rejected refresh was automatically replayed.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, DB::table('target_credentials')->count());
    }

    public function test_second_unknown_rotation_never_triggers_a_third_refresh_replay(): void
    {
        $alpha = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($alpha);
        $this->expire($alpha);
        $this->failRefresh = true;

        for ($attempt = 1; $attempt <= 2; $attempt++) {
            if ($attempt === 2) {
                DB::table('wp_ai_bridge_refresh_intents')->update(['created_at' => now()->subSeconds(20)]);
            }
            try {
                $service->accessToken($alpha);
                self::fail('A failed refresh returned a valid bearer.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_ambiguous', $exception->reason);
            }
        }
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));

        $this->failRefresh = false;
        try {
            $service->accessToken($alpha);
            self::fail('An unresolved second rotation was replayed a third time.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(1, DB::table('target_credentials')->count());
    }

    public function test_due_idle_maintenance_rotates_only_selected_wordpress_target_before_expiry(): void
    {
        $alpha = $this->target('alpha');
        $beta = $this->target('beta');
        $this->pair($alpha);
        $this->pair($beta);
        $due = DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $this->credential($alpha)->getKey())->first();
        self::assertNotNull($due);
        self::assertGreaterThan(time() + 3000, strtotime((string) $due->refresh_expires_at));
        self::assertGreaterThan(time() + 1000, strtotime((string) $due->refresh_due_at));
        DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $this->credential($alpha)->getKey())
            ->update(['refresh_due_at' => now()->subMinute()]);

        $baseline = DB::transactionLevel();
        self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(1, $this->refreshCalls);
        self::assertSame('alpha-rotated-access',
            app(WpAiBridgeTargetConnectionService::class)->accessToken($alpha));
        self::assertSame('beta-access',
            app(WpAiBridgeTargetConnectionService::class)->accessToken($beta));
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $this->credential($alpha)->getKey())->value('generation'));
        self::assertSame(1, (int) DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $this->credential($beta)->getKey())->value('generation'));
        self::assertGreaterThan(time() + 1000,
            strtotime((string) DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $this->credential($alpha)->getKey())->value('refresh_due_at')));
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        foreach ($this->outboundTransactionLevels as $level) {
            self::assertSame($baseline, $level, 'Idle refresh performed remote I/O under a database lock.');
        }
    }

    public function test_temporary_http_400_invalid_client_preserves_unconsumed_offline_grant_for_later_read(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $credential = $this->credential($target);
        $before = app(WpAiBridgeTargetVault::class)->openCredential($target, $credential);
        $this->failClientAuthentication = true;
        $service = app(WpAiBridgeTargetConnectionService::class);

        Sleep::fake();
        try {
            try {
                $service->routingContextWithRecovery($target);
                self::fail('Temporary pre-rotation client authentication was treated as success.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_unavailable', $exception->reason);
            }
            Sleep::assertNeverSlept();
        } finally {
            Sleep::fake(false);
        }

        self::assertSame(1, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame('refresh_unavailable', $target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        $after = app(WpAiBridgeTargetVault::class)->openCredential($target, $this->credential($target));
        self::assertSame($before['refresh_token'], $after['refresh_token']);
        self::assertSame(1, (int) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())->value('generation'));
        $retryAt = strtotime((string) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())->value('refresh_due_at'));
        self::assertGreaterThan(time(), $retryAt);
        self::assertLessThanOrEqual(time() + 60, $retryAt);

        try {
            $service->routingContextWithRecovery($target);
            self::fail('A follow-up read spun another network refresh before backoff.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(1, $this->refreshCalls);

        // Dependency restored; time advances to the scheduled bounded retry.
        $this->failClientAuthentication = false;
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())
            ->update(['refresh_due_at' => now()->subSecond()]);
        self::assertSame('alpha-rotated-access', $service->routingContextWithRecovery($target)['access_token']);
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())->value('generation'));
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertNull($target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
    }

    public function test_idle_maintenance_http_400_invalid_client_defers_without_revoking_or_recovery_replay(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $credential = $this->credential($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())
            ->update(['refresh_due_at' => now()->subSecond()]);
        $this->failClientAuthentication = true;

        Sleep::fake();
        try {
            self::assertSame(1, Artisan::call('gateway:wordpress-credentials-maintain'));
            Sleep::assertNeverSlept();
        } finally {
            Sleep::fake(false);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame('refresh_unavailable', $target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, (int) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())->value('generation'));
        self::assertSame('alpha-access',
            app(WpAiBridgeTargetConnectionService::class)->accessToken($target));
        self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(1, $this->refreshCalls);

        $this->failClientAuthentication = false;
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())
            ->update(['refresh_due_at' => now()->subSecond()]);
        self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertNull($target->last_error_code);
    }

    public function test_invalid_client_on_second_attempt_cannot_clear_prior_ambiguous_rotation(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $this->failRefreshOnce = true;
        $service = app(WpAiBridgeTargetConnectionService::class);
        try {
            $service->routingContext($target);
            self::fail('The first lost response must remain uncertain.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        DB::table('wp_ai_bridge_refresh_intents')->update([
            'created_at' => now()->subSeconds(20),
        ]);
        $this->failClientAuthentication = true;
        try {
            $service->routingContext($target);
            self::fail('The second request was falsely accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);

        $this->failClientAuthentication = false;
        try {
            $service->routingContext($target);
            self::fail('A third replay was permitted after an uncertain successor.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
        self::assertSame(2, $this->refreshCalls);
    }

    public function test_http_400_temporarily_unavailable_keeps_lost_successor_recovery_fence(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $this->temporarilyUnavailable400Once = true;

        Sleep::fake();
        Sleep::whenFakingSleep(static function (): void {
            DB::table('wp_ai_bridge_refresh_intents')->update([
                'created_at' => now()->subSeconds(20),
            ]);
        });
        try {
            $response = app(WpAiBridgeTargetConnectionService::class)
                ->routingContextWithRecovery($target);
            Sleep::assertSleptTimes(1);
        } finally {
            Sleep::fake(false);
        }

        self::assertSame('alpha-rotated-access', $response['access_token']);
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
    }

    public function test_lost_refresh_successor_expiry_is_anchored_to_first_request(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $this->failRefreshOnce = true;
        $service = app(WpAiBridgeTargetConnectionService::class);
        try {
            $service->routingContext($target);
            self::fail('The first response must be uncertain.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        $issuedAt = time() - 20;
        DB::table('wp_ai_bridge_refresh_intents')->update([
            'created_at' => now()->subSeconds(20),
        ]);
        self::assertSame('alpha-rotated-access', $service->accessToken($target));

        $meta = DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())->first();
        self::assertNotNull($meta);
        self::assertEqualsWithDelta($issuedAt + 3600,
            strtotime((string) $meta->access_expires_at), 2);
        self::assertEqualsWithDelta($issuedAt + 7200,
            strtotime((string) $meta->refresh_expires_at), 2);
        self::assertEqualsWithDelta($issuedAt + 3600,
            strtotime((string) $meta->refresh_due_at), 2);
    }

    public function test_stale_health_does_not_rotate_30_day_offline_refresh_on_access_token_half_life(): void
    {
        $target = $this->target('alpha');
        $this->refreshTokenTtl = 2592000; // WordPress's currently advertised 30-day lifetime.
        $this->pair($target);

        $metadata = DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())->first();
        self::assertNotNull($metadata);
        $refreshDue = strtotime((string) $metadata->refresh_due_at);
        self::assertGreaterThan(time() + 14 * 86400, $refreshDue);
        self::assertLessThan(time() + 16 * 86400, $refreshDue);

        // Stale means an old health observation, not disconnection or
        // permission to rotate this still-valid offline grant every 30m.
        $target->forceFill(['last_success_at' => now()->subWeeks(3)])->save();
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(0, $this->refreshCalls);
        self::assertSame(1, DB::table('target_credentials')->count());

        // The expired 1h access bearer must be transparently replaced on the
        // next read, without interpreting three weeks of Stale as revocation.
        $this->expire($target);
        self::assertSame('alpha-rotated-access',
            app(WpAiBridgeTargetConnectionService::class)
                ->routingContextWithRecovery($target)['access_token']);
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
    }

    public function test_on_demand_access_refresh_recovers_single_transient_503_without_reauthorization(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $this->failRefreshOnce = true;

        Sleep::fake();
        Sleep::whenFakingSleep(static function (): void {
            DB::table('wp_ai_bridge_refresh_intents')->update([
                'created_at' => now()->subSeconds(20),
            ]);
        });
        try {
            $response = app(WpAiBridgeTargetConnectionService::class)
                ->routingContextWithRecovery($target);
            Sleep::assertSleptTimes(1);
        } finally {
            Sleep::fake(false);
        }

        self::assertSame('alpha-rotated-access', $response['access_token']);
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertNull($target->last_error_code);
    }

    public function test_on_demand_refresh_never_recovers_rejected_or_exhausted_refresh(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $this->rejectRefresh = true;

        Sleep::fake();
        try {
            try {
                app(WpAiBridgeTargetConnectionService::class)
                    ->routingContextWithRecovery($target);
                self::fail('A definitive invalid_grant must not be retried.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_rejected', $exception->reason);
            }
            Sleep::assertNeverSlept();
        } finally {
            Sleep::fake(false);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
    }

    public function test_on_demand_refresh_never_replays_outside_the_one_shot_window(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $this->failRefreshOnce = true;

        try {
            app(WpAiBridgeTargetConnectionService::class)->routingContext($target);
            self::fail('First uncertain refresh should not be treated as a successful call.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }
        DB::table('wp_ai_bridge_refresh_intents')->update([
            'created_at' => now()->subSeconds(50),
        ]);

        Sleep::fake();
        try {
            try {
                app(WpAiBridgeTargetConnectionService::class)
                    ->routingContextWithRecovery($target);
                self::fail('Expired recovery intent must not be replayed.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                self::assertSame('refresh_pending', $exception->reason);
            }
            Sleep::assertNeverSlept();
        } finally {
            Sleep::fake(false);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
    }

    public function test_ambiguous_idle_maintenance_uses_only_one_bounded_recovery_then_fails_closed(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['refresh_due_at' => now()->subMinute()]);
        $this->failRefresh = true;

        Sleep::fake();
        Sleep::whenFakingSleep(static function (): void {
            // Simulate waiting inside the single-use WordPress window without
            // introducing a real 12-second pause in the feature suite.
            DB::table('wp_ai_bridge_refresh_intents')->update([
                'created_at' => now()->subSeconds(20),
            ]);
        });
        try {
            self::assertSame(1, Artisan::call('gateway:wordpress-credentials-maintain'));
            Sleep::assertSleptTimes(1);
        } finally {
            Sleep::fake(false);
        }

        self::assertSame(2, $this->refreshCalls);
        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame('refresh_ambiguous', $target->last_error_code);
        // A later cron tick must never replay the same old token a third time.
        self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(2, $this->refreshCalls);
    }

    public function test_idle_refresh_retries_once_after_lost_response_and_restores_connected_state(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['refresh_due_at' => now()->subMinute()]);
        $this->failRefreshOnce = true;

        Sleep::fake();
        Sleep::whenFakingSleep(static function (): void {
            DB::table('wp_ai_bridge_refresh_intents')->update([
                'created_at' => now()->subSeconds(20),
            ]);
        });
        try {
            self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
            Sleep::assertSleptTimes(1);
        } finally {
            Sleep::fake(false);
        }

        self::assertSame(2, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertNull($target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(2, (int) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())->value('generation'));
        self::assertSame('alpha-rotated-access',
            app(WpAiBridgeTargetConnectionService::class)->accessToken($target));
    }

    public function test_idle_refresh_terminal_rejection_never_queues_automatic_recovery(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['refresh_due_at' => now()->subMinute()]);
        $this->rejectRefresh = true;

        Sleep::fake();
        try {
            self::assertSame(1, Artisan::call('gateway:wordpress-credentials-maintain'));
            Sleep::assertNeverSlept();
        } finally {
            Sleep::fake(false);
        }
        self::assertSame(1, $this->refreshCalls);
        self::assertSame('refresh_rejected', $target->refresh()->last_error_code);
        self::assertSame(2, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
    }

    public function test_idle_refresh_abandons_replay_when_settling_would_exceed_recovery_window(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['refresh_due_at' => now()->subMinute()]);
        $this->failRefreshOnce = true;

        Sleep::fake();
        Sleep::whenFakingSleep(static function (): void {
            // Simulate a delayed CLI wakeup; no replay after the short window.
            DB::table('wp_ai_bridge_refresh_intents')->update([
                'created_at' => now()->subSeconds(60),
            ]);
        });
        try {
            self::assertSame(1, Artisan::call('gateway:wordpress-credentials-maintain'));
            Sleep::assertSleptTimes(1);
        } finally {
            Sleep::fake(false);
        }

        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, (int) DB::table('wp_ai_bridge_refresh_intents')->value('attempts'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
    }

    public function test_expired_offline_credential_is_rejected_without_remote_refresh(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update([
                'refresh_due_at' => now()->subMinutes(5),
                'refresh_expires_at' => now()->subMinute(),
            ]);

        self::assertSame(1, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(0, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame('refresh_expired', $target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
    }

    public function test_encrypted_oauth_flow_expiry_cannot_be_extended_by_editing_database_timestamp(): void
    {
        $target = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $url = $service->begin($target);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $params);
        self::assertIsString($params['state']);

        // The encrypted state binds its original expiration. Changing only
        // the database row must not extend the authorization window.
        DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $target->getKey())
            ->update(['expires_at' => now()->addDays(2)]);
        try {
            $service->completeCallback($params['state'], 'alpha-code', 'https://alpha.example.test', null);
            self::fail('Database timestamp manipulation extended the protected OAuth flow.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('invalid_state', $exception->reason);
        }

        self::assertSame(0, DB::table('target_credentials')->count());
        self::assertSame(TargetConnectionState::Pending, $target->refresh()->connection_state);
    }

    public function test_unrotated_refresh_success_is_ambiguous_and_never_replaces_known_ciphertext(): void
    {
        $target = $this->target('alpha');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($target);
        $original = $this->credential($target);
        $originalCiphertext = $original->encrypted_payload;
        $this->expire($target);
        $ciphertextBeforeRefresh = $this->credential($target)->encrypted_payload;
        $this->malformedRefresh = true;

        try {
            $service->accessToken($target);
            self::fail('Unrotated OAuth refresh token was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        self::assertSame(1, $this->refreshCalls);
        self::assertSame($ciphertextBeforeRefresh, $this->credential($target)->encrypted_payload);
        self::assertNotSame($originalCiphertext, $ciphertextBeforeRefresh);
        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        try {
            $service->disconnect($target);
            self::fail('Unknown downstream token state was disconnected without reconciliation.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_pending', $exception->reason);
        }
    }

    public function test_manual_ambiguous_refresh_reconciliation_is_owner_only_and_requires_remote_attestation(): void
    {
        $alpha = $this->target('alpha');
        $beta = $this->target('beta');
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->pair($alpha);
        $this->pair($beta);
        $this->expire($alpha);
        $this->failRefresh = true;

        try {
            $service->accessToken($alpha);
            self::fail('Ambiguous rotating refresh was accepted.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        $intent = DB::table('wp_ai_bridge_refresh_intents')->where('target_record_id', $alpha->getKey())->first();
        self::assertNotNull($intent);
        $payload = [
            'intent_id' => $intent->id,
            'confirm_target_id' => 'alpha',
            'wordpress_client_revoked' => 'yes',
            'other_clients_affected' => 'yes',
            'current_password' => 'CorrectHorse!234',
        ];

        $this->actingAs($this->user('operator', 'all'))
            ->post('/admin/targets/alpha/reconcile-refresh', $payload)->assertForbidden();
        $this->actingAs($this->user('owner', 'all'))
            ->post('/admin/targets/alpha/reconcile-refresh', [
                ...$payload, 'current_password' => 'wrong',
            ])->assertSessionHasErrors('current_password');
        $this->post('/admin/targets/alpha/reconcile-refresh', [
            ...$payload, 'wordpress_client_revoked' => '',
        ])->assertSessionHasErrors('wordpress_client_revoked');
        $this->get('/admin/targets/alpha')->assertOk()
            ->assertSee('Manual WordPress refresh recovery')
            ->assertSee('other non-ChatGPT OAuth clients');

        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(2, DB::table('target_credentials')->count());

        // The remote one-shot recovery window must expire first.
        $this->post('/admin/targets/alpha/reconcile-refresh', $payload)
            ->assertRedirect('/admin/targets/alpha')
            ->assertSessionHasErrors('target');
        self::assertSame(2, DB::table('target_credentials')->count());

        // Purely test a simulated human-confirmed WordPress-side client
        // approval-revision change; this cannot prove a real remote revocation.
        DB::table('wp_ai_bridge_refresh_intents')->where('id', $intent->id)
            ->update(['created_at' => now()->subMinutes(3)]);
        $refreshCallsBefore = $this->refreshCalls;
        $this->post('/admin/targets/alpha/reconcile-refresh', $payload)
            ->assertRedirect('/admin/targets/alpha')
            ->assertSessionHasNoErrors();

        self::assertSame($refreshCallsBefore, $this->refreshCalls);
        self::assertSame(TargetConnectionState::Disconnected, $alpha->refresh()->connection_state);
        self::assertSame('manual_revocation_attested', $alpha->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(0, DB::table('target_credentials')->where('target_record_id', $alpha->getKey())->count());
        self::assertSame(1, DB::table('target_credentials')->where('target_record_id', $beta->getKey())->count());
        self::assertSame('beta-access', $service->accessToken($beta));

        self::assertSame(1, DB::table('activity_events')
            ->where('target_record_id', $alpha->getKey())
            ->where('operation', 'wordpress-refresh-remote-revocation-attested')
            ->where('outcome', 'operator-attested')->count());
        $this->post('/admin/targets/alpha/reconcile-refresh', $payload)
            ->assertSessionHasErrors('target');
        // Fresh pairing is possible only after the operator restores
        // Gateway client approval and initiates a new WordPress OAuth flow.
        self::assertStringContainsString('state=', $service->begin($alpha));
    }

    public function test_refresh_manual_reconciliation_rejects_stale_intent_and_wrong_target(): void
    {
        $alpha = $this->target('alpha');
        $this->pair($alpha);
        $this->expire($alpha);
        $this->failRefresh = true;
        try {
            app(WpAiBridgeTargetConnectionService::class)->accessToken($alpha);
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        $intent = DB::table('wp_ai_bridge_refresh_intents')->first();
        self::assertNotNull($intent);
        DB::table('wp_ai_bridge_refresh_intents')->where('id', $intent->id)
            ->update(['created_at' => now()->subMinutes(3)]);

        $this->actingAs($this->user('owner', 'all'));
        $payload = [
            'intent_id' => $intent->id,
            'confirm_target_id' => 'other-target',
            'wordpress_client_revoked' => 'yes',
            'other_clients_affected' => 'yes',
            'current_password' => 'CorrectHorse!234',
        ];
        $this->post('/admin/targets/alpha/reconcile-refresh', $payload)
            ->assertSessionHasErrors('confirm_target_id');
        $this->post('/admin/targets/alpha/reconcile-refresh', [
            ...$payload, 'confirm_target_id' => 'alpha', 'intent_id' => (string) Str::ulid(),
        ])->assertSessionHasErrors('target');

        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame(0, DB::table('activity_events')
            ->where('operation', 'wordpress-refresh-remote-revocation-attested')->count());
    }

    public function test_manual_revocation_reconciliation_rolls_back_if_required_audit_fails(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $this->failRefresh = true;
        $service = app(WpAiBridgeTargetConnectionService::class);
        try {
            $service->accessToken($target);
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_ambiguous', $exception->reason);
        }

        $intent = DB::table('wp_ai_bridge_refresh_intents')->first();
        self::assertNotNull($intent);
        DB::table('wp_ai_bridge_refresh_intents')->where('id', $intent->id)
            ->update(['created_at' => now()->subMinutes(3)]);
        $credentialId = (string) $this->credential($target)->getKey();

        try {
            $service->reconcileRevokedRefresh($target, $intent->id, static function (): void {
                throw new \RuntimeException('Synthetic mandatory audit database failure.');
            });
            self::fail('An absent mandatory audit was treated as completed reconciliation.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Synthetic mandatory audit database failure.', $exception->getMessage());
        }

        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->where('id', $intent->id)->count());
        self::assertSame(1, DB::table('target_credentials')->where('id', $credentialId)->count());
        self::assertSame(1, DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credentialId)->count());
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame('refresh_ambiguous', $target->last_error_code);
    }

    /**
     * Exercise a well-formed matching RSA keypair that the locked JWT library
     * rejects at signing time. Fixtures are temporary; production keys and
     * the repository's key generation policy remain untouched.
     *
     * @param  callable(): void  $callback
     */
    private function withMatchingWeakRsaSigningKeys(callable $callback): void
    {
        $generated = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($generated);
        self::assertTrue(openssl_pkey_export($generated, $privatePem));
        $details = openssl_pkey_get_details($generated);
        self::assertIsArray($details);
        self::assertIsString($details['key'] ?? null);

        $privateFile = tempnam(sys_get_temp_dir(), 'gateway-short-rsa-private-');
        self::assertNotFalse($privateFile);
        $publicFile = tempnam(sys_get_temp_dir(), 'gateway-short-rsa-public-');
        self::assertNotFalse($publicFile);
        $originalPrivate = (string) config('bridge.keys.private');
        $originalPublic = (string) config('bridge.keys.public');

        try {
            self::assertNotFalse(file_put_contents($privateFile, $privatePem));
            self::assertNotFalse(file_put_contents($publicFile, $details['key']));
            config()->set('bridge.keys.private', $privateFile);
            config()->set('bridge.keys.public', $publicFile);
            $callback();
        } finally {
            config()->set('bridge.keys.private', $originalPrivate);
            config()->set('bridge.keys.public', $originalPublic);
            unlink($privateFile);
            unlink($publicFile);
        }
    }

    private function assertJwtRejectsWeakButMatchingKey(): void
    {
        try {
            app(GatewayBridgeClientIdentity::class)
                ->assertion('https://alpha.example.test/wp-json/wp-ai-bridge/v1/oauth/token');
            self::fail('The locked JWT library must reject an RSA key smaller than 2048 bits.');
        } catch (\DomainException $exception) {
            self::assertNotSame('', $exception->getMessage());
        }
    }

    private function assertFirstConnectionFailureDefersRefresh(string $mode): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->expire($target);
        $before = app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target));
        $service = app(WpAiBridgeTargetConnectionService::class);
        $this->refreshTransportFailure = $mode;

        try {
            $service->routingContextWithRecovery($target);
            self::fail('A failed TCP/TLS handshake must not strand an unconsumed refresh grant.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        }

        self::assertSame(1, $this->refreshCalls, 'One transport attempt was made.');
        self::assertSame(0, $this->refreshHandledByBridge, 'No token request reached the fixture endpoint.');
        $this->assertDeferredFirstRefreshIsUnconsumed($target, $before['refresh_token']);
        try {
            $service->routingContextWithRecovery($target);
            self::fail('A transient handshake failure must use bounded backoff.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('refresh_unavailable', $exception->reason);
        }
        self::assertSame(1, $this->refreshCalls);

        $this->refreshTransportFailure = null;
        $this->makeRefreshDueNow($target);
        self::assertSame('alpha-rotated-access', $service->accessToken($target));
        self::assertSame(2, $this->refreshCalls);
        self::assertSame(1, $this->refreshHandledByBridge);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
    }

    private function assertDeferredFirstRefreshIsUnconsumed(Target $target, string $refreshToken): void
    {
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame('refresh_unavailable', $target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame($refreshToken, app(WpAiBridgeTargetVault::class)
            ->openCredential($target, $this->credential($target))['refresh_token']);
        self::assertSame(1, (int) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())->value('generation'));
        $dueAt = strtotime((string) DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())->value('refresh_due_at'));
        self::assertGreaterThan(time(), $dueAt);
        self::assertLessThanOrEqual(time() + 60, $dueAt);
    }

    private function makeRefreshDueNow(Target $target): void
    {
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['refresh_due_at' => now()->subSecond()]);
    }

    private function installSwitchablePrivateDnsFixture(): DnsResolver
    {
        $dns = new class implements DnsResolver
        {
            public bool $reject = false;

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $this->reject
                    ? ['8.8.8.8', '10.0.0.8']
                    : ['8.8.8.8'];
            }
        };
        $this->app->instance(DnsResolver::class, $dns);

        return $dns;
    }

    public function test_predispatch_retry_completes_only_same_intent_and_prevents_double_submit(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->revokeFailureMode = 'pre_dispatch';
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
            self::fail('Expected pre-dispatch refusal.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('network_failure', $exception->reason);
            self::assertTrue($exception->diagnostics['pre_dispatch']);
        }
        $intent = DB::table('wp_ai_bridge_revocation_intents')->first();
        self::assertSame('retryable', $intent->phase);
        self::assertSame(0, (int) $intent->token_confirmed);
        $this->actingAs($this->user('owner', 'all'))->get('/admin/targets/alpha')
            ->assertOk()->assertSee('Finish disconnect')->assertSee('Cancel pending disconnect');
        $this->revokeFailureMode = null;
        $this->post('/admin/targets/alpha/finish-disconnect', ['intent_id' => $intent->id])
            ->assertRedirect('/admin/targets/alpha')->assertSessionHas('status');
        self::assertSame(['alpha-refresh', 'alpha-refresh', 'alpha-access'], $this->revocationTokenAttempts);
        self::assertSame(TargetConnectionState::Disconnected, $target->refresh()->connection_state);
        $this->post('/admin/targets/alpha/finish-disconnect', ['intent_id' => $intent->id])
            ->assertSessionHasErrors('target');
        self::assertSame(['alpha-refresh', 'alpha-refresh', 'alpha-access'], $this->revocationTokenAttempts);
    }

    public function test_expiring_access_token_hides_cancel_and_preserves_service_authority(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->revokeFailureMode = 'pre_dispatch';
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
            self::fail('Expected pre-dispatch refusal.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('network_failure', $exception->reason);
        }
        $intent = DB::table('wp_ai_bridge_revocation_intents')->first();
        self::assertSame('retryable', $intent->phase);

        $owner = $this->user('owner', 'all');
        $this->actingAs($owner)->get('/admin/targets/alpha')
            ->assertOk()->assertSee('Cancel pending disconnect');

        // The recorded metadata and encrypted credential both become expired.
        $this->expire($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['access_expires_at' => now()->subMinute()]);

        $this->get('/admin/targets/alpha')
            ->assertOk()
            ->assertDontSee('Cancel pending disconnect')
            ->assertSee('verification token has expired or expires too soon')
            ->assertSee('Finish disconnect');

        // The same UI refusal also covers tokens expiring within 30 seconds.
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['access_expires_at' => now()->addSeconds(25)]);
        $this->get('/admin/targets/alpha')
            ->assertOk()
            ->assertDontSee('Cancel pending disconnect')
            ->assertSee('verification token has expired or expires too soon');

        // Forged POST is still rejected by the authoritative credential check.
        $this->post('/admin/targets/alpha/cancel-disconnect', [
            'intent_id' => $intent->id, 'confirm_target_id' => 'alpha',
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'cancel_verification_unavailable');
        self::assertSame('retryable', DB::table('wp_ai_bridge_revocation_intents')->value('phase'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame(0, $this->catalogProbeCalls);
    }

    public function test_partial_acknowledgment_resumes_without_replaying_first_token(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->revokeFailureMode = 'second_pre_dispatch';
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
            self::fail('Expected second-token refusal.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('network_failure', $exception->reason);
        }
        $intent = DB::table('wp_ai_bridge_revocation_intents')->first();
        self::assertSame('retryable', $intent->phase);
        self::assertSame(1, (int) $intent->token_confirmed);
        $this->revokeFailureMode = null;
        app(WpAiBridgeTargetConnectionService::class)->disconnect($target, (string) $intent->id);
        self::assertSame(['alpha-refresh', 'alpha-access', 'alpha-access'], $this->revocationTokenAttempts);
        self::assertSame(TargetConnectionState::Disconnected, $target->refresh()->connection_state);
    }

    public function test_lost_revoke_response_never_allows_cancel_or_replay_after_public_metadata_success(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->revokeFailureMode = 'response_lost';
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
            self::fail('Response loss must not become confirmed revocation.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('network_failure', $exception->reason);
            self::assertFalse($exception->diagnostics['pre_dispatch']);
        }
        $intent = DB::table('wp_ai_bridge_revocation_intents')->first();
        self::assertSame('unknown', $intent->phase);
        $this->revokeFailureMode = null;
        app(WpAiBridgeTargetConnectionService::class)->testConnection($target);
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame(1, DB::table('target_credentials')->count());
        $this->actingAs($this->user('owner', 'all'))->get('/admin/targets/alpha')
            ->assertOk()->assertSee('WordPress-side recovery for uncertain revocation')
            ->assertDontSee('Cancel pending disconnect')
            ->assertSee('Public metadata verified')
            ->assertSee('Blocked: the existing WordPress credential cannot be used.');
        try {
            app(WpAiBridgeTargetConnectionService::class)->cancelNeverSentDisconnect(
                $target, (string) $intent->id,
                static function (): void {
                    self::fail('Invalid cancel attempted remote verification.');
                },
                static function (): void {
                    self::fail('Invalid cancel wrote audit.');
                },
            );
            self::fail('Unknown revocation was cancelled.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('cancel_not_safe', $exception->reason);
        }
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target, (string) $intent->id);
            self::fail('Unknown revoke was replayed.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('revocation_uncertain', $exception->reason);
        }
        self::assertSame(['alpha-refresh'], $this->revocationTokenAttempts);
    }

    public function test_concurrent_disconnect_is_rejected_before_duplicate_remote_request(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->tryConcurrentRevoke = true;
        app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
        self::assertTrue($this->concurrentRevokeBlocked);
        self::assertSame(['alpha-refresh', 'alpha-access'], $this->revocationTokenAttempts);
        self::assertSame(0, DB::table('wp_ai_bridge_revocation_intents')->count());
    }

    public function test_owner_cancel_requires_authenticated_catalog_and_audits_only_verified_success(): void
    {
        $target = $this->target('alpha');
        $owner = $this->user('owner', 'all');
        $this->pair($target);
        $this->revokeFailureMode = 'pre_dispatch';
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
            self::fail('Expected refusal before remote dispatch.');
        } catch (WpAiBridgeTargetConnectionException) {
        }
        $id = (string) DB::table('wp_ai_bridge_revocation_intents')->value('id');
        $this->revokeFailureMode = null;
        $this->allowProtectedCatalogProbe = true;
        $this->rejectProtectedCatalogProbe = true;
        $payload = [
            'intent_id' => $id,
            'confirm_target_id' => 'alpha',
            'current_password' => 'CorrectHorse!234',
        ];

        $this->actingAs($owner)->post('/admin/targets/alpha/cancel-disconnect', $payload)
            ->assertSessionHasErrors('target')->assertSessionHas('diagnostic_code', 'cancel_verification_failed');
        self::assertSame('retryable', DB::table('wp_ai_bridge_revocation_intents')->value('phase'));
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        self::assertSame(1, DB::table('target_credentials')->count());

        $this->rejectProtectedCatalogProbe = false;
        $this->post('/admin/targets/alpha/cancel-disconnect', $payload)
            ->assertRedirect('/admin/targets/alpha')->assertSessionHas('status');
        self::assertSame(1, $this->catalogProbeCalls);
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertNull($target->last_error_code);
        self::assertSame(0, DB::table('wp_ai_bridge_revocation_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        $this->assertDatabaseHas('activity_events', [
            'target_id' => 'alpha', 'operation' => 'wordpress-disconnect-cancel-verified',
            'outcome' => 'success',
        ]);
        self::assertSame(['alpha-refresh'], $this->revocationTokenAttempts);
    }

    public function test_disconnect_recovery_rejects_operator_stale_intent_wrong_target_and_password(): void
    {
        $alpha = $this->target('alpha');
        $beta = $this->target('beta');
        $this->pair($alpha);
        $this->pair($beta);
        $this->revokeFailureMode = 'pre_dispatch';
        foreach ([$alpha, $beta] as $target) {
            try {
                app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
            } catch (WpAiBridgeTargetConnectionException) {
            }
        }
        $alphaId = (string) DB::table('wp_ai_bridge_revocation_intents')
            ->where('target_record_id', $alpha->getKey())->value('id');
        $payload = [
            'intent_id' => $alphaId,
            'confirm_target_id' => 'alpha',
            'current_password' => 'CorrectHorse!234',
        ];

        $this->actingAs($this->user('operator', 'all'))
            ->post('/admin/targets/alpha/cancel-disconnect', $payload)->assertForbidden();
        $this->post('/admin/targets/alpha/reconcile-disconnect', [
            ...$payload, 'wordpress_client_revoked' => 'yes', 'other_clients_affected' => 'yes',
        ])->assertForbidden();
        $this->actingAs($this->user('owner', 'all'))
            ->post('/admin/targets/alpha/cancel-disconnect',
                [...$payload, 'current_password' => 'incorrect'])->assertSessionHasErrors('current_password');
        $this->post('/admin/targets/alpha/cancel-disconnect',
            [...$payload, 'confirm_target_id' => 'beta'])->assertSessionHasErrors('confirm_target_id');
        $this->post('/admin/targets/alpha/cancel-disconnect',
            [...$payload, 'intent_id' => (string) Str::ulid()])->assertSessionHasErrors('target');
        $this->post('/admin/targets/beta/finish-disconnect', ['intent_id' => $alphaId])
            ->assertSessionHasErrors('target');
        self::assertSame(2, DB::table('wp_ai_bridge_revocation_intents')->count());
        self::assertSame(2, DB::table('target_credentials')->count());
        self::assertSame(['alpha-refresh', 'beta-refresh'], $this->revocationTokenAttempts);
    }

    public function test_pre_upgrade_disconnect_intent_does_not_inherit_replay_authorization(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $id = (string) Str::ulid();
        DB::table('wp_ai_bridge_revocation_intents')->insert([
            'id' => $id, 'target_record_id' => $target->getKey(),
            'kind' => 'disconnect', 'created_at' => now()->subHour(), 'updated_at' => now()->subHour(),
        ]);
        self::assertSame('legacy_unknown', DB::table('wp_ai_bridge_revocation_intents')->value('phase'));
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target, $id);
            self::fail('Legacy intent was replayed.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('revocation_conflict', $exception->reason);
        }
        $this->actingAs($this->user('owner', 'all'))->get('/admin/targets/alpha')
            ->assertSee('WordPress-side recovery for uncertain revocation')
            ->assertDontSee('Cancel pending disconnect');
        self::assertSame([], $this->revocationTokenAttempts);
    }

    public function test_attestation_waits_for_inflight_settlement_and_rolls_back_on_audit_failure(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        $this->failRevocation = true;
        try {
            app(WpAiBridgeTargetConnectionService::class)->disconnect($target);
        } catch (WpAiBridgeTargetConnectionException) {
        }
        $id = (string) DB::table('wp_ai_bridge_revocation_intents')->value('id');
        $payload = [
            'intent_id' => $id,
            'confirm_target_id' => 'alpha',
            'wordpress_client_revoked' => 'yes',
            'other_clients_affected' => 'yes',
            'current_password' => 'CorrectHorse!234',
        ];
        $this->actingAs($this->user('owner', 'all'))
            ->post('/admin/targets/alpha/reconcile-disconnect', $payload)
            ->assertSessionHasErrors('target')->assertSessionHas('diagnostic_code', 'refresh_settling');
        self::assertSame(1, DB::table('target_credentials')->count());

        DB::table('wp_ai_bridge_revocation_intents')->where('id', $id)
            ->update(['updated_at' => now()->subMinutes(3)]);
        try {
            app(WpAiBridgeTargetConnectionService::class)->reconcileRevokedDisconnect(
                $target, $id, static function (): void {
                    throw new \RuntimeException('Audit storage unavailable');
                },
            );
            self::fail('Failed audit committed local delete.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Audit storage unavailable', $exception->getMessage());
        }
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame(1, DB::table('wp_ai_bridge_revocation_intents')->count());
        $this->post('/admin/targets/alpha/reconcile-disconnect', $payload)
            ->assertRedirect('/admin/targets/alpha')->assertSessionHas('status');
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'wordpress-disconnect-remote-revocation-attested',
            'outcome' => 'operator-attested',
        ]);
        self::assertSame(0, DB::table('target_credentials')->count());
        self::assertSame(TargetConnectionState::Disconnected, $target->refresh()->connection_state);
    }

    public function test_disconnect_replay_fence_migration_prevents_downgrade_with_unresolved_intents(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::table('wp_ai_bridge_revocation_intents')->insert([
            'id' => (string) Str::ulid(), 'target_record_id' => $target->getKey(),
            'kind' => 'disconnect', 'created_at' => now(), 'updated_at' => now(),
        ]);
        $migration = require database_path('migrations/2026_10_13_000000_fence_wordpress_disconnect_recovery.php');
        try {
            $migration->down();
            self::fail('Unsafe schema downgrade passed an unresolved intent.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('Cannot roll back', $exception->getMessage());
        }
        self::assertTrue(Schema::hasColumn('wp_ai_bridge_revocation_intents', 'phase'));
    }

    public function test_db_audit_failure_after_all_remote_acks_preserves_confirmed_intent_without_revoke_replay(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::unprepared('CREATE TRIGGER fail_confirmed BEFORE INSERT ON activity_events '.
            "WHEN NEW.operation = 'wordpress-disconnect-confirmed' ".
            "BEGIN SELECT RAISE(ABORT, 'test required audit unavailable'); END");
        $this->actingAs($this->user('owner', 'all'))
            ->post('/admin/targets/alpha/disconnect')
            ->assertRedirect('/admin/targets/alpha')
            ->assertSessionHas('diagnostic_code', 'operation_unconfirmed');
        $intent = DB::table('wp_ai_bridge_revocation_intents')->first();
        self::assertSame('confirmed', $intent->phase);
        self::assertSame(2, (int) $intent->token_confirmed);
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame(['alpha-refresh', 'alpha-access'], $this->revocationTokenAttempts);
        $this->get('/admin/targets/alpha')
            ->assertOk()->assertSee('Finish confirmed disconnect');
        DB::unprepared('DROP TRIGGER fail_confirmed');
        $this->post('/admin/targets/alpha/finish-disconnect', ['intent_id' => $intent->id])
            ->assertRedirect('/admin/targets/alpha')->assertSessionHas('status');
        self::assertSame(['alpha-refresh', 'alpha-access'], $this->revocationTokenAttempts);
        self::assertSame(0, DB::table('target_credentials')->count());
        self::assertSame(TargetConnectionState::Disconnected, $target->refresh()->connection_state);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'wordpress-disconnect-confirmed', 'outcome' => 'success',
        ]);
    }

    public function test_failed_required_intent_audit_never_dispatches_remote_revocation(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::unprepared('CREATE TRIGGER fail_intent BEFORE INSERT ON activity_events '.
            "WHEN NEW.operation = 'wordpress-disconnect-intent' ".
            "BEGIN SELECT RAISE(ABORT, 'test intent audit unavailable'); END");
        $this->actingAs($this->user('owner', 'all'))
            ->post('/admin/targets/alpha/disconnect')
            ->assertRedirect('/admin/targets/alpha')
            ->assertSessionHas('diagnostic_code', 'operation_unconfirmed');
        self::assertSame(0, DB::table('wp_ai_bridge_revocation_intents')->count());
        self::assertSame(1, DB::table('target_credentials')->count());
        self::assertSame(TargetConnectionState::Connected, $target->refresh()->connection_state);
        self::assertSame([], $this->revocationTokenAttempts);
        DB::unprepared('DROP TRIGGER fail_intent');
    }

    private function expire(Target $target): void
    {
        $vault = app(WpAiBridgeTargetVault::class);
        $credential = $this->credential($target);
        $secret = $vault->openCredential($target, $credential);
        $credential->forceFill(['encrypted_payload' => $vault->sealCredential(
            $target, $secret['client_id'], $secret['resource_url'],
            $secret['access_token'], $secret['refresh_token'],
            now()->subMinute(), $secret['scopes'],
        )])->save();
    }

    private function pair(Target $target): string
    {
        $service = app(WpAiBridgeTargetConnectionService::class);
        $url = $service->begin($target);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);
        $service->completeCallback($args['state'], $target->target_id.'-code',
            'https://'.$target->target_id.'.example.test', null);

        return $service->accessToken($target);
    }

    private function target(string $name): Target
    {
        return app(WpAiBridgeTargetRegistration::class)
            ->register($name, 'WP '.$name, 'https://'.$name.'.example.test');
    }

    private function credential(Target $target): TargetCredential
    {
        return TargetCredential::query()->where('target_record_id', $target->getKey())->firstOrFail();
    }

    private function user(string $role, string $scope): User
    {
        return User::query()->create([
            'name' => 'Operator '.$role,
            'email' => Str::random(10).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => $scope,
            'access_enabled' => true,
        ]);
    }

    private function bridgeResponse(Request $request): PromiseInterface
    {
        $this->outboundTransactionLevels[] = DB::transactionLevel();
        $url = $request->url();
        $host = (string) parse_url($url, PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($url, PHP_URL_PATH);

        if ($path === '/.well-known/oauth-protected-resource') {
            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
            ], 200);
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
            ], 200);
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/token') {
            if (($request->data()['grant_type'] ?? null) === 'refresh_token') {
                $this->refreshCalls++;
                if ($this->refreshTransportFailure !== null) {
                    return match ($this->refreshTransportFailure) {
                        'connect' => Http::failedConnection('Connection refused')($request),
                        'tls' => Http::failedConnection('SSL certificate problem')($request),
                        'connect_timeout' => Create::rejectionFor(new GuzzleConnectTimeoutException(
                            'Connection timed out before TLS handshake.',
                            $request->toPsrRequest(),
                        )),
                        'network_timeout' => Create::rejectionFor(new GuzzleNetworkTimeoutException(
                            'Timed out after transmitting refresh request bytes.',
                            $request->toPsrRequest(),
                        )),
                        default => self::fail('Unexpected transport fixture failure mode.'),
                    };
                }
                $this->refreshHandledByBridge++;
                if ($this->failClientAuthentication) {
                    // Real Bridge emits this before accessing any refresh
                    // source on temporary client-metadata or JWKS HTTP 503.
                    return Http::response(['error' => 'invalid_client'], 400);
                }
                if ($this->temporarilyUnavailable400Once) {
                    $this->temporarilyUnavailable400Once = false;

                    return Http::response(['error' => 'temporarily_unavailable'], 400);
                }
                if ($this->failRefresh) {
                    return Http::response(['error' => 'temporarily_unavailable'], 503);
                }
                if ($this->failRefreshOnce) {
                    $this->failRefreshOnce = false;

                    return Http::response(['error' => 'temporarily_unavailable'], 503);
                }
                if ($this->rejectRefresh) {
                    return Http::response(['error' => 'invalid_grant'], 400);
                }
                if ($this->malformedRefresh) {
                    return Http::response([
                        'token_type' => 'Bearer',
                        'expires_in' => 3600,
                        'access_token' => explode('.', $host)[0].'-unexpected-access',
                        'refresh_token' => explode('.', $host)[0].'-refresh',
                        'scope' => 'mcp:use offline_access',
                    ], 200);
                }

                return Http::response([
                    'token_type' => 'Bearer',
                    'expires_in' => 3600,
                    'refresh_token_expires_in' => $this->refreshTokenTtl,
                    'access_token' => explode('.', $host)[0].'-rotated-access',
                    'refresh_token' => explode('.', $host)[0].'-rotated-refresh',
                    'scope' => 'mcp:use offline_access',
                ], 200);
            }
            if ($this->attemptConcurrentDisconnect) {
                $this->attemptConcurrentDisconnect = false;
                try {
                    app(WpAiBridgeTargetConnectionService::class)
                        ->disconnect(Target::query()->where('target_id', 'alpha')->firstOrFail());
                    self::fail('Disconnect bypassed the consumed OAuth callback fence.');
                } catch (WpAiBridgeTargetConnectionException $exception) {
                    self::assertSame('callback_pending', $exception->reason);
                    $this->sawCallbackFence = true;
                }
            }
            if ($this->failTokenExchange) {
                return Http::response(['error' => 'invalid_grant'], 400);
            }

            return Http::response([
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token_expires_in' => $this->refreshTokenTtl,
                'access_token' => explode('.', $host)[0].'-access',
                'refresh_token' => explode('.', $host)[0].'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/revoke') {
            $this->revocationTokenAttempts[] = (string) ($request->data()['token'] ?? '');
            if ($this->tryConcurrentRevoke) {
                $this->tryConcurrentRevoke = false;
                $target = Target::query()->where('target_id', explode('.', $host)[0])->firstOrFail();
                $intentId = (string) DB::table('wp_ai_bridge_revocation_intents')
                    ->where('target_record_id', $target->getKey())->value('id');
                try {
                    app(WpAiBridgeTargetConnectionService::class)->disconnect($target, $intentId);
                    self::fail('Concurrent remote revoke dispatch was permitted.');
                } catch (WpAiBridgeTargetConnectionException $exception) {
                    $this->concurrentRevokeBlocked = $exception->reason === 'revocation_uncertain';
                }
            }
            if ($this->revokeFailureMode === 'pre_dispatch'
                || ($this->revokeFailureMode === 'second_pre_dispatch' && count($this->revocationTokenAttempts) === 2)) {
                return Http::failedConnection('cURL error 7: connection refused')($request);
            }
            if ($this->revokeFailureMode === 'response_lost') {
                return Create::rejectionFor(new GuzzleNetworkTimeoutException(
                    'Response timed out after revoke request bytes were sent.',
                    $request->toPsrRequest(),
                ));
            }

            return $this->failRevocation ? Http::response(['error' => 'invalid_client'], 400) : Http::response('', 200);
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/mcp' && $this->allowProtectedCatalogProbe) {
            if ($request->method() === 'DELETE') {
                return Http::response('', 200);
            }
            $rpc = $request->data();
            if ($this->rejectProtectedCatalogProbe) {
                return Http::response(['error' => 'invalid_token'], 401);
            }
            if (($rpc['method'] ?? null) === 'initialize') {
                return Http::response([
                    'jsonrpc' => '2.0', 'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25', 'capabilities' => []],
                ], 200, ['Mcp-Session-Id' => 'verified-test-session']);
            }
            if (($rpc['method'] ?? null) === 'tools/call'
                && ($rpc['params']['arguments']['ability_name'] ?? null) === 'wp-ai-bridge/abilities-read'
                && $request->hasHeader('Authorization', 'Bearer '.explode('.', $host)[0].'-access')) {
                $this->catalogProbeCalls++;

                return Http::response([
                    'jsonrpc' => '2.0', 'id' => 2,
                    'result' => ['structuredContent' => ['success' => true,
                        'data' => ['items' => [['name' => 'wp-ai-bridge/test']]]]],
                ], 200);
            }

            return Http::response(['error' => 'unrecognized_rpc'], 400);
        }

        return Http::response(['error' => 'missing'], 404);
    }
}
