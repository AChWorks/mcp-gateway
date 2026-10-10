<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetVault;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

final class WpAiBridgeTargetConnectionTest extends TestCase
{
    use RefreshDatabase;

    private bool $failRevocation = false;

    private bool $failTokenExchange = false;

    private bool $failRefresh = false;

    private bool $rejectRefresh = false;

    private bool $malformedRefresh = false;

    private int $refreshCalls = 0;

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
            public function resolve(string $host): array
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

    public function test_disconnect_requires_confirmed_remote_revocation_and_supports_safe_retry(): void
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
        $service->disconnect($alpha);
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
        $response->assertRedirect();
        $url = (string) $response->headers->get('Location');
        parse_str((string) parse_url($url, PHP_URL_QUERY), $args);
        self::assertArrayHasKey('state', $args);

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

    public function test_ambiguous_idle_maintenance_does_not_unboundedly_replay_credentials(): void
    {
        $target = $this->target('alpha');
        $this->pair($target);
        DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $this->credential($target)->getKey())
            ->update(['refresh_due_at' => now()->subMinute()]);
        $this->failRefresh = true;

        self::assertSame(1, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(1, $this->refreshCalls);
        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(TargetConnectionState::Error, $target->refresh()->connection_state);
        // Even after a remote timeout, the scheduler never tries the old
        // rotating refresh token a second time without an explicit action.
        DB::table('wp_ai_bridge_refresh_intents')->update(['created_at' => now()->subSeconds(20)]);
        self::assertSame(0, Artisan::call('gateway:wordpress-credentials-maintain'));
        self::assertSame(1, $this->refreshCalls);
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
                if ($this->failRefresh) {
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
                    'refresh_token_expires_in' => 7200,
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
                'refresh_token_expires_in' => 7200,
                'access_token' => explode('.', $host)[0].'-access',
                'refresh_token' => explode('.', $host)[0].'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/revoke') {
            return $this->failRevocation ? Http::response(['error' => 'invalid_client'], 400) : Http::response('', 200);
        }

        return Http::response(['error' => 'missing'], 404);
    }
}
