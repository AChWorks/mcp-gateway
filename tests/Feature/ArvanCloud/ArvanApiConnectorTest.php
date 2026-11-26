<?php

namespace Tests\Feature\ArvanCloud;

use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Targets\ArvanApiOperations;
use App\Application\Targets\ConnectionRelayAdministration;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetTransportBinding;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetAdapter;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetConfig;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetVault;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ArvanApiConnectorTest extends TestCase
{
    use RefreshDatabase;

    private const KEY = 'example-valid-machine-key-never-expose';

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
    }

    public function test_missing_optional_arvan_catalog_spec_retains_actionable_diagnostics_without_outbound_request(): void
    {
        [$target, $owner] = $this->fixture();
        ArvanApiTargetConfig::query()->sole()->forceFill(['spec_url' => null])->save();

        $result = app(ArvanApiOperations::class)->catalog($owner, $target->target_id);
        self::assertFalse($result['ok']);
        self::assertSame('catalog_unavailable', $result['error']['code']);
        self::assertStringContainsString('optional OpenAPI description URL', $result['error']['next_step']);
        $event = DB::table('activity_events')->where('operation', 'arvan-api-catalog')->sole();
        $details = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('openapi_spec_url_missing', $details['source_error_code']);
        self::assertSame('Target has no configured OpenAPI description URL.', $details['source_error_message']);
        self::assertSame('admission', $details['failure_stage']);
        self::assertTrue($details['request_not_sent']);
        Http::assertNothingSent();
    }

    public function test_registered_target_key_is_bound_encrypted_and_admin_never_replays_the_secret(): void
    {
        $administrator = $this->user('administrator');
        $administrator->forceFill(['self_created_target_access' => true])->save();
        $payload = [
            'target_id' => 'arvan-cdn',
            'display_name' => 'Arvan CDN',
            'connector_type' => 'arvancloud',
            'api_base_url' => 'https://api.example.test/cdn/4.0',
            'api_spec_url' => 'https://spec.example.test/cdn.yaml',
            'api_probe_path' => '/domains',
            'api_key' => self::KEY,
            'current_password' => 'CorrectHorse!234',
        ];
        $this->actingAs($this->user('operator'))
            ->post('/admin/targets', $payload)->assertForbidden();
        self::assertSame(0, Target::query()->count());
        $this->actingAs($administrator);
        $this->post('/admin/targets', [...$payload, 'connection_relay_id' => 'missing-relay'])->assertSessionHasErrors('connection_relay_id');
        self::assertSame(0, Target::query()->count());
        $this->post('/admin/targets', $payload)->assertAdminRedirect('/admin/targets/arvan-cdn');

        $target = Target::query()->sole();
        $config = ArvanApiTargetConfig::query()->sole();
        $credential = TargetCredential::query()->sole();
        self::assertSame('arvancloud', $target->connector_type);
        self::assertSame($administrator->id, $target->created_by_user_id);
        self::assertSame('https://api.example.test/cdn/4.0', $config->base_url);
        self::assertSame(self::KEY, app(ArvanApiTargetVault::class)->open($target, $config, $credential));
        self::assertStringNotContainsString(self::KEY, $credential->encrypted_payload);
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('ArvanCloud API root')->assertDontSee(self::KEY);
        $editByRecoveryLink = $this->get('/admin/targets/arvan-cdn/edit?section=api-connection')->assertOk();
        self::assertMatchesRegularExpression(
            '/<details[^>]+id="target-connection-settings"[^>]*\\bopen\\b/',
            (string) $editByRecoveryLink->getContent(),
        );
        $this->get('/admin/targets/arvan-cdn/edit')->assertOk()
            ->assertSee('Advanced connector connection settings')->assertDontSee(self::KEY);
        Http::assertNothingSent();

        $keyFlashed = 'should-never-be-flashed';
        $this->from('/admin/targets/create?connector_type=arvancloud')->post('/admin/targets', [
            ...$payload, 'target_id' => 'INVALID SPACE', 'api_key' => $keyFlashed,
        ])->assertSessionHasErrors('target_id');
        self::assertNotContains($keyFlashed, (array) session()->getOldInput());
    }

    public function test_arvan_target_details_offer_readonly_connection_test_and_truthful_local_disconnect(): void
    {
        [$target, $owner] = $this->fixture();
        $this->actingAs($owner);
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Verify API key (read-only GET)')
            ->assertSee('Check HTTPS endpoint (no API key)')
            ->assertSee('Target details and diagnostic history')
            ->assertDontSee('Registered SSH/connector details and diagnostic history')
            ->assertSee('Remove stored API key (advanced)')
            ->assertSee('Delete Gateway API key')
            ->assertSee('revoke that key separately')
            ->assertDontSee('This connector is not yet available for enrollment.')
            ->assertDontSee(self::KEY);

        $target->forceFill(['operations_paused' => true])->save();
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Check HTTPS endpoint (no API key)')
            ->assertSee('Verify API key (read-only GET)')
            ->assertSee('Both actions are disabled while paused.')
            ->assertSee('type="submit" disabled', false);
        $target->forceFill(['operations_paused' => false])->save();

        ArvanApiTargetConfig::query()->sole()->forceFill(['probe_path' => null])->save();
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Check HTTPS endpoint (no API key)')
            ->assertDontSee('Verify API key (read-only GET)')
            ->assertSee('authenticated GET probe is optional and not configured')
            ->assertSee('Set a GET probe in advanced connection settings');
        TargetCredential::query()->delete();
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('No Machine User key is stored')
            ->assertSee('Machine User key presence is shown below')
            ->assertDontSee('Bound encrypted Machine User API key')
            ->assertSee('Check HTTPS endpoint (no API key)')
            ->assertDontSee('Verify API key (read-only GET)')
            ->assertSee('Open advanced connection settings to add a key')
            ->assertDontSee('Delete Gateway API key');
        Http::assertNothingSent();
    }

    public function test_arvan_recovery_respects_effective_configuration_permission_without_removing_admin_test_or_disconnect(): void
    {
        [$target, $owner] = $this->fixture();
        $administrator = $this->user('administrator');
        DB::table('user_target_access')->insert([
            'user_id' => $administrator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);

        // Configuration is an independent, scoped, deniable permission.
        $this->actingAs($administrator)
            ->get('/admin/targets/arvan-cdn/edit?section=api-connection')->assertOk()
            ->assertSee('id="target-connection-settings"', false);
        DB::table('user_permission_denials')->insert(['user_id' => $administrator->id, 'permission' => 'targets.configure']);
        $this->actingAs($administrator)
            ->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Verify API key (read-only GET)')
            ->assertSee('Check HTTPS endpoint (no API key)')
            ->assertSee('Delete Gateway API key')
            ->assertSee('An authorized Target configuration editor must add a new key before this Target can be used again.')
            ->assertDontSee('To use this Target again, enter a new key in its connection settings.');
        $this->get('/admin/targets/arvan-cdn/edit?section=api-connection')->assertOk()
            ->assertDontSee('id="target-connection-settings"', false);

        // Removing a probe is a scoped configuration task. The restricted Admin must
        // see a next step, but not a link to a form they cannot access.
        $config = ArvanApiTargetConfig::query()->sole();
        $config->forceFill(['probe_path' => null])->save();
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Ask an authorized Target configuration editor to configure a read-only GET probe for this Target.')
            ->assertSee('Delete Gateway API key')
            ->assertDontSee('Set a GET probe in advanced connection settings')
            ->assertDontSee('section=api-connection')
            ->assertSee('Check HTTPS endpoint (no API key)')
            ->assertDontSee('Verify API key (read-only GET)');

        $this->actingAs($owner)
            ->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Set a GET probe in advanced connection settings')
            ->assertSee('To use this Target again, enter a new key in its connection settings.')
            ->assertDontSee('Ask an authorized Target configuration editor to configure a read-only GET probe');
        $this->get('/admin/targets/arvan-cdn/edit?section=api-connection')->assertOk()
            ->assertSee('id="target-connection-settings"', false)
            ->assertSee('Advanced connector connection settings');

        // After deletion, the same authority distinction applies to the
        // missing credential rather than advertising a dead recovery route.
        $this->actingAs($administrator)
            ->post(route('admin.targets.disconnect', ['target' => $target->target_id]))
            ->assertAdminRedirect('/admin/targets/arvan-cdn');
        self::assertSame(0, TargetCredential::query()->count());
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Ask an authorized Target configuration editor to add a Machine User API key')
            ->assertDontSee('Open advanced connection settings to add a key')
            ->assertDontSee('section=api-connection');
        $this->actingAs($owner)
            ->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('Open advanced connection settings to add a key')
            ->assertDontSee('Ask an authorized Target configuration editor to add a Machine User API key');
        Http::assertNothingSent();
    }

    public function test_optional_probe_keeps_a_real_readonly_https_check_without_key_or_state_mutation(): void
    {
        [$target, $owner] = $this->fixture();
        ArvanApiTargetConfig::query()->sole()->forceFill(['probe_path' => null])->save();
        Http::fake(static fn (Request $request) => Http::response('', 405));

        // The submitted URL, method and key are ignored: only the registered
        // Target origin can be contacted, once, with an unauthenticated HEAD.
        $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
            'api_base_url' => 'https://unregistered.example.test/private',
            'method' => 'DELETE',
            'path' => '/dangerous-action',
            'api_key' => 'SYNTHETIC-CALLER-INJECTION-NEVER-USED',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')
            ->assertSessionHas('status', static fn (string $message): bool => str_contains($message, 'HTTP 405')
                && str_contains($message, 'API key was NOT tested')
                && str_contains($message, 'NOT changed'));
        Http::assertSentCount(1);
        Http::assertSent(static fn (Request $request): bool => $request->method() === 'HEAD'
            && $request->url() === 'https://api.example.test/cdn/4.0/'
            && ! $request->hasHeader('Authorization')
            && ! str_contains($request->url(), 'unregistered.example.test'));
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertNull($target->fresh()->last_tested_at);
        self::assertSame(1, TargetCredential::query()->count());

        // Direct/stale clients cannot silently turn a no-probe test into
        // authenticated success or dispatch a guessed GET path.
        $this->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'authenticated',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')->assertSessionHasErrors('target');
        Http::assertSentCount(1);

        // Endpoint reachability is independently useful after local key
        // removal; it never consumes or recreates credential material.
        TargetCredential::query()->delete();
        $this->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')->assertSessionHas('status');
        Http::assertSentCount(2);
        self::assertSame(0, TargetCredential::query()->count());
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
    }

    public function test_redirecting_api_root_is_reachable_without_following_redirect_or_changing_authentication(): void
    {
        [$target, $owner] = $this->fixture();
        // A server may return a 3xx (even to itself) for its registered
        // HTTPS root. That is a real peer response, not proof of usable API
        // routing, valid credentials or permission to follow Location.
        ArvanApiTargetConfig::query()->sole()->forceFill(['probe_path' => null])->save();
        Http::fake(static fn (Request $request) => Http::response('untrusted redirect body', 302, [
            'Location' => 'https://other.example.test/private?token=MUST_NOT_LEAK',
        ]));

        $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
            'method' => 'DELETE',
            'api_key' => 'INJECTED_KEY_MUST_NOT_BE_USED',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')
            ->assertSessionHas('status', static fn (string $message): bool => str_contains($message, 'HTTP 302')
                && str_contains($message, 'redirect was NOT followed')
                && str_contains($message, 'No API key was sent')
                && str_contains($message, 'NOT changed')
                && ! str_contains($message, 'other.example.test')
                && ! str_contains($message, 'MUST_NOT_LEAK'));

        Http::assertSentCount(1);
        Http::assertSent(static fn (Request $request): bool => $request->method() === 'HEAD'
            && $request->url() === 'https://api.example.test/cdn/4.0/'
            && ! $request->hasHeader('Authorization'));
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertNull($target->fresh()->last_tested_at);
        self::assertSame(1, TargetCredential::query()->count());
    }

    public function test_authenticated_get_still_rejects_redirect_and_never_verifies_key(): void
    {
        [$target, $owner] = $this->fixture();
        Http::fake(static fn (Request $request) => Http::response('', 307, [
            'Location' => 'https://other.example.test/credential-replay',
        ]));

        $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'authenticated',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')
            ->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'unsafe_redirect')
            ->assertSessionHas('diagnostic_context', static fn (array $context): bool => ($context['remote_http_status'] ?? null) === 307);

        Http::assertSentCount(1);
        Http::assertSent(static fn (Request $request): bool => $request->method() === 'GET'
            && $request->url() === 'https://api.example.test/cdn/4.0/domains'
            && $request->hasHeader('Authorization', 'Apikey '.self::KEY));
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertNull($target->fresh()->last_tested_at);
    }

    public function test_redirect_reachability_result_is_stale_after_concurrent_target_pause(): void
    {
        [$target, $owner] = $this->fixture();
        Http::fake(function (Request $request) use ($target) {
            $target->forceFill(['operations_paused' => true])->save();

            return Http::response('', 308, ['Location' => '/']);
        });

        $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')
            ->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'endpoint_check_stale');
        Http::assertSentCount(1);
        self::assertTrue((bool) $target->fresh()->operations_paused);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
    }

    public function test_root_rotation_and_successful_regular_api_get_do_not_falsely_prove_key_without_optional_probe(): void
    {
        [$target, $owner] = $this->fixture();
        $adapter = app(ArvanApiTargetAdapter::class);
        $adapter->updateConfiguration($target, [
            'configuration_revision' => $adapter->configurationRevision($target),
            'api_base_url' => 'https://second.example.test/cdn/4.0',
            'api_spec_url' => '',
            'api_probe_path' => '',
            'api_key' => 'rotated-synthetic-machine-user-key',
        ]);

        self::assertNull(ArvanApiTargetConfig::query()->sole()->probe_path);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        Http::fake(static fn (Request $request) => Http::response(['items' => ['ok']], 200));

        // An explicitly requested real API GET can succeed with the rotated
        // Machine User key, while Target verification remains distinct.
        $result = app(ArvanApiOperations::class)->execute($owner, $target->target_id, 'GET', '/domains');
        self::assertTrue($result['ok']);
        Http::assertSent(static fn (Request $request): bool => $request->method() === 'GET'
            && $request->url() === 'https://second.example.test/cdn/4.0/domains'
            && $request->hasHeader('Authorization', 'Apikey rotated-synthetic-machine-user-key'));
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));

        $this->actingAs($owner)->get('/admin/targets/arvan-cdn')
            ->assertOk()->assertSee('Check HTTPS endpoint (no API key)')
            ->assertDontSee('Verify API key (read-only GET)')
            ->assertSee('API requests may still succeed');
        $this->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')->assertSessionHas('status');
        Http::assertSentCount(2);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
    }

    public function test_authenticated_verification_uses_only_saved_get_path_and_failure_does_not_claim_success(): void
    {
        [$target, $owner] = $this->fixture();
        $authenticatedChecks = 0;
        Http::fake(static function (Request $request) use (&$authenticatedChecks) {
            if ($request->method() === 'HEAD') {
                return Http::response('', 404);
            }

            $authenticatedChecks++;

            return $authenticatedChecks === 1
                ? Http::response(['ok' => true], 200)
                : Http::response(['error' => 'forbidden'], 403);
        });
        $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'authenticated',
            'api_probe_path' => '/delete-everything',
            'method' => 'POST',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')
            ->assertSessionHas('status', static fn (string $message): bool => str_contains($message, 'Authenticated ArvanCloud GET probe succeeded.'));
        Http::assertSentCount(1);
        Http::assertSent(static fn (Request $request): bool => $request->method() === 'GET'
            && $request->url() === 'https://api.example.test/cdn/4.0/domains'
            && $request->hasHeader('Authorization', 'Apikey '.self::KEY));
        self::assertSame('connected', $target->fresh()->getRawOriginal('connection_state'));
        $verifiedAt = (string) $target->fresh()->last_tested_at;

        $this->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')->assertSessionHas('status');
        Http::assertSentCount(2);
        self::assertSame('connected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertSame($verifiedAt, (string) $target->fresh()->last_tested_at);

        // A failing authenticated GET must show the distinct provider
        // failure and never forge a new verification timestamp.
        $this->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'authenticated',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'upstream_http_error');
        self::assertSame($verifiedAt, (string) $target->fresh()->last_tested_at);
    }

    public function test_endpoint_reachability_obeys_pause_permission_mode_validation_and_revision_fences(): void
    {
        [$target, $owner] = $this->fixture();
        Http::fake(static fn (Request $request) => Http::response('', 200));
        $viewer = $this->user('viewer');
        $this->actingAs($viewer)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertForbidden();
        Http::assertNothingSent();

        $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'DELETE',
        ])->assertSessionHasErrors('arvan_check');
        Http::assertNothingSent();

        $target->forceFill(['operations_paused' => true])->save();
        $this->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')->assertSessionHasErrors('target');
        Http::assertNothingSent();

        $target->forceFill(['operations_paused' => false])->save();
        $adapter = app(ArvanApiTargetAdapter::class);
        $revision = $adapter->configurationRevision($target);
        Http::fake(function (Request $request) use ($target, $adapter, $revision) {
            $adapter->updateConfiguration($target, [
                'configuration_revision' => $revision,
                'api_base_url' => 'https://second.example.test/cdn/4.0',
                'api_spec_url' => '',
                'api_probe_path' => '',
                'api_key' => 'another-synthetic-rotated-key',
            ]);

            return Http::response('', 200);
        });
        $this->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'endpoint_check_stale');
        Http::assertSentCount(1);
        self::assertSame('https://second.example.test/cdn/4.0', ArvanApiTargetConfig::query()->sole()->base_url);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
    }

    public function test_endpoint_transport_failure_has_specific_diagnostics_and_never_leaks_exception_or_key(): void
    {
        [$target, $owner] = $this->fixture();
        $sentMethod = null;
        $hasAuthorization = null;
        Http::fake(static function (Request $request) use (&$sentMethod, &$hasAuthorization): never {
            $sentMethod = $request->method();
            $hasAuthorization = $request->hasHeader('Authorization');
            throw new ConnectionException('cURL error 60: certificate rejected; SENSITIVE_FAKE_DIAGNOSTIC_VALUE');
        });

        $response = $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ]);
        $response->assertAdminRedirect('/admin/targets/arvan-cdn')
            ->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'tls_failure')
            ->assertSessionHas('diagnostic_reference');
        self::assertSame('HEAD', $sentMethod);
        self::assertFalse($hasAuthorization);
        // Laravel does not record a fake request when its response callback
        // throws before the HTTP client receives a response.
        Http::assertNothingSent();

        // Native Admin feedback is bound to the redirect's one-use nonce,
        // not visible on an unrelated GET without that token.
        $this->get((string) $response->headers->get('Location'))->assertOk()
            ->assertSee('HTTPS HEAD check')
            ->assertSee('tls_failure')
            ->assertSee('Check DNS, TLS')
            ->assertDontSee('SENSITIVE_FAKE_DIAGNOSTIC_VALUE')
            ->assertDontSee(self::KEY);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
    }

    public function test_pause_during_no_key_head_check_invalidates_the_observation(): void
    {
        [$target, $owner] = $this->fixture();
        Http::fake(function (Request $request) use ($target) {
            $target->forceFill(['operations_paused' => true])->save();

            return Http::response('', 200);
        });

        $this->actingAs($owner)->post(route('admin.targets.test', ['target' => $target->target_id]), [
            'arvan_check' => 'endpoint',
        ])->assertAdminRedirect('/admin/targets/arvan-cdn')
            ->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'endpoint_check_stale');
        Http::assertSentCount(1);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertTrue((bool) $target->fresh()->operations_paused);
    }

    public function test_configuration_revision_ignores_later_probe_and_separate_route_but_fences_key_changes(): void
    {
        [$target] = $this->fixture();
        $adapter = app(ArvanApiTargetAdapter::class);
        $revision = $adapter->configurationRevision($target);
        Http::fake(static fn () => Http::response(['ok' => true], 200));
        $adapter->test($target);
        self::assertSame('connected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertSame($revision, $adapter->configurationRevision($target->fresh()));
        // A local API configuration edit does not use the selected route.
        // The separate route mutation fence is checked at dispatch.
        DB::table('targets')->where('id', $target->getKey())->increment('transport_revision');
        self::assertSame($revision, $adapter->configurationRevision($target->fresh()));
        $payload = [
            'configuration_revision' => $revision,
            'api_base_url' => 'https://api.example.test/cdn/4.0',
            'api_spec_url' => 'https://spec.example.test/openapi.yaml',
            'api_probe_path' => '/domains',
            'api_key' => 'replacement-synthetic-key',
        ];
        $adapter->updateConfiguration($target, $payload);
        self::assertNotSame($revision, $adapter->configurationRevision($target->fresh()));
        try {
            $adapter->updateConfiguration($target, [...$payload, 'api_key' => 'stale-synthetic-key']);
            self::fail('An old form cannot replace a newer credential.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('configuration_revision', $exception->field);
        }
        self::assertSame('replacement-synthetic-key', app(ArvanApiTargetVault::class)->open(
            $target->fresh(), ArvanApiTargetConfig::query()->sole(), TargetCredential::query()->sole(),
        ));
        Http::assertSentCount(1);
    }

    public function test_arvan_configuration_errors_identify_correct_fields_and_probe_changes_clear_old_verification(): void
    {
        [$target] = $this->fixture();
        $adapter = app(ArvanApiTargetAdapter::class);
        $revision = $adapter->configurationRevision($target);
        $base = [
            'configuration_revision' => $revision,
            'api_base_url' => 'https://api.example.test/cdn/4.0',
            'api_spec_url' => 'https://spec.example.test/openapi.yaml',
            'api_probe_path' => '/domains',
            'api_key' => '',
        ];
        foreach ([
            [[...$base, 'api_base_url' => 'https://different.example.test/v10'], 'api_key'],
            [[...$base, 'api_spec_url' => 'https://spec.example.test/openapi.yaml?token=secret'], 'api_spec_url'],
            [[...$base, 'api_probe_path' => '/domains/../bad'], 'api_probe_path'],
            [[...$base, 'api_key' => 'key with whitespace'], 'api_key'],
        ] as [$invalid, $expectedField]) {
            try {
                $adapter->updateConfiguration($target, $invalid);
                self::fail('Invalid Arvan configuration unexpectedly saved: '.$expectedField);
            } catch (TargetConnectorFailure $exception) {
                self::assertSame($expectedField, $exception->field);
                self::assertSame('invalid_input', $exception->reason);
            }
        }
        self::assertSame('/domains', ArvanApiTargetConfig::query()->sole()->probe_path);
        self::assertSame(self::KEY, app(ArvanApiTargetVault::class)->open(
            $target, ArvanApiTargetConfig::query()->sole(), TargetCredential::query()->sole(),
        ));
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $freshRevision = $adapter->configurationRevision($target);
        $adapter->updateConfiguration($target, [
            ...$base, 'configuration_revision' => $freshRevision,
            'api_probe_path' => '/availability-zones',
        ]);
        self::assertSame('/availability-zones', ArvanApiTargetConfig::query()->sole()->probe_path);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertSame(1, TargetCredential::query()->count());
        Http::assertNothingSent();
    }

    public function test_api_target_reuses_shared_relay_for_all_http_formats_without_direct_fallback(): void
    {
        $relay = ConnectionRelay::query()->create([
            'relay_id' => 'fixture-relay',
            'display_name' => 'Fixture Relay',
            'control_host' => '1.1.1.1',
            'control_port' => 22,
            'control_user' => 'fixture',
            'control_host_key' => 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('a', 32)),
            'local_socks_port' => 46081,
        ]);
        DB::table('connection_relays')->where('id', $relay->id)->update(['enabled' => true]);
        $relay->refresh();
        $owner = $this->user('owner');
        $this->actingAs($owner);
        $this->get('/admin/targets/create?connector_type=arvancloud')
            ->assertOk()->assertSee('value="fixture-relay"', false);
        $target = app(ArvanApiTargetAdapter::class)->register([
            'target_id' => 'arvan-relayed',
            'display_name' => 'Relayed API',
            'api_base_url' => 'https://api.example.test/cdn/4.0',
            'api_spec_url' => 'https://spec.example.test/openapi.yaml',
            'api_probe_path' => '/domains',
            'api_key' => self::KEY,
            'connection_relay_id' => 'fixture-relay',
        ], $owner);
        self::assertSame($relay->id, $target->relay_record_id);
        self::assertSame(1, $target->transport_revision);
        $this->get('/admin/targets/arvan-relayed/edit')
            ->assertOk()->assertSee('Network routing')->assertSee('value="fixture-relay" selected', false);

        $proxies = [];
        $disableDuringProbe = false;
        Http::fake(function (Request $request, array $options) use (&$proxies, &$disableDuringProbe, $relay) {
            $proxies[] = $options['proxy'] ?? null;
            self::assertTrue($options['verify']);
            self::assertFalse($options['allow_redirects']);
            if (str_contains($request->url(), 'spec.example.test')) {
                self::assertFalse($request->hasHeader('Authorization'));

                return Http::response(['openapi' => '3.0.0', 'paths' => ['/domains' => ['get' => ['summary' => 'Domains']]]]);
            }
            if ($request->method() === 'HEAD') {
                self::assertFalse($request->hasHeader('Authorization'));
            } else {
                self::assertTrue($request->hasHeader('Authorization', 'Apikey '.self::KEY));
            }
            if ($disableDuringProbe) {
                app(ConnectionRelayAdministration::class)->disable($relay, 1);
            }

            return Http::response(['ok' => true]);
        });
        $adapter = app(ArvanApiTargetAdapter::class);
        $api = app(ArvanApiOperations::class);
        $adapter->checkReachability($target);
        $adapter->test($target);
        self::assertTrue($api->catalog($owner, $target->target_id)['ok']);
        self::assertTrue($api->execute($owner, $target->target_id, 'GET', '/domains')['ok']);
        self::assertTrue($api->execute($owner, $target->target_id, 'PATCH', '/domains', bodyJson: '{"enabled":true}')['ok']);
        self::assertTrue($api->execute($owner, $target->target_id, 'PATCH', '/domains', bodyJson: '{}', contentType: 'application/json-patch+json')['ok']);
        self::assertTrue($api->execute($owner, $target->target_id, 'PUT', '/domains', bodyText: 'hello', contentType: 'text/plain')['ok']);
        self::assertTrue($api->execute($owner, $target->target_id, 'POST', '/domains', formFields: ['value' => 'x'])['ok']);
        self::assertTrue($api->execute($owner, $target->target_id, 'POST', '/domains', formFiles: [[
            'name' => 'file', 'filename' => 'file.txt', 'content_base64' => 'eA==',
        ]])['ok']);
        self::assertSame(array_fill(0, 9, 'socks5://127.0.0.1:46081'), $proxies);

        $bindings = app(TargetTransportBinding::class);
        $target->refresh();
        $ciphertext = TargetCredential::query()->sole()->encrypted_payload;
        self::assertTrue($bindings->change($target, $bindings->revision($target), null));
        $target->refresh();
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        self::assertSame($ciphertext, TargetCredential::query()->sole()->encrypted_payload);
        self::assertTrue($api->execute($owner, $target->target_id, 'GET', '/domains')['ok']);
        self::assertSame('', end($proxies));

        self::assertTrue($bindings->change($target, $bindings->revision($target), 'fixture-relay'));
        $target->refresh();
        $disableDuringProbe = true;
        try {
            $adapter->test($target);
            self::fail('An obsolete probe marked the changed route as Connected.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('probe_stale', $exception->reason);
        }
        self::assertSame(TargetConnectionState::Connected, $target->fresh()->connection_state);
        self::assertNull($target->fresh()->last_error_code);
        $count = count($proxies);
        self::assertFalse($api->catalog($owner, $target->target_id)['ok']);
        self::assertFalse($api->execute($owner, $target->target_id, 'GET', '/domains')['ok']);
        foreach (['checkReachability', 'test'] as $method) {
            try {
                $adapter->{$method}($target->fresh());
                self::fail('A disabled Relay reached the HTTP transport.');
            } catch (TargetConnectorFailure $exception) {
                self::assertSame('network_failure', $exception->reason);
            }
        }
        self::assertCount($count, $proxies);
        self::assertSame($ciphertext, TargetCredential::query()->sole()->encrypted_payload);
    }

    public function test_catalog_discovers_new_schema_and_api_uses_registered_origin_query_and_json_body(): void
    {
        [$target, $owner] = $this->fixture();
        $calls = [];
        Http::fake(function (Request $request) use (&$calls) {
            $calls[] = $request;
            if (str_contains($request->url(), 'spec.example.test')) {
                self::assertFalse($request->hasHeader('Authorization'));

                return Http::response(<<<'YAML'
openapi: 3.0.0
info: { title: CDN, version: 99 }
paths:
  /domains:
    get: { operationId: domains.list, summary: Get domains }
  /future-service/v99/new-path:
    patch:
      operationId: future.update
      summary: Update new resource
YAML, 200);
            }
            if ($request->method() === 'PATCH') {
                return Http::response(['updated' => true, 'provider_id' => 77], 200, ['X-Request-ID' => 'arvan-123']);
            }

            return Http::response(['items' => ['one', 'two']], 200);
        });

        $api = app(ArvanApiOperations::class);
        $catalog = $api->catalog($owner, $target->target_id, limit: 5);
        self::assertTrue($catalog['ok'], json_encode($catalog));
        self::assertSame(2, $catalog['total']);
        self::assertSame('PATCH', $catalog['operations'][1]['method']);

        $list = $api->execute($owner, $target->target_id, 'GET', '/domains', ['page' => 2]);
        self::assertTrue($list['ok'], json_encode($list));
        self::assertSame(['one', 'two'], $list['data']['items']);
        self::assertSame('https://api.example.test/cdn/4.0/domains?page=2', $calls[1]->url());
        self::assertTrue($calls[1]->hasHeader('Authorization', 'Apikey '.self::KEY));

        $updated = $api->execute($owner, $target->target_id,
            'PATCH', '/future-service/v99/new-path', [], '{"enabled":true}');
        self::assertTrue($updated['ok'], json_encode($updated));
        self::assertSame('arvan-123', $updated['upstream_request_id']);
        self::assertSame('{"enabled":true}', $calls[2]->body());
        self::assertSame('PATCH', $calls[2]->method());
    }

    public function test_existing_json_and_new_patch_form_and_multipart_bodies_preserve_origin_auth_and_reconciliation(): void
    {
        [$target, $owner] = $this->fixture();
        $calls = [];
        Http::fake(function (Request $request) use (&$calls) {
            $calls[] = $request;
            if ($request->hasHeader('Accept', 'text/plain')) {
                return Http::response('ready', 200, [
                    'X-Request-ID' => 'body-mode-test', 'Content-Type' => 'text/plain',
                ]);
            }

            return Http::response(['ok' => true], 200, ['X-Request-ID' => 'body-mode-test']);
        });

        $api = app(ArvanApiOperations::class);
        $patch = $api->execute($owner, $target->target_id,
            'PATCH', '/api/v1/namespaces/demo/configmaps/one', [], null,
            "apiVersion: v1\nkind: ConfigMap\n", 'application/apply-patch+yaml');
        self::assertTrue($patch['ok'], json_encode($patch));
        self::assertSame('PATCH', $calls[0]->method());
        self::assertSame('application/apply-patch+yaml', $calls[0]->header('Content-Type')[0]);
        self::assertStringContainsString('kind: ConfigMap', $calls[0]->body());

        $jsonPatch = $api->execute($owner, $target->target_id,
            'PATCH', '/api/v1/namespaces/demo/configmaps/one', [],
            '[{"op":"replace","path":"/data/flag","value":"1"}]', null, 'application/json-patch+json');
        self::assertTrue($jsonPatch['ok']);
        self::assertSame('application/json-patch+json', $calls[1]->header('Content-Type')[0]);
        self::assertStringContainsString('"op":"replace"', $calls[1]->body());

        $form = $api->execute($owner, $target->target_id,
            'POST', '/tags', [], null, null, 'application/x-www-form-urlencoded',
            ['title' => 'example tag']);
        self::assertTrue($form['ok'], json_encode($form));
        self::assertSame('application/x-www-form-urlencoded', $calls[2]->header('Content-Type')[0]);
        self::assertSame('title=example+tag', $calls[2]->body());

        $upload = $api->execute($owner, $target->target_id,
            'POST', '/domains/example.test/dns-records/import', [], null, null, 'multipart/form-data',
            ['overwrite' => 'true'], [[
                'name' => 'f_zone_file',
                'filename' => 'dns-records.txt',
                'content_base64' => base64_encode('$ORIGIN example.test.'."\n"),
                'content_type' => 'text/plain',
            ]]);
        self::assertTrue($upload['ok'], json_encode($upload));
        self::assertStringStartsWith('multipart/form-data; boundary=', $calls[3]->header('Content-Type')[0]);
        self::assertStringContainsString('dns-records.txt', $calls[3]->body());
        self::assertStringContainsString('$ORIGIN example.test.', $calls[3]->body());
        self::assertStringContainsString('name="overwrite"', $calls[3]->body());

        $plain = $api->execute($owner, $target->target_id,
            'GET', '/plain', [], null, null, null, [], [], 'text/plain');
        self::assertTrue($plain['ok']);
        self::assertSame('ready', $plain['data']);
        self::assertTrue($calls[4]->hasHeader('Accept', 'text/plain'));

        foreach ($calls as $request) {
            self::assertStringStartsWith('https://api.example.test/cdn/4.0/', $request->url());
            self::assertTrue($request->hasHeader('Authorization', 'Apikey '.self::KEY));
        }
        foreach ([
            ['body_text' => 'yaml', 'content_type' => 'application/yaml\r\nInjected: yes'],
            ['body_text' => null, 'content_type' => 'text/plain'],
            ['form_fields' => ['title' => 'a'], 'form_files' => [['name' => 'file', 'filename' => '../bad', 'content_base64' => 'Zm9v']]],
            ['form_files' => [['name' => 'file', 'filename' => 'good.txt', 'content_base64' => '***']]],
            ['accept' => "text/plain\r\nX-Fake: injected"],
        ] as $invalid) {
            $result = $api->execute($owner, $target->target_id, 'POST', '/domains',
                [], null, $invalid['body_text'] ?? null, $invalid['content_type'] ?? null,
                $invalid['form_fields'] ?? [], $invalid['form_files'] ?? [],
                $invalid['accept'] ?? null);
            self::assertSame('invalid_input', $result['error']['code'], json_encode($result));
        }
        Http::assertSentCount(5);
        $activity = (string) json_encode(DB::table('activity_events')->get());
        self::assertStringNotContainsString(self::KEY, $activity);
        self::assertStringNotContainsString('$ORIGIN', $activity);
        self::assertStringNotContainsString('kind: ConfigMap', $activity);
    }

    public function test_permissions_pause_origin_traversal_and_key_lifecycle_prevent_unauthorized_effects(): void
    {
        [$target, $owner] = $this->fixture();
        $viewer = $this->user('viewer');
        DB::table('user_target_access')->insert([
            'user_id' => $viewer->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);
        Http::fake(fn (Request $request) => Http::response(['ok' => true], 200));
        $api = app(ArvanApiOperations::class);
        self::assertSame('target_not_found', $api->execute($viewer, $target->target_id, 'POST', '/domains')['error']['code']);
        Http::assertNothingSent();
        self::assertTrue($api->execute($viewer, $target->target_id, 'GET', '/domains')['ok']);
        Http::assertSentCount(1);
        foreach (['//evil.example.test/exfiltrate', '/../secrets', '/%2e%2e/private', '/domains?access=bad'] as $path) {
            $result = $api->execute($owner, $target->target_id, 'GET', $path);
            self::assertSame('invalid_input', $result['error']['code'], json_encode($result));
        }
        Http::assertSentCount(1);

        $target->forceFill(['operations_paused' => true])->save();
        self::assertSame('target_paused', $api->execute($owner, $target->target_id, 'GET', '/domains')['error']['code']);
        Http::assertSentCount(1);
        $target->forceFill(['operations_paused' => false])->save();

        $key = TargetCredential::query()->sole();
        $config = ArvanApiTargetConfig::query()->sole();
        $config->base_url = 'https://other.example.test/cdn/4.0';
        $config->save();
        self::assertSame('credential_unavailable', $api->execute($owner, $target->target_id, 'GET', '/domains')['error']['code']);
        Http::assertSentCount(1);
        self::assertSame('arvan.api.write', GatewayPermission::ArvanApiWrite->value);

        // Any user with only read authority cannot issue DELETE; no provider call.
        self::assertSame('target_not_found', $api->execute($viewer, $target->target_id, 'DELETE', '/domains')['error']['code']);
        $this->expectException(\RuntimeException::class);
        app(ArvanApiTargetVault::class)->open($target, $config, $key);
    }

    public function test_api_key_origin_rotation_requires_fresh_key_and_stale_revision_never_wins(): void
    {
        [$target] = $this->fixture();
        $adapter = app(ArvanApiTargetAdapter::class);
        $oldRevision = $adapter->configurationRevision($target);
        $base = [
            'configuration_revision' => $oldRevision,
            'api_base_url' => 'https://new-api.example.test/v99',
            'api_spec_url' => 'https://spec.example.test/v99.yaml',
            'api_probe_path' => '/capabilities',
            'api_key' => '',
        ];

        try {
            $adapter->updateConfiguration($target, $base);
            self::fail('Rebinding the original key to a new origin succeeded.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('invalid_input', $exception->reason);
        }
        self::assertSame('https://api.example.test/cdn/4.0', ArvanApiTargetConfig::query()->sole()->base_url);
        self::assertSame(self::KEY, app(ArvanApiTargetVault::class)->open(
            $target, ArvanApiTargetConfig::query()->sole(), TargetCredential::query()->sole(),
        ));

        $adapter->updateConfiguration($target, [
            ...$base,
            'api_key' => 'new-machine-user-key-for-new-origin',
        ]);
        $config = ArvanApiTargetConfig::query()->sole();
        self::assertSame('https://new-api.example.test/v99', $config->base_url);
        self::assertSame('new-machine-user-key-for-new-origin', app(ArvanApiTargetVault::class)->open(
            $target, $config, TargetCredential::query()->sole(),
        ));
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));

        try {
            $adapter->updateConfiguration($target, [
                ...$base, 'api_base_url' => 'https://stale.example.test/v1',
                'api_key' => 'another-machine-key',
            ]);
            self::fail('An obsolete configuration revision overwrote the new origin.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('invalid_input', $exception->reason);
        }
        self::assertSame('https://new-api.example.test/v99', $config->fresh()->base_url);
        Http::assertNothingSent();
    }

    public function test_scope_and_explicit_permission_denials_are_stricter_than_provider_key_scope(): void
    {
        [$target, $owner] = $this->fixture();
        $operator = $this->user('operator');
        $unassigned = $this->user('operator');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::ArvanApiWrite->value,
        ]);
        Http::fake(fn (Request $request) => Http::response(['ok' => true], 200));
        $api = app(ArvanApiOperations::class);
        self::assertSame('target_not_found', $api->execute($unassigned, 'arvan-cdn', 'GET', '/domains')['error']['code']);
        self::assertSame('target_not_found', $api->execute($operator, 'arvan-cdn', 'PATCH', '/domains', [], '{"enabled":true}')['error']['code']);
        self::assertTrue($api->execute($operator, 'arvan-cdn', 'GET', '/domains')['ok']);
        Http::assertSentCount(1);

        $operator->forceFill(['ai_access_enabled' => false])->save();
        // A real MCP request's pre-authentication middleware also applies;
        // Direct human-channel invocation is not an AI OAuth grant.
        self::assertTrue($api->execute($owner, 'arvan-cdn', 'GET', '/domains')['ok']);
    }

    public function test_mutation_http_failure_is_unknown_without_blind_replay_and_get_failure_is_confirmed(): void
    {
        [$target, $owner] = $this->fixture();
        Http::fake(fn (Request $request) => Http::response(['error' => 'temporary provider fault'], 503, [
            'X-Request-ID' => 'provider-503',
        ]));
        $api = app(ArvanApiOperations::class);
        $mutate = $api->execute($owner, $target->target_id, 'POST', '/domains', [], '{"domain":"test"}');
        self::assertFalse($mutate['ok']);
        self::assertSame('outcome_unknown', $mutate['error']['code']);
        self::assertSame('upstream_http_error', $api->execute($owner, $target->target_id, 'GET', '/domains')['error']['code']);
        Http::assertSentCount(2);
        $history = DB::table('activity_events')->where('operation', 'arvan-api-request')->orderBy('created_at')->get();
        self::assertCount(2, $history);
        self::assertNotSame(self::KEY, (string) json_encode($history));
    }

    public function test_untrusted_provider_body_and_request_id_cannot_echo_gateway_machine_key(): void
    {
        [$target, $owner] = $this->fixture();
        Http::fake(fn (Request $request) => Http::response([
            'error' => 'never share '.self::KEY,
        ], 400, ['X-Request-ID' => self::KEY]));
        $result = app(ArvanApiOperations::class)->execute(
            $owner, $target->target_id, 'GET', '/broken',
        );

        self::assertSame('upstream_http_error', $result['error']['code']);
        $events = DB::table('activity_events')->where('operation', 'arvan-api-request')->get();
        self::assertCount(1, $events);
        self::assertStringNotContainsString(self::KEY, (string) json_encode($events));
        self::assertStringContainsString('[REDACTED]', (string) json_encode($events));
        Http::assertSentCount(1);
    }

    public function test_paused_target_blocks_admin_connect_reconnect_and_test_without_a_provider_request(): void
    {
        [$target, $owner] = $this->fixture();
        $target->forceFill(['operations_paused' => true])->save();
        Http::fake(fn (Request $request) => Http::response(['unexpected' => true]));

        $this->actingAs($owner);
        foreach (['connect', 'reconnect', 'test'] as $action) {
            $this->post(route('admin.targets.'.$action, ['target' => $target->target_id], false))
                ->assertRedirect();
        }
        Http::assertNothingSent();
        foreach (['connect', 'reconnect', 'test'] as $method) {
            try {
                app(ArvanApiTargetAdapter::class)->{$method}($target);
                self::fail('Paused Target dispatched a provider probe.');
            } catch (TargetConnectorFailure $exception) {
                self::assertSame('target_paused', $exception->reason);
            }
        }
        Http::assertNothingSent();

        // Local recovery/disconnect must remain available even when paused.
        app(ArvanApiTargetAdapter::class)->disconnect($target);
        self::assertSame(0, TargetCredential::query()->count());
    }

    public function test_probe_reply_after_local_disconnect_never_resurrects_the_old_key(): void
    {
        [$target] = $this->fixture();
        $adapter = app(ArvanApiTargetAdapter::class);
        Http::fake(function (Request $request) use ($adapter, $target) {
            self::assertTrue($request->hasHeader('Authorization', 'Apikey '.self::KEY));
            // Deterministic interleaving: a reply for the old key is still
            // pending when an Owner removes the local credential.
            $adapter->disconnect($target);

            return Http::response(['status' => true], 200);
        });

        try {
            $adapter->test($target);
            self::fail('An obsolete in-flight health check marked a disconnected Target connected.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('probe_stale', $exception->reason);
        }

        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertNull($target->fresh()->connected_at);
        self::assertSame(0, TargetCredential::query()->count());
        Http::assertSentCount(1);
    }

    public function test_probe_reply_after_key_and_origin_rotation_keeps_new_credential_disconnected(): void
    {
        [$target] = $this->fixture();
        $adapter = app(ArvanApiTargetAdapter::class);
        $revision = $adapter->configurationRevision($target);
        Http::fake(function (Request $request) use ($adapter, $target, $revision) {
            self::assertTrue($request->hasHeader('Authorization', 'Apikey '.self::KEY));
            $adapter->updateConfiguration($target, [
                'configuration_revision' => $revision,
                'api_base_url' => 'https://rotated.example.test/new-api/v4',
                'api_spec_url' => 'https://spec.example.test/rotated.yaml',
                'api_probe_path' => '/health',
                'api_key' => 'rotated-key-not-used-by-old-probe',
            ]);

            return Http::response(['status' => true], 200);
        });

        try {
            $adapter->connect($target);
            self::fail('An old probe reply overwrote the new unverified connection state.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('probe_stale', $exception->reason);
        }

        $current = $target->fresh();
        self::assertSame('disconnected', $current->getRawOriginal('connection_state'));
        self::assertNull($current->connected_at);
        self::assertSame('https://rotated.example.test/new-api/v4', ArvanApiTargetConfig::query()->sole()->base_url);
        self::assertSame('rotated-key-not-used-by-old-probe', app(ArvanApiTargetVault::class)->open(
            $target, ArvanApiTargetConfig::query()->sole(), TargetCredential::query()->sole(),
        ));
        Http::assertSentCount(1);
    }

    public function test_pause_during_probe_prevents_obsolete_connected_evidence_on_reply(): void
    {
        [$target] = $this->fixture();
        Http::fake(function (Request $request) use ($target) {
            $target->forceFill(['operations_paused' => true])->save();

            return Http::response(['ok' => true], 200);
        });

        try {
            app(ArvanApiTargetAdapter::class)->reconnect($target);
            self::fail('Paused Target accepted an in-flight probe result.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('probe_stale', $exception->reason);
        }

        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        Http::assertSentCount(1);
    }

    public function test_activity_and_authorized_diagnostics_retain_safe_operation_identity_for_all_outcomes(): void
    {
        [$target, $owner] = $this->fixture();
        $networkAttempts = 0;
        Http::fake(function (Request $request) use (&$networkAttempts) {
            $networkAttempts++;
            if ($request->method() === 'GET') {
                return Http::response(['ok' => true], 200, ['X-Request-ID' => 'provider-ok']);
            }
            if ($request->method() === 'PATCH') {
                return Http::response(['error' => 'not yet applied'], 503, ['X-Request-ID' => 'provider-503']);
            }

            // No response: the remote state cannot be inferred from transport.
            throw new ConnectionException('Connection closed after request transmission.');
        });

        $api = app(ArvanApiOperations::class);
        $success = $api->execute($owner, $target->target_id, 'GET', '/domains/alpha', ['page' => 27]);
        $failed = $api->execute($owner, $target->target_id, 'PATCH', '/domains/beta', [],
            '{"token":"PRIVATE_BODY_MUST_NOT_BE_LOGGED"}');
        $uncertain = $api->execute($owner, $target->target_id, 'DELETE', '/domains/'.self::KEY);
        self::assertTrue($success['ok']);
        self::assertSame('outcome_unknown', $failed['error']['code']);
        self::assertSame('outcome_unknown', $uncertain['error']['code']);
        // Laravel only records HTTP fake calls that return a response;
        // the third attempt throws before a response can be recorded.
        self::assertSame(3, $networkAttempts);
        Http::assertSentCount(2);

        $rows = DB::table('activity_events')->where('operation', 'arvan-api-request')->get();
        self::assertCount(3, $rows);
        $byMethod = [];
        foreach ($rows as $row) {
            $details = json_decode((string) $row->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
            $byMethod[$details['api_operation']['method']] = [$row, $details];
            self::assertSame(64, strlen($details['api_operation']['path_sha256']));
            self::assertStringNotContainsString(self::KEY, (string) $row->diagnostic_context);
            self::assertStringNotContainsString('PRIVATE_BODY_MUST_NOT_BE_LOGGED', (string) $row->diagnostic_context);
            self::assertArrayNotHasKey('body_json', $details);
            self::assertArrayNotHasKey('query', $details);
        }

        self::assertSame('success', $byMethod['GET'][0]->outcome);
        self::assertSame('/domains/alpha', $byMethod['GET'][1]['api_operation']['relative_path']);
        self::assertSame('provider-ok', $byMethod['GET'][1]['api_operation']['provider_request_id']);
        self::assertSame(200, $byMethod['GET'][1]['remote_http_status']);

        self::assertSame('unknown', $byMethod['PATCH'][0]->outcome);
        self::assertSame('/domains/beta', $byMethod['PATCH'][1]['api_operation']['relative_path']);
        self::assertSame('provider-503', $byMethod['PATCH'][1]['api_operation']['provider_request_id']);
        self::assertSame(503, $byMethod['PATCH'][1]['remote_http_status']);
        self::assertFalse($byMethod['PATCH'][1]['retry_safe']);

        self::assertSame('unknown', $byMethod['DELETE'][0]->outcome);
        self::assertSame('/domains/[REDACTED]', $byMethod['DELETE'][1]['api_operation']['relative_path']);
        self::assertSame('gateway_transport', $byMethod['DELETE'][1]['failure_origin']);
        self::assertTrue($byMethod['DELETE'][1]['effect_unconfirmed']);
        self::assertFalse($byMethod['DELETE'][1]['retry_safe']);

        // Existing permissioned MCP diagnostic lookup must expose the same
        // bounded evidence, not just a database blob or a new unscoped API.
        $reader = app(OperationDiagnosticsMcpToolHandlers::class);
        foreach ($byMethod as $method => [$row, $saved]) {
            $reference = (string) $row->correlation_id;
            $lookup = $reader->read($owner, $reference);
            self::assertTrue($lookup['ok']);
            self::assertSame($saved['api_operation'], $lookup['events'][0]['diagnostics']['api_operation']);
            self::assertSame($method, $lookup['events'][0]['diagnostics']['api_operation']['method']);
            self::assertStringNotContainsString(self::KEY, json_encode($lookup, JSON_THROW_ON_ERROR));
            $admin = $this->actingAs($owner)->get('/admin/activity?diagnostic_reference='.$reference)
                ->assertOk()->assertSee($reference)->assertDontSee(self::KEY);
            // Admin currently expands rich evidence on failed/uncertain rows;
            // the existing MCP diagnostic lookup also exposes success data.
            if ($row->outcome !== 'success') {
                $admin->assertSee($saved['api_operation']['relative_path']);
            }
        }
    }

    public function test_url_encoded_key_echoes_are_never_persisted_in_api_identity_or_provider_diagnostics(): void
    {
        [$target, $owner] = $this->fixture();
        $partial = '%65x%61'.substr(self::KEY, 3);
        $mixed = '%65xa%6D'.substr(self::KEY, 4);
        $nested = rawurlencode($partial);
        $doubleNested = rawurlencode($nested);
        $deep = $partial;
        for ($i = 0; $i < 12; $i++) {
            $deep = rawurlencode($deep);
        }
        $cases = [
            ['GET', '/domains/'.self::KEY, 'success'],
            ['PATCH', '/domains/'.$partial, 'unknown'],
            ['DELETE', '/domains/'.$mixed, 'unknown'],
            ['GET', '/domains/'.$nested, 'success'],
            ['GET', '/domains/'.$doubleNested, 'success'],
            ['GET', '/domains/%6Eonsecret', 'success'],
            ['GET', '/domains/'.$deep, 'success'],
        ];
        $sent = [];
        Http::fake(function (Request $request) use (&$sent, $nested, $doubleNested, $mixed) {
            $index = count($sent);
            $sent[] = [$request->method(), $request->url()];
            if ($index === 2) {
                throw new ConnectionException('Connection closed after request dispatch.');
            }
            if ($index === 1) {
                return Http::response(['message' => 'provider echo: '.$nested], 503, [
                    'X-Request-ID' => 'trace-'.$mixed,
                ]);
            }

            return Http::response($index === 4 ? ['echo' => $nested] : ['ok' => true], 200, [
                'X-Request-ID' => $index === 3 ? 'trace-'.$doubleNested
                    : ($index === 5 ? 'provider-%64iagnostic' : 'provider-safe'),
            ]);
        });

        $api = app(ArvanApiOperations::class);
        $reader = app(OperationDiagnosticsMcpToolHandlers::class);
        foreach ($cases as $index => [$method, $path, $outcome]) {
            $result = $api->execute($owner, $target->target_id, $method, $path,
                ['page' => 8], $method === 'PATCH' ? '{"value":"private body must stay out of Activity"}' : null);
            self::assertSame([$method, 'https://api.example.test/cdn/4.0'.$path.'?page=8'], $sent[$index]);
            self::assertSame($outcome === 'success', $result['ok']);
            if ($index === 4) {
                self::assertSame('[REDACTED]', $result['data']);
            }
            $event = DB::table('activity_events')->where('operation', 'arvan-api-request')
                ->orderByDesc('created_at')->orderByDesc('id')->first();
            self::assertNotNull($event);
            self::assertSame($outcome, $event->outcome);
            $details = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
            self::assertSame($method, $details['api_operation']['method']);
            self::assertSame(hash('sha256', $path), $details['api_operation']['path_sha256']);
            self::assertSame($index === 5 ? $path : '/domains/[REDACTED]',
                $details['api_operation']['relative_path']);

            if ($index === 1) {
                self::assertSame(503, $details['remote_http_status']);
                self::assertSame('[REDACTED]', $details['api_operation']['provider_request_id']);
                self::assertSame('[REDACTED]', $details['source_error_details']['response_excerpt']);
            } elseif ($index === 2) {
                self::assertTrue($details['effect_unconfirmed']);
                self::assertFalse($details['retry_safe']);
            } else {
                self::assertSame(200, $details['remote_http_status']);
                self::assertSame($index === 3 ? '[REDACTED]'
                    : ($index === 5 ? 'provider-%64iagnostic' : 'provider-safe'),
                    $details['api_operation']['provider_request_id']);
            }

            $stored = (string) $event->diagnostic_context;
            self::assertStringNotContainsString('private body must stay out of Activity', $stored);
            $lookup = $reader->read($owner, (string) $event->correlation_id);
            self::assertTrue($lookup['ok']);
            self::assertSame($details, $lookup['events'][0]['diagnostics']);
            $admin = $this->actingAs($owner)->get('/admin/activity?diagnostic_reference='.$event->correlation_id)
                ->assertOk();
            if ($outcome !== 'success') {
                $admin->assertSee($details['api_operation']['relative_path']);
            }
            foreach ([$stored, json_encode($lookup, JSON_THROW_ON_ERROR), $admin->getContent()] as $serialized) {
                foreach ([false, true] as $formEncoding) {
                    $decoded = $serialized;
                    while (true) {
                        self::assertStringNotContainsString(self::KEY, $decoded);
                        $next = $formEncoding ? urldecode($decoded) : rawurldecode($decoded);
                        if ($next === $decoded) {
                            break;
                        }
                        $decoded = $next;
                    }
                }
            }
        }
        self::assertCount(count($cases), $sent);
    }

    public function test_encoded_plus_and_cross_segment_key_echo_redact_only_diagnostics(): void
    {
        [$target, $owner] = $this->fixture();
        $credential = TargetCredential::query()->sole();
        $key = 'machine+secret/seg';
        $config = ArvanApiTargetConfig::query()->sole();
        $credential->forceFill([
            'encrypted_payload' => app(ArvanApiTargetVault::class)->seal($target, $config, $key),
        ])->save();
        $path = '/domains/machine%2Bsecret/seg';
        Http::fake(function (Request $request) use ($key, $path) {
            self::assertSame('https://api.example.test/cdn/4.0'.$path, $request->url());
            self::assertTrue($request->hasHeader('Authorization', 'Apikey '.$key));

            return Http::response(['ok' => true], 200, ['X-Request-ID' => 'trace-'.urlencode($key)]);
        });

        $result = app(ArvanApiOperations::class)->execute($owner, $target->target_id, 'GET', $path);
        self::assertTrue($result['ok']);
        self::assertSame('[REDACTED]', $result['upstream_request_id']);
        $event = DB::table('activity_events')->where('operation', 'arvan-api-request')->sole();
        $details = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('/[REDACTED]', $details['api_operation']['relative_path']);
        self::assertSame(hash('sha256', $path), $details['api_operation']['path_sha256']);
        self::assertSame('[REDACTED]', $details['api_operation']['provider_request_id']);
        $lookup = app(OperationDiagnosticsMcpToolHandlers::class)
            ->read($owner, (string) $event->correlation_id);
        self::assertTrue($lookup['ok']);
        foreach ([(string) $event->diagnostic_context, json_encode($lookup, JSON_THROW_ON_ERROR)] as $raw) {
            for ($i = 0; $i < 4; $i++) {
                self::assertStringNotContainsString($key, $raw);
                $raw = urldecode($raw);
            }
        }
        Http::assertSentCount(1);
    }

    public function test_json_escaped_provider_credentials_are_redacted_before_success_and_error_diagnostics(): void
    {
        [$target, $owner] = $this->fixture();
        $config = ArvanApiTargetConfig::query()->sole();
        $credential = TargetCredential::query()->sole();
        $key = 'machine+secret/seg';
        $credential->forceFill([
            'encrypted_payload' => app(ArvanApiTargetVault::class)->seal($target, $config, $key),
        ])->save();

        $cases = [
            ['PATCH', 503, json_encode(['message' => 'echo '.$key], JSON_THROW_ON_ERROR), 'provider-http-503', true],
            ['GET', 200, '{"message":"\u006dachine+secret\u002fseg"}', 'provider-ok', true],
            ['GET', 200, '{"machine+secret\/seg":"safe data"}', 'provider-ok', true],
            ['GET', 200, json_encode(['nested' => json_encode(['echo' => $key], JSON_THROW_ON_ERROR)], JSON_THROW_ON_ERROR), 'provider-ok', true],
            ['GET', 200, json_encode(['echo' => '%6dachine%2Bsecret%2fseg'], JSON_THROW_ON_ERROR), 'provider-ok', true],
            ['GET', 200, '{"message":"ordinary response","detail":"safe"}', 'provider-safe', false],
            ['PATCH', 422, '{"message":"ordinary provider error","detail":"safe"}',
                'req-'.str_replace('/', '\/', $key), false],
            ['PATCH', 422, '{"message":"ordinary provider error","detail":"safe"}',
                'req-'.str_replace('m', '\u006d', $key), false],
            ['GET', 200, rawurlencode(json_encode(['message' => $key], JSON_THROW_ON_ERROR)),
                'provider-url-encoded-json', true],
            ['PATCH', 503, rawurlencode(rawurlencode(json_encode(['message' => $key], JSON_THROW_ON_ERROR))),
                'provider-double-url-json', true],
            ['PATCH', 503, '{"message":"machine+secret\/seg","message":"safe duplicate"}',
                'provider-duplicate-field', true],
        ];

        $outbound = [];
        Http::fake(function (Request $request) use (&$outbound, $cases, $key) {
            $case = $cases[count($outbound)];
            self::assertSame('Apikey '.$key, $request->header('Authorization')[0]);
            $outbound[] = [$request->method(), $request->url()];

            return Http::response($case[2], $case[1], ['X-Request-ID' => $case[3]]);
        });

        $operation = app(ArvanApiOperations::class);
        $reader = app(OperationDiagnosticsMcpToolHandlers::class);
        foreach ($cases as $index => [$method, $status, $body, $requestId, $unsafeBody]) {
            $result = $operation->execute($owner, $target->target_id, $method, '/domains/safe-resource');
            self::assertSame([$method, 'https://api.example.test/cdn/4.0/domains/safe-resource'], $outbound[$index]);
            self::assertSame($status >= 200 && $status < 300, $result['ok']);
            if ($status === 200) {
                if ($unsafeBody) {
                    self::assertSame('[REDACTED]', $result['data']);
                } else {
                    self::assertSame(['message' => 'ordinary response', 'detail' => 'safe'], $result['data']);
                }
            } else {
                self::assertSame('outcome_unknown', $result['error']['code']);
            }

            $event = DB::table('activity_events')->where('operation', 'arvan-api-request')
                ->orderByDesc('id')->first();
            self::assertNotNull($event);
            $context = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
            self::assertSame($method, $context['api_operation']['method']);
            self::assertSame('/domains/safe-resource', $context['api_operation']['relative_path']);
            self::assertSame(hash('sha256', '/domains/safe-resource'), $context['api_operation']['path_sha256']);
            self::assertSame($status, $context['remote_http_status']);
            self::assertSame(
                in_array($index, [6, 7], true) ? '[REDACTED]' : $requestId,
                $context['api_operation']['provider_request_id'],
            );
            if ($status !== 200) {
                self::assertSame('unknown', $event->outcome);
                self::assertFalse($context['retry_safe']);
                self::assertTrue($context['effect_unconfirmed']);
                self::assertSame(
                    $unsafeBody ? '[REDACTED]' : $body,
                    $context['source_error_details']['response_excerpt'],
                );
            } else {
                self::assertSame('success', $event->outcome);
            }

            $lookup = $reader->read($owner, (string) $event->correlation_id);
            self::assertTrue($lookup['ok']);
            self::assertSame($context, $lookup['events'][0]['diagnostics']);
            $admin = $this->actingAs($owner)->get('/admin/activity?diagnostic_reference='.$event->correlation_id)
                ->assertOk();
            foreach ([(string) $event->diagnostic_context,
                json_encode($lookup, JSON_THROW_ON_ERROR),
                $admin->getContent()] as $serialized) {
                // A JSON decoder, unlike a plain substring check, reconstructs
                // standard slash and Unicode escapes inside provider evidence.
                $decoded = $serialized;
                for ($pass = 0; $pass < 4; $pass++) {
                    self::assertStringNotContainsString($key, $decoded);
                    $decoded = rawurldecode($decoded);
                }
            }
        }

        Http::assertSentCount(count($cases));
    }

    public function test_json_escaped_numeric_key_is_detected_before_assoc_key_coercion(): void
    {
        [$target, $owner] = $this->fixture();
        $config = ArvanApiTargetConfig::query()->sole();
        $credential = TargetCredential::query()->sole();
        $key = '123456789';
        $credential->forceFill([
            'encrypted_payload' => app(ArvanApiTargetVault::class)->seal($target, $config, $key),
        ])->save();

        // PHP associative JSON decoding changes a numeric object property
        // into an integer key. Inspect the raw JSON string tokens as well.
        $body = '{"\u0031\u0032\u0033\u0034\u0035\u0036\u0037\u0038\u0039":"not confidential"}';
        Http::fake(fn (Request $request) => Http::response($body, 200, [
            'X-Request-ID' => 'provider-numeric-key',
        ]));
        $result = app(ArvanApiOperations::class)->execute(
            $owner, $target->target_id, 'GET', '/domains/safe-resource',
        );
        self::assertTrue($result['ok']);
        self::assertSame('[REDACTED]', $result['data']);
        $event = DB::table('activity_events')->where('operation', 'arvan-api-request')->sole();
        $context = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('GET', $context['api_operation']['method']);
        self::assertSame('provider-numeric-key', $context['api_operation']['provider_request_id']);
        self::assertStringNotContainsString($key, (string) $event->diagnostic_context);
        Http::assertSentCount(1);
    }

    public function test_authentication_probe_is_real_readonly_get_and_disconnect_only_erases_local_credential(): void
    {
        [$target] = $this->fixture();
        Http::fake(function (Request $request) {
            self::assertSame('GET', $request->method());
            self::assertSame('https://api.example.test/cdn/4.0/domains', $request->url());

            return Http::response(['status' => true], 200);
        });
        $adapter = app(ArvanApiTargetAdapter::class);
        self::assertStringContainsString('succeeded', $adapter->test($target)->statusMessage);
        self::assertSame('connected', $target->fresh()->getRawOriginal('connection_state'));
        $adapter->disconnect($target);
        self::assertSame('disconnected', $target->fresh()->getRawOriginal('connection_state'));
        self::assertSame(0, TargetCredential::query()->count());
        Http::assertSentCount(1);
    }

    /** @return array{Target,User} */
    private function fixture(): array
    {
        $target = Target::query()->create([
            'target_id' => 'arvan-cdn',
            'display_name' => 'Arvan CDN',
            'connector_type' => 'arvancloud',
        ]);
        $config = ArvanApiTargetConfig::query()->create([
            'target_record_id' => $target->getKey(),
            'base_url' => 'https://api.example.test/cdn/4.0',
            'spec_url' => 'https://spec.example.test/openapi.yaml',
            'probe_path' => '/domains',
        ]);
        TargetCredential::query()->create([
            'target_record_id' => $target->getKey(),
            'connector_type' => 'arvancloud',
            'purpose' => ArvanApiTargetVault::PURPOSE,
            'encrypted_payload' => app(ArvanApiTargetVault::class)->seal($target, $config, self::KEY),
        ]);

        return [$target, $this->user('owner')];
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => 'Fixture '.$role,
            'email' => Str::random(12).'@example.test',
            'password' => bcrypt('CorrectHorse!234'),
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
            'ai_access_enabled' => true,
        ]);
    }
}
