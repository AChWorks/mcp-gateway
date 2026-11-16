<?php

namespace Tests\Feature\ArvanCloud;

use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Targets\ArvanApiOperations;
use App\Application\Targets\TargetConnectorFailure;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetAdapter;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetConfig;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetVault;
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

    public function test_registered_target_key_is_bound_encrypted_and_admin_never_replays_the_secret(): void
    {
        $owner = $this->user('owner');
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
        $this->actingAs($this->user('administrator'))
            ->post('/admin/targets', $payload)->assertForbidden();
        self::assertSame(0, Target::query()->count());
        $this->actingAs($owner)
            ->post('/admin/targets', $payload)->assertAdminRedirect('/admin/targets/arvan-cdn');

        $target = Target::query()->sole();
        $config = ArvanApiTargetConfig::query()->sole();
        $credential = TargetCredential::query()->sole();
        self::assertSame('arvancloud', $target->connector_type);
        self::assertSame('https://api.example.test/cdn/4.0', $config->base_url);
        self::assertSame(self::KEY, app(ArvanApiTargetVault::class)->open($target, $config, $credential));
        self::assertStringNotContainsString(self::KEY, $credential->encrypted_payload);
        $this->get('/admin/targets/arvan-cdn')->assertOk()
            ->assertSee('ArvanCloud API root')->assertDontSee(self::KEY);
        $this->get('/admin/targets/arvan-cdn/edit')->assertOk()
            ->assertSee('Advanced connector connection settings')->assertDontSee(self::KEY);
        Http::assertNothingSent();

        $keyFlashed = 'should-never-be-flashed';
        $this->from('/admin/targets/create?connector_type=arvancloud')->post('/admin/targets', [
            ...$payload, 'target_id' => 'INVALID SPACE', 'api_key' => $keyFlashed,
        ])->assertSessionHasErrors('target_id');
        self::assertNotContains($keyFlashed, (array) session()->getOldInput());
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
