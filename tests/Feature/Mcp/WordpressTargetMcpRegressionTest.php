<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Mcp\TargetMcpToolHandlers;
use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use App\Application\Targets\WordpressTargetOperations;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Mcp\GatewayMcpEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Tests\TestCase;

final class WordpressTargetMcpRegressionTest extends TestCase
{
    use RefreshDatabase;

    /** @var list<array{host:string,ability:string,authorization:string}> */
    private array $toolCalls = [];

    private User $principal;

    protected function setUp(): void
    {
        parent::setUp();

        $this->principal = User::query()->create([
            'name' => 'Gateway MCP Owner',
            'email' => 'mcp-owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);

        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.name', 'MCP Gateway Test');
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

        $this->fakeBridge();
    }

    public function test_sites_list_and_context_expose_bounded_non_secret_site_state(): void
    {
        $alpha = $this->createSite('alpha');
        $alpha->forceFill(['ai_guidance' => 'Production site: ask before risky writes.'])->save();
        $this->pair($alpha);
        $this->createSite('beta');

        $handlers = app(WordpressTargetMcpToolHandlers::class);
        $list = app(TargetMcpToolHandlers::class)->targetsList($this->principal);
        $context = app(TargetMcpToolHandlers::class)->targetContext($this->principal, 'alpha');

        self::assertTrue($list['ok']);
        self::assertSame(['alpha', 'beta'], array_column($list['targets'], 'target_id'));
        self::assertSame('Production site: ask before risky writes.', $list['targets'][0]['ai_guidance']);
        self::assertNull($list['targets'][1]['ai_guidance']);
        self::assertFalse($list['truncated']);
        self::assertSame('connected', $list['targets'][0]['connection_state']);
        self::assertSame('disconnected', $list['targets'][1]['connection_state']);

        self::assertTrue($context['ok']);
        self::assertSame('alpha', $context['target']['target_id']);
        self::assertSame('wp_ai_bridge', $context['target']['connector_type']);
        self::assertSame('Production site: ask before risky writes.', $context['target']['ai_guidance']);
        self::assertArrayNotHasKey('base_url', $context['target']);
        self::assertArrayNotHasKey('mcp_resource_url', $context['target']);

        $encoded = json_encode([$list, $context], JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('alpha-access', $encoded);
        self::assertStringNotContainsString('alpha-refresh', $encoded);
        self::assertStringNotContainsString('client_assertion', $encoded);
        self::assertStringNotContainsString('oauth/token', $encoded);
        self::assertStringNotContainsString('oauth/revoke', $encoded);
    }

    public function test_ability_catalog_reads_are_routed_to_the_exact_selected_site(): void
    {
        $alpha = $this->createSite('alpha');
        $beta = $this->createSite('beta');
        $this->pair($alpha);
        $this->pair($beta);

        $handlers = app(WordpressTargetMcpToolHandlers::class);
        $alphaList = $handlers->read($this->principal, 'alpha', null, 2, 1, 'alpha-space', 'needle');
        $betaExact = $handlers->read($this->principal, 'beta', 'beta/demo');

        self::assertTrue($alphaList['ok']);
        self::assertSame('alpha/demo', $alphaList['catalog']['items'][0]['name']);
        self::assertSame(2, $alphaList['catalog']['page']);
        self::assertSame(1, $alphaList['catalog']['per_page']);
        self::assertSame('not_evaluated', $alphaList['catalog']['execution_permission']);

        self::assertTrue($betaExact['ok']);
        self::assertSame('beta/demo', $betaExact['catalog']['items'][0]['name']);
        self::assertSame('object', $betaExact['catalog']['items'][0]['input_schema']['type']);
        self::assertSame(2, DB::table('activity_events')
            ->where('operation', 'wordpress-abilities-read')->where('outcome', 'success')->count());

        self::assertSame(['alpha.example.test', 'beta.example.test'], array_column($this->toolCalls, 'host'));
        self::assertSame(['wp-ai-bridge/abilities-read', 'wp-ai-bridge/abilities-read'], array_column($this->toolCalls, 'ability'));
        self::assertSame(['Bearer alpha-access', 'Bearer beta-access'], array_column($this->toolCalls, 'authorization'));
    }

    public function test_admin_and_mcp_share_readonly_bridge_execution(): void
    {
        $site = $this->createSite('alpha');
        $this->pair($site);

        $this->actingAs($this->principal)->get(route('admin.targets.show', ['target' => 'alpha']))
            ->assertOk()->assertSee('Inspect Bridge information (read-only)');

        $this->post(route('admin.targets.wordpress.bridge-info', ['target' => 'alpha']))
            ->assertOk()->assertSee('Read-only Bridge information received.')
            ->assertSee('&quot;target&quot;: &quot;alpha&quot;', false);

        $mcp = app(WordpressTargetMcpToolHandlers::class)->execute(
            $this->principal, 'alpha', 'wp-ai-bridge/bridge-info', [],
        );
        self::assertTrue($mcp['ok']);
        self::assertSame(['target' => 'alpha', 'kind' => 'read'], $mcp['result']);
        self::assertSame(2, DB::table('activity_events')
            ->where('operation', 'wordpress-ability-execute')->where('outcome', 'success')->count());
        self::assertSame([
            'wp-ai-bridge/abilities-read', 'wp-ai-bridge/bridge-info',
            'wp-ai-bridge/abilities-read', 'wp-ai-bridge/bridge-info',
        ], array_column($this->toolCalls, 'ability'));
    }

    public function test_admin_readonly_operation_denies_mutation_and_rechecks_scope_and_pause(): void
    {
        $site = $this->createSite('alpha');
        $this->pair($site);
        $operations = app(WordpressTargetOperations::class);

        $result = $operations->execute(
            $this->principal, 'alpha', 'demo/write', ['value' => 'must-not-apply'], readonlyOnly: true,
        );
        self::assertFalse($result['ok']);
        self::assertSame('forbidden', $result['error']['code']);
        self::assertSame(['wp-ai-bridge/abilities-read'], array_column($this->toolCalls, 'ability'));

        $operator = User::query()->create([
            'name' => 'Scoped readonly operator',
            'email' => 'read-only-operator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->id, 'target_record_id' => $site->id,
            'allowed' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->actingAs($operator)->get(route('admin.targets.show', ['target' => 'alpha']))
            ->assertOk()->assertSee('Inspect Bridge information (read-only)');
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->id, 'target_record_id' => $site->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->get(route('admin.targets.show', ['target' => 'alpha']))
            ->assertOk()->assertDontSee('Inspect Bridge information (read-only)');
        $this->post(route('admin.targets.wordpress.bridge-info', ['target' => 'alpha']))
            ->assertNotFound();

        $this->post(route('admin.targets.wordpress.bridge-info', ['target' => 'unknown-target']))
            ->assertNotFound();
        $this->post(route('admin.targets.wordpress.bridge-info', ['target' => 'invalid_!!']))
            ->assertNotFound();

        $this->actingAs($this->principal);
        $site->forceFill(['operations_paused' => true])->save();
        $this->get(route('admin.targets.show', ['target' => 'alpha']))
            ->assertOk()->assertDontSee('Inspect Bridge information (read-only)');
        $this->post(route('admin.targets.wordpress.bridge-info', ['target' => 'alpha']))
            ->assertStatus(409)->assertSee('target_paused');
        self::assertSame(['wp-ai-bridge/abilities-read'], array_column($this->toolCalls, 'ability'),
            'Denied and paused Admin actions must not reach the remote execution stage.');
    }

    public function test_execution_routes_read_write_and_downstream_denial_without_bypass(): void
    {
        $alpha = $this->createSite('alpha');
        $beta = $this->createSite('beta');
        $this->pair($alpha);
        $this->pair($beta);

        $handlers = app(WordpressTargetMcpToolHandlers::class);
        $read = $handlers->execute($this->principal, 'alpha', 'demo/read', ['id' => 7]);
        $write = $handlers->execute($this->principal, 'beta', 'demo/write', ['value' => 'changed']);
        $denied = $handlers->execute($this->principal, 'alpha', 'demo/denied', []);

        self::assertTrue($read['ok']);
        self::assertSame(['target' => 'alpha', 'kind' => 'read'], $read['result']);

        self::assertTrue($write['ok']);
        self::assertSame(['target' => 'beta', 'kind' => 'write', 'updated' => true], $write['result']);

        self::assertFalse($denied['ok']);
        self::assertSame('downstream_rejected', $denied['error']['code']);
        self::assertStringNotContainsString('alpha-access', $denied['error']['message']);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'wordpress-ability-execute',
            'target_id' => 'alpha',
            'error_code' => 'downstream_rejected',
        ]);

        self::assertSame(
            [
                'wp-ai-bridge/abilities-read',
                'demo/read',
                'wp-ai-bridge/abilities-read',
                'demo/write',
                'wp-ai-bridge/abilities-read',
                'demo/denied',
            ],
            array_column($this->toolCalls, 'ability'),
        );
        self::assertSame(
            [
                'Bearer alpha-access',
                'Bearer alpha-access',
                'Bearer beta-access',
                'Bearer beta-access',
                'Bearer alpha-access',
                'Bearer alpha-access',
            ],
            array_column($this->toolCalls, 'authorization'),
        );
    }

    public function test_operator_site_can_be_write_only_and_unclassified_or_destructive_execution_fails_closed(): void
    {
        $site = $this->createSite('alpha');
        $this->pair($site);
        $operator = User::query()->create([
            'name' => 'Write Only Operator',
            'email' => 'write-only@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
        ]);

        DB::table('user_target_access')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_target_permission_denials')->insert([
            [
                'user_id' => $operator->id,
                'target_record_id' => $site->id,
                'permission' => GatewayPermission::TargetsView->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'user_id' => $operator->id,
                'target_record_id' => $site->id,
                'permission' => GatewayPermission::WordpressAbilitiesInspect->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'user_id' => $operator->id,
                'target_record_id' => $site->id,
                'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);

        $handlers = app(WordpressTargetMcpToolHandlers::class);

        $context = app(TargetMcpToolHandlers::class)->targetContext($operator, 'alpha');
        self::assertFalse($context['ok']);
        self::assertSame('target_not_found', $context['error']['code']);

        $catalog = $handlers->read($operator, 'alpha');
        self::assertFalse($catalog['ok']);
        self::assertSame('target_not_found', $catalog['error']['code']);

        $read = $handlers->execute($operator, 'alpha', 'demo/read', []);
        self::assertFalse($read['ok']);
        self::assertSame('forbidden', $read['error']['code']);

        $write = $handlers->execute($operator, 'alpha', 'demo/write', ['value' => 'changed']);
        self::assertTrue($write['ok']);
        self::assertSame('write', $write['result']['kind']);

        $destructive = $handlers->execute($operator, 'alpha', 'demo/delete', []);
        self::assertFalse($destructive['ok']);
        self::assertSame('forbidden', $destructive['error']['code']);

        $unclassified = $handlers->execute($operator, 'alpha', 'provider/write', []);
        self::assertFalse($unclassified['ok']);
        self::assertSame('forbidden', $unclassified['error']['code']);
    }

    public function test_default_ability_catalog_page_size_is_ten(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);

        $result = app(WordpressTargetMcpToolHandlers::class)->read($this->principal, 'alpha');

        self::assertTrue($result['ok']);
        self::assertSame(10, $result['catalog']['per_page']);
    }

    public function test_mutating_mcp_tool_rejection_retains_compatible_code_but_never_claims_rollback(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        Log::spy();

        $response = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/denied', []);

        self::assertFalse($response['ok']);
        self::assertSame('downstream_rejected', $response['error']['code']);
        $reference = $response['error']['diagnostic_reference'] ?? null;
        self::assertTrue(is_string($reference) && Str::isUuid($reference));
        self::assertStringContainsString('provider cause may be unavailable', $response['error']['next_step']);
        $event = DB::table('activity_events')->where('operation', 'wordpress-ability-execute')
            ->where('error_code', 'downstream_rejected')->firstOrFail();
        self::assertSame('unknown', $event->outcome);
        self::assertSame($reference, $event->correlation_id);
        self::assertSame('Permission denied by WordPress.', json_decode($event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR)['source_error_message']);
        self::assertStringNotContainsString('Permission denied by WordPress.', json_encode($response, JSON_THROW_ON_ERROR));
        self::assertSame(1, collect($this->toolCalls)
            ->where('ability', 'demo/denied')->count(), 'The rejected mutation must not be replayed.');

        Log::shouldHaveReceived('warning')->withArgs(
            static function (string $message, array $context) use ($reference): bool {
                $encoded = json_encode($context, JSON_THROW_ON_ERROR);

                return $message === 'Gateway operation failure.'
                    && ($context['correlation_id'] ?? null) === $reference
                    && ($context['failure_origin'] ?? null) === 'downstream_mcp'
                    && ($context['failure_stage'] ?? null) === 'operation'
                    && ($context['provider_cause'] ?? null) === 'unknown'
                    && ($context['effect_unconfirmed'] ?? null) === true
                    && ($context['retry_safe'] ?? null) === false
                    && ! str_contains($encoded, 'alpha-access')
                    // The exact observed downstream message is intentionally
                    // retained for authorized diagnostics, not flattened away.
                    && str_contains($encoded, 'Permission denied by WordPress.');
            },
        )->once();
    }

    public function test_readonly_mcp_tool_rejection_is_a_failure_not_an_unknown_write(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        $this->fakeBridge(function (Request $request) {
            $payload = $request->data();
            if (($payload['method'] ?? null) === 'tools/call'
                && ($payload['params']['arguments']['ability_name'] ?? null) === 'demo/read') {
                return Http::response([
                    'jsonrpc' => '2.0', 'id' => $payload['id'] ?? null,
                    'result' => [
                        'isError' => true,
                        'content' => [['type' => 'text', 'text' => 'Provider secret detail']],
                    ],
                ], 200);
            }

            return $this->bridgeResponse($request);
        });
        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/read', []);

        self::assertSame('downstream_rejected', $result['error']['code']);
        $event = DB::table('activity_events')->where('operation', 'wordpress-ability-execute')
            ->where('error_code', 'downstream_rejected')->firstOrFail();
        self::assertSame('failure', $event->outcome);
        self::assertSame($event->correlation_id, $result['error']['diagnostic_reference']);
        self::assertStringNotContainsString('Provider secret detail', json_encode($result, JSON_THROW_ON_ERROR));
    }

    public function test_exact_unknown_downstream_error_code_message_and_structured_details_reach_authorized_ai(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        $this->fakeBridge(function (Request $request) {
            $payload = $request->data();
            if (($payload['method'] ?? null) === 'tools/call'
                && ($payload['params']['arguments']['ability_name'] ?? null) === 'demo/read') {
                return Http::response([
                    'jsonrpc' => '2.0', 'id' => $payload['id'] ?? null,
                    'result' => [
                        'isError' => true,
                        'content' => [[
                            'type' => 'text',
                            'text' => 'WP_Error /var/www/blog/plugins/tool.php: validation failed on php_version; '
                                .'Authorization: Bearer alpha-access password=REMOTE_PASSWORD_123',
                        ]],
                        'structuredContent' => [
                            'error' => [
                                'code' => 'vendor-new/errors:not_known_to_gateway.422',
                                'message' => 'Validation failed at /var/www/blog/plugins/tool.php',
                                'data' => [
                                    'file' => '/var/www/blog/plugins/tool.php',
                                    'parameter' => 'php_version',
                                    'password' => 'REMOTE_PASSWORD_123',
                                    'access_token' => 'REMOTE_ACCESS_TOKEN_456',
                                    'unlabelled_debug_note' => 'Observed bare credential alpha-access in a downstream note',
                                ],
                            ],
                        ],
                    ],
                ], 200);
            }

            return $this->bridgeResponse($request);
        });

        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/read', []);

        self::assertSame('downstream_rejected', $result['error']['code']);
        $event = DB::table('activity_events')
            ->where('operation', 'wordpress-ability-execute')
            ->where('error_code', 'downstream_rejected')->firstOrFail();
        $details = json_decode($event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);

        self::assertSame('vendor-new/errors:not_known_to_gateway.422', $details['source_error_code']);
        self::assertSame('Validation failed at /var/www/blog/plugins/tool.php',
            $details['source_error_structured_message']);
        self::assertStringContainsString('/var/www/blog/plugins/tool.php', $details['source_error_message']);
        self::assertStringContainsString('validation failed on php_version', $details['source_error_message']);
        self::assertSame('/var/www/blog/plugins/tool.php', $details['source_error_details']['file']);
        self::assertSame('php_version', $details['source_error_details']['parameter']);
        self::assertSame('[REDACTED]', $details['source_error_details']['password']);
        self::assertSame('[REDACTED]', $details['source_error_details']['access_token']);
        self::assertSame('unknown', $details['provider_cause']);
        self::assertStringContainsString('Observed bare credential [redacted]',
            $details['source_error_details']['unlabelled_debug_note']);
        self::assertStringNotContainsString('alpha-access', json_encode($details, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('REMOTE_PASSWORD_123', json_encode($details, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('REMOTE_ACCESS_TOKEN_456', json_encode($details, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('/var/www/blog/plugins/tool.php', json_encode($result, JSON_THROW_ON_ERROR));

        $lookup = app(OperationDiagnosticsMcpToolHandlers::class)
            ->read($this->principal, (string) $event->correlation_id);
        self::assertTrue($lookup['ok']);
        self::assertSame($details, $lookup['events'][0]['diagnostics']);
    }

    public function test_json_rpc_protocol_error_keeps_exact_observed_code_and_message_for_diagnostics(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        $this->fakeBridge(function (Request $request) {
            $payload = $request->data();
            if (($payload['method'] ?? null) === 'tools/call'
                && ($payload['params']['arguments']['ability_name'] ?? null) === 'demo/read') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => $payload['id'] ?? null,
                    'error' => [
                        'code' => -32602,
                        'message' => 'Invalid parameter on /srv/site/plugins/news.php; access_token=TOP_SECRET_998',
                        'data' => ['field' => 'php_version', 'password' => 'SECRET_IN_ERROR_DATA'],
                    ],
                ], 200);
            }

            return $this->bridgeResponse($request);
        });

        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/read', []);
        self::assertSame('protocol_error', $result['error']['code']);

        $event = DB::table('activity_events')->where('operation', 'wordpress-ability-execute')
            ->where('error_code', 'protocol_error')->firstOrFail();
        $safe = json_decode($event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(-32602, $safe['source_error_code']);
        self::assertStringContainsString('Invalid parameter on /srv/site/plugins/news.php',
            $safe['source_error_message']);
        self::assertSame('php_version', $safe['source_error_details']['field']);
        self::assertSame('[REDACTED]', $safe['source_error_details']['password']);
        self::assertStringNotContainsString('TOP_SECRET_998', json_encode($safe, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('SECRET_IN_ERROR_DATA', json_encode($safe, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('/srv/site/plugins/news.php', json_encode($result, JSON_THROW_ON_ERROR));
    }

    public function test_readonly_transport_failure_is_not_reported_as_mutation_uncertainty_or_retried(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);

        $catalogCalls = 0;
        $targetCalls = 0;
        $this->resetHttp();
        Http::fake(function (Request $request) use (&$catalogCalls, &$targetCalls) {
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
                return $this->bridgeResponse($request);
            }

            if ($request->method() === 'DELETE') {
                return Http::response('', 200);
            }

            $payload = $request->data();
            if (($payload['method'] ?? null) === 'initialize') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25'],
                ], 200, ['Mcp-Session-Id' => 'session-alpha']);
            }

            if (($payload['method'] ?? null) === 'tools/call') {
                $ability = (string) ($payload['params']['arguments']['ability_name'] ?? '');
                if ($ability === 'wp-ai-bridge/abilities-read') {
                    $catalogCalls++;

                    return $this->bridgeResponse($request);
                }
                if ($ability === 'demo/read') {
                    $targetCalls++;

                    return Http::failedConnection('cURL error 7: Failed to connect.');
                }
            }

            return $this->bridgeResponse($request);
        });

        Log::spy();
        $result = app(WordpressTargetMcpToolHandlers::class)->execute($this->principal, 'alpha', 'demo/read', []);

        self::assertFalse($result['ok']);
        self::assertSame('network_failure', $result['error']['code']);
        self::assertStringNotContainsString('alpha-access', $result['error']['message']);
        self::assertSame(1, $catalogCalls);
        self::assertSame(1, $targetCalls);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'wordpress-ability-execute',
            'target_id' => 'alpha',
            'error_code' => 'network_failure',
        ]);
        $event = DB::table('activity_events')->where('operation', 'wordpress-ability-execute')->firstOrFail();
        Log::shouldHaveReceived('warning')->withArgs(
            static fn (string $message, array $context): bool => $message === 'Gateway operation failure.'
                && ($context['operation'] ?? null) === 'wordpress-ability-execute'
                && ($context['failure_stage'] ?? null) === 'tcp_connect'
                && ($context['correlation_id'] ?? null) === $event->correlation_id,
        )->atLeast()->once();
    }

    public function test_wordpress_mcp_transport_diagnostics_keep_safe_stages_and_shared_activity_reference(): void
    {
        $target = $this->createSite('alpha');
        $this->pair($target);

        $cases = [
            'dns_lookup' => 'cURL error 6: Could not resolve host PRIVATE_OAUTH_TOKEN URL_SECRET',
            'tcp_connect' => 'cURL error 7: Failed to connect to PRIVATE_OAUTH_TOKEN URL_SECRET',
            'tls_handshake' => 'cURL error 60: SSL certificate problem PRIVATE_OAUTH_TOKEN URL_SECRET',
            'request_timeout' => 'cURL error 28: Operation timed out PRIVATE_OAUTH_TOKEN URL_SECRET',
        ];

        foreach ($cases as $stage => $message) {
            Http::swap(new Factory);
            Http::preventStrayRequests();
            Http::fake(static fn (Request $request) => Http::failedConnection($message));
            Log::spy();

            $result = app(WordpressTargetMcpToolHandlers::class)
                ->read($this->principal, 'alpha');
            self::assertFalse($result['ok']);
            self::assertSame($stage === 'tls_handshake' ? 'tls_failure' : 'network_failure', $result['error']['code']);
            self::assertArrayHasKey('next_step', $result['error']);
            self::assertArrayNotHasKey('correlation_id', $result['error']);
            self::assertStringNotContainsString('PRIVATE_OAUTH_TOKEN', json_encode($result, JSON_THROW_ON_ERROR));
            self::assertStringNotContainsString('URL_SECRET', json_encode($result, JSON_THROW_ON_ERROR));

            $event = DB::table('activity_events')->where('operation', 'wordpress-abilities-read')
                ->orderByDesc('created_at')->orderByDesc('id')->firstOrFail();
            Log::shouldHaveReceived('warning')->withArgs(
                static function (string $description, array $context) use ($stage, $event): bool {
                    $encoded = json_encode($context, JSON_THROW_ON_ERROR);

                    return $description === 'Gateway operation failure.'
                        && ($context['operation'] ?? null) === 'wordpress-abilities-read'
                        && ($context['error_code'] ?? null) === ($stage === 'tls_handshake' ? 'tls_failure' : 'network_failure')
                        && ($context['failure_stage'] ?? null) === $stage
                        && ($context['correlation_id'] ?? null) === $event->correlation_id
                        && ! str_contains($encoded, 'PRIVATE_OAUTH_TOKEN')
                        && ! str_contains($encoded, 'URL_SECRET')
                        && ! str_contains($encoded, 'oauth/token')
                        && ! str_contains($encoded, 'access_token');
                },
            )->atLeast()->once();
        }
    }

    public function test_real_mcp_transport_accepts_nested_empty_object_and_preserves_object_identity_downstream(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);

        $downstreamParameters = null;
        $this->fakeBridge(function (Request $request) use (&$downstreamParameters) {
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            if ($path === '/wp-json/wp-ai-bridge/v1/mcp' && $request->method() === 'POST') {
                $payload = $request->data();
                if (($payload['method'] ?? null) === 'tools/call'
                    && ($payload['params']['arguments']['ability_name'] ?? null) === 'demo/read') {
                    $raw = json_decode($request->body());
                    $downstreamParameters = $raw?->params?->arguments?->parameters;
                }
            }

            return $this->bridgeResponse($request);
        });

        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        self::assertIsString($host);

        $headers = [
            'HTTP_HOST' => $host,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_MCP_PROTOCOL_VERSION' => '2025-11-25',
        ];
        $endpoint = app(GatewayMcpEndpoint::class);

        $initialize = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'initialize',
            'params' => [
                'protocolVersion' => '2025-11-25',
                'capabilities' => (object) [],
                'clientInfo' => ['name' => 'target-regression', 'version' => '1.0.0'],
            ],
        ], JSON_THROW_ON_ERROR));
        $initialize->attributes->set('oauth_user', $this->principal);
        $initialized = $endpoint->handle($initialize);
        self::assertSame(200, $initialized->getStatusCode());
        $session = $initialized->headers->get('Mcp-Session-Id');
        self::assertNotEmpty($session);
        $headers['HTTP_MCP_SESSION_ID'] = $session;

        $request = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0',
            'id' => 50,
            'method' => 'tools/call',
            'params' => [
                'name' => 'wordpress-ability-execute',
                'arguments' => [
                    'target_id' => 'alpha',
                    'ability' => 'demo/read',
                    'input' => (object) [],
                ],
            ],
        ], JSON_THROW_ON_ERROR));
        $request->attributes->set('oauth_user', $this->principal);
        $response = $endpoint->handle($request);
        self::assertSame(200, $response->getStatusCode());
        ob_start();
        $response->sendContent();
        $body = (string) ob_get_clean();
        self::assertStringContainsString('"isError":false', $body);
        self::assertInstanceOf(\stdClass::class, $downstreamParameters);

        // The SDK's empty-object coercion must not turn into permission for
        // nonempty JSON arrays masquerading as WordPress Ability objects.
        $previousCalls = count($this->toolCalls);
        $invalid = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0',
            'id' => 51,
            'method' => 'tools/call',
            'params' => [
                'name' => 'wordpress-ability-execute',
                'arguments' => ['target_id' => 'alpha', 'ability' => 'demo/read', 'input' => [1, 2]],
            ],
        ], JSON_THROW_ON_ERROR));
        $invalid->attributes->set('oauth_user', $this->principal);
        $rejected = $endpoint->handle($invalid);
        ob_start();
        $rejected->sendContent();
        $invalidBody = (string) ob_get_clean();
        self::assertStringContainsString('Invalid parameters', $invalidBody);
        self::assertSame($previousCalls, count($this->toolCalls));
    }

    public function test_unknown_or_disconnected_site_fails_before_downstream_mcp_execution(): void
    {
        $this->createSite('alpha');
        $mcpRequests = 0;
        $this->fakeBridge(function (Request $request) use (&$mcpRequests) {
            if ((string) parse_url($request->url(), PHP_URL_PATH) === '/wp-json/wp-ai-bridge/v1/mcp') {
                $mcpRequests++;
            }

            return $this->bridgeResponse($request);
        });

        $handlers = app(WordpressTargetMcpToolHandlers::class);
        $unknown = $handlers->read($this->principal, 'missing');
        $disconnected = $handlers->execute($this->principal, 'alpha', 'demo/write', []);

        self::assertFalse($unknown['ok']);
        self::assertSame('target_not_found', $unknown['error']['code']);
        self::assertFalse($disconnected['ok']);
        self::assertSame('missing_credential', $disconnected['error']['code']);
        self::assertSame(0, $mcpRequests);
        self::assertNull(Target::query()->where('target_id', 'alpha')->sole()->last_failure_at);
    }

    public function test_ambiguous_mutation_transport_failure_is_not_retried(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);

        $catalogCalls = 0;
        $targetCalls = 0;
        $this->resetHttp();
        Http::fake(function (Request $request) use (&$catalogCalls, &$targetCalls) {
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
                return $this->bridgeResponse($request);
            }

            if ($request->method() === 'DELETE') {
                return Http::response('', 200);
            }

            $payload = $request->data();
            if (($payload['method'] ?? null) === 'initialize') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25'],
                ], 200, ['Mcp-Session-Id' => 'session-alpha']);
            }

            if (($payload['method'] ?? null) === 'tools/call') {
                $ability = (string) ($payload['params']['arguments']['ability_name'] ?? '');
                if ($ability === 'wp-ai-bridge/abilities-read') {
                    $catalogCalls++;

                    return $this->bridgeResponse($request);
                }
                if ($ability === 'demo/write') {
                    $targetCalls++;

                    return Http::failedConnection();
                }
            }

            return $this->bridgeResponse($request);
        });

        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/write', ['value' => 'ambiguous']);

        self::assertFalse($result['ok']);
        self::assertSame('outcome_unknown', $result['error']['code']);
        self::assertSame(1, $catalogCalls);
        self::assertSame(1, $targetCalls);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'wordpress-ability-execute',
            'target_id' => 'alpha',
            'outcome' => 'unknown',
            'error_code' => 'outcome_unknown',
        ]);
    }

    public function test_disconnect_of_one_site_does_not_break_other_site_routing(): void
    {
        $alpha = $this->createSite('alpha');
        $beta = $this->createSite('beta');
        $this->pair($alpha);
        $this->pair($beta);

        app(WpAiBridgeTargetConnectionService::class)->disconnect($alpha);
        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'beta', 'demo/read', []);

        self::assertTrue($result['ok']);
        self::assertSame('beta', $result['result']['target']);
        self::assertSame('Bearer beta-access', $this->toolCalls[array_key_last($this->toolCalls)]['authorization']);
    }

    public function test_catalog_response_size_limit_fails_closed(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        config()->set('bridge.http.max_response_bytes', 1024);
        config()->set('bridge.http.readonly_tool_max_response_bytes', 1024);

        $this->resetHttp();
        Http::fake(function (Request $request) {
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
                return $this->bridgeResponse($request);
            }

            if ($request->method() === 'DELETE') {
                return Http::response('', 200);
            }

            $payload = $request->data();
            if (($payload['method'] ?? null) === 'initialize') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25'],
                ], 200, ['Mcp-Session-Id' => 'session-alpha']);
            }

            return Http::response(str_repeat('x', 2048), 200, ['Content-Type' => 'application/json']);
        });

        Log::spy();
        $result = app(WordpressTargetMcpToolHandlers::class)->read($this->principal, 'alpha', null, 1, 25);

        self::assertFalse($result['ok']);
        self::assertSame('response_too_large', $result['error']['code']);
        self::assertStringNotContainsString(str_repeat('x', 1024), $result['error']['message']);
        self::assertArrayNotHasKey('details', $result['error']);
        self::assertStringNotContainsString(str_repeat('x', 1024), json_encode($result, JSON_THROW_ON_ERROR));
        $reference = $result['error']['diagnostic_reference'] ?? null;
        self::assertTrue(is_string($reference) && Str::isUuid($reference));
        Log::shouldHaveReceived('warning')->withArgs(
            static fn (string $message, array $context): bool => $message === 'Gateway operation failure.'
                && ($context['correlation_id'] ?? null) === $reference
                && ($context['failure_origin'] ?? null) === 'gateway_response'
                && ($context['limit_bytes'] ?? null) === 1024
                && ($context['observed_bytes'] ?? 0) > 1024
                && in_array(($context['response_phase'] ?? null), [
                    'content_length', 'collected_body', 'decoded_body',
                ], true),
        )->once();
    }

    public function test_oversized_mutating_result_is_unknown_and_not_retried(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        config()->set('bridge.http.max_response_bytes', 1024);
        config()->set('bridge.http.readonly_tool_max_response_bytes', 4096);

        $mutationCalls = 0;
        $this->fakeBridge(function (Request $request) use (&$mutationCalls) {
            $payload = $request->data();
            if (($payload['method'] ?? null) === 'tools/call'
                && ($payload['params']['arguments']['ability_name'] ?? null) === 'demo/write') {
                $mutationCalls++;

                return Http::response(str_repeat('secret-mutation-result', 128), 200);
            }

            return $this->bridgeResponse($request);
        });

        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/write', ['value' => 'sensitive']);

        self::assertFalse($result['ok']);
        self::assertSame('outcome_unknown', $result['error']['code']);
        self::assertSame(1, $mutationCalls);
        self::assertStringNotContainsString('secret-mutation-result', json_encode($result, JSON_THROW_ON_ERROR));
    }

    public function test_effect_scoped_decoded_http_limits_account_for_duplicated_mcp_content(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        config()->set('bridge.http.max_response_bytes', 65536);
        config()->set('bridge.http.readonly_tool_max_response_bytes', 262144);

        $dataBytes = 65536;
        $calls = [];
        $this->fakeBridge(function (Request $request) use (&$dataBytes, &$calls) {
            $payload = $request->data();
            $ability = (string) ($payload['params']['arguments']['ability_name'] ?? '');
            if (($payload['method'] ?? null) === 'tools/call'
                && in_array($ability, ['demo/read', 'demo/write'], true)) {
                $calls[] = $ability;
                $data = ['payload' => str_repeat('x', $dataBytes)];
                $structured = ['success' => true, 'data' => $data];

                // The real adapter can echo structuredContent as text. Both
                // copies consume the *decoded HTTP envelope* budget.
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => $payload['id'] ?? null,
                    'result' => [
                        'isError' => false,
                        'structuredContent' => $structured,
                        'content' => [[
                            'type' => 'text',
                            'text' => json_encode($structured, JSON_THROW_ON_ERROR),
                        ]],
                    ],
                ], 200);
            }

            return $this->bridgeResponse($request);
        });

        $read = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/read', []);
        self::assertTrue($read['ok']);
        self::assertSame(65536, strlen($read['result']['payload']));

        $mutation = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/write', ['action' => 'bounded']);
        self::assertSame('outcome_unknown', $mutation['error']['code']);
        self::assertArrayHasKey('diagnostic_reference', $mutation['error']);

        $dataBytes = 131072;
        $oversizeRead = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->principal, 'alpha', 'demo/read', []);
        self::assertSame('response_too_large', $oversizeRead['error']['code']);
        self::assertSame(['demo/read', 'demo/write', 'demo/read'], $calls,
            'An unknown mutation must never be resent to recover a large result.');
        $this->assertDatabaseHas('activity_events', [
            'target_id' => 'alpha', 'operation' => 'wordpress-ability-execute',
            'error_code' => 'outcome_unknown', 'outcome' => 'unknown',
        ]);
    }

    public function test_readonly_ability_result_can_be_larger_than_metadata_budget(): void
    {
        $alpha = $this->createSite('alpha');
        $this->pair($alpha);
        config()->set('bridge.http.max_response_bytes', 1024);
        config()->set('bridge.http.readonly_tool_max_response_bytes', 4096);

        $this->fakeBridge(function (Request $request) {
            $payload = $request->data();
            if (($payload['method'] ?? null) === 'tools/call'
                && ($payload['params']['arguments']['ability_name'] ?? null) === 'demo/read') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => $payload['id'] ?? null,
                    'result' => [
                        'isError' => false,
                        'structuredContent' => [
                            'success' => true,
                            'data' => ['large_read' => str_repeat('x', 2048)],
                        ],
                    ],
                ], 200);
            }

            return $this->bridgeResponse($request);
        });

        $result = app(WordpressTargetMcpToolHandlers::class)->execute($this->principal, 'alpha', 'demo/read', []);
        self::assertTrue($result['ok']);
        self::assertSame(str_repeat('x', 2048), $result['result']['large_read']);
    }

    private function createSite(string $siteId): Target
    {
        return app(WpAiBridgeTargetRegistration::class)->register(
            $siteId, ucfirst($siteId), 'https://'.$siteId.'.example.test',
        );
    }

    private function pair(Target $site): void
    {
        $connections = app(WpAiBridgeTargetConnectionService::class);
        $authorizeUrl = $connections->begin($site);
        parse_str((string) parse_url($authorizeUrl, PHP_URL_QUERY), $query);
        self::assertIsString($query['state'] ?? null);
        $connections->completeCallback((string) $query['state'], $site->target_id.'-code',
            'https://'.$site->target_id.'.example.test', null);
    }

    private function fakeBridge(?callable $override = null): void
    {
        $this->resetHttp();
        Http::fake(fn (Request $request) => $override !== null
            ? $override($request)
            : $this->bridgeResponse($request));
    }

    private function resetHttp(): void
    {
        Http::swap(new Factory);
        Http::preventStrayRequests();
    }

    private function bridgeResponse(Request $request)
    {
        $url = $request->url();
        $host = (string) parse_url($url, PHP_URL_HOST);
        $siteId = (string) strtok($host, '.');
        $base = 'https://'.$host;
        $path = (string) parse_url($url, PHP_URL_PATH);

        if ($path === '/.well-known/oauth-protected-resource') {
            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
                'resource_name' => 'WP AI Bridge',
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
            return Http::response([
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'access_token' => $siteId.'-access',
                'refresh_token' => $siteId.'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }

        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/revoke') {
            return Http::response('', 200);
        }

        if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
            return Http::response(['error' => 'not_found'], 404);
        }

        if ($request->method() === 'DELETE') {
            return Http::response('', 200);
        }

        $payload = $request->data();
        if (($payload['method'] ?? null) === 'initialize') {
            // Real WordPress MCP Adapter validates the required empty object, not [].
            $wire = json_decode($request->body(), false, 64, JSON_THROW_ON_ERROR);
            self::assertInstanceOf(\stdClass::class, $wire->params->capabilities ?? null);
            self::assertSame([], get_object_vars($wire->params->capabilities));
            self::assertSame('Bearer '.$siteId.'-access', $this->requestHeader($request, 'Authorization'));
            self::assertStringContainsString('application/json', $this->requestHeader($request, 'Accept'));

            return Http::response([
                'jsonrpc' => '2.0',
                'id' => 1,
                'result' => [
                    'protocolVersion' => '2025-11-25',
                    'serverInfo' => ['name' => 'wp-ai-bridge', 'version' => 'test'],
                    'capabilities' => ['tools' => (object) []],
                ],
            ], 200, ['Mcp-Session-Id' => 'session-'.$siteId]);
        }

        if (($payload['method'] ?? null) !== 'tools/call') {
            return Http::response([
                'jsonrpc' => '2.0',
                'id' => $payload['id'] ?? null,
                'error' => ['code' => -32601, 'message' => 'Method not found'],
            ], 200);
        }

        self::assertSame('session-'.$siteId, $this->requestHeader($request, 'Mcp-Session-Id'));
        self::assertSame('Bearer '.$siteId.'-access', $this->requestHeader($request, 'Authorization'));
        self::assertSame('mcp-adapter-execute-ability', $payload['params']['name'] ?? null);

        $arguments = $payload['params']['arguments'] ?? [];
        $ability = (string) ($arguments['ability_name'] ?? '');
        $this->toolCalls[] = [
            'host' => $host,
            'ability' => $ability,
            'authorization' => $this->requestHeader($request, 'Authorization'),
        ];

        if ($ability === 'demo/denied') {
            return Http::response([
                'jsonrpc' => '2.0',
                'id' => $payload['id'] ?? null,
                'result' => [
                    'content' => [['type' => 'text', 'text' => 'Permission denied by WordPress.']],
                    'structuredContent' => null,
                    'isError' => true,
                ],
            ], 200);
        }

        if ($ability === 'wp-ai-bridge/abilities-read') {
            $parameters = $arguments['parameters'] ?? [];
            $exact = ($parameters['action'] ?? 'list') === 'get';
            $itemName = $exact ? (string) ($parameters['name'] ?? '') : $siteId.'/demo';
            $item = [
                'name' => $itemName,
                'namespace' => $siteId,
                'label' => ucfirst($siteId).' Demo',
                'description' => 'Site-specific current ability contract.',
                'mcp_type' => 'tool',
                'annotations' => [
                    'readonly' => in_array($itemName, ['demo/read', 'wp-ai-bridge/bridge-info'], true),
                    'destructive' => $itemName === 'demo/delete',
                    'idempotent' => true,
                ],
                'bridge_delegation' => str_starts_with($itemName, 'provider/')
                    ? 'native_abilities'
                    : 'ability_specific',
                'execution_permission' => 'not_evaluated',
            ];
            if ($exact) {
                $item['input_schema'] = ['type' => 'object', 'additionalProperties' => false];
                $item['output_schema'] = ['type' => 'object'];
            }

            $data = [
                'items' => [$item],
                'page' => (int) ($parameters['page'] ?? 1),
                'per_page' => (int) ($parameters['per_page'] ?? 25),
                'total' => 1,
                'total_pages' => 1,
                'execution_permission' => 'not_evaluated',
            ];

            return $this->toolSuccess($data, (int) ($payload['id'] ?? 2));
        }

        if ($ability === 'demo/write') {
            return $this->toolSuccess(['target' => $siteId, 'kind' => 'write', 'updated' => true], (int) ($payload['id'] ?? 2));
        }

        return $this->toolSuccess(['target' => $siteId, 'kind' => 'read'], (int) ($payload['id'] ?? 2));
    }

    private function requestHeader(Request $request, string $name): string
    {
        return (string) ($request->header($name)[0] ?? '');
    }

    private function toolSuccess(mixed $data, int $requestId)
    {
        return Http::response([
            'jsonrpc' => '2.0',
            'id' => $requestId,
            'result' => [
                'content' => [['type' => 'text', 'text' => json_encode(['success' => true, 'data' => $data], JSON_THROW_ON_ERROR)]],
                'structuredContent' => ['success' => true, 'data' => $data],
                'isError' => false,
            ],
        ], 200);
    }
}
