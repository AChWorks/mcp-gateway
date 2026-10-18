<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Mcp\TargetFileInputMcpToolHandlers;
use App\Application\Mcp\WordpressFileInputMcpToolHandlers;
use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Mcp\GatewayMcpEndpoint;
use App\Models\User;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory as HttpClientFactory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

final class WordpressTargetMcpRuntimeTest extends TestCase
{
    use RefreshDatabase;

    /** @var list<array{host:string,ability:string,authorization:string,transaction:int}> */
    private array $downstream = [];

    /** @var list<array{host:string,method:string,session:string}> */
    private array $sessionTraffic = [];

    private bool $pauseDuringCatalog = false;

    private ?string $chatFilePayload = null;

    /** @var array<string, mixed> */
    private array $syntheticPrivateLease = [];

    private bool $syntheticBuilderWriteEnabled = true;

    private bool $syntheticUploadFilesAllowed = true;

    /** @var array<string,mixed> */
    private array $syntheticBeginOverrides = [];

    /** @var array<string,mixed> */
    private array $syntheticVerifyOverrides = [];

    private int $syntheticBeginCount = 0;

    /** @var array<string,array<string,mixed>> */
    private array $syntheticLeases = [];

    /** @var array<string,array<string,mixed>> */
    private array $syntheticCommittedLeases = [];

    private bool $syntheticImportUnknown = false;

    private int $syntheticImportCalls = 0;

    /** @var list<string> */
    private array $syntheticTransferActions = [];

    protected function setUp(): void
    {
        parent::setUp();
        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.name', 'Gateway Test');
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/targets/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');
        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return str_ends_with($host, '.example.test') || $host === 'files.oaiusercontent.com'
                    ? ['1.1.1.1'] : [];
            }
        });
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->bridgeResponse($request));
    }

    public function test_optional_wordpress_timing_tracks_success_with_existing_activity_permissions(): void
    {
        config()->set('bridge.timing.enabled', true);
        config()->set('bridge.timing.minimum_ms', 0);
        $owner = $this->user('owner');
        $this->pair('alpha');

        $result = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'demo/read', []);
        self::assertTrue($result['ok']);

        $stored = DB::table('activity_events')
            ->where('operation', 'wordpress-ability-execute')->first();
        self::assertNotNull($stored);
        $diagnostics = json_decode((string) $stored->diagnostic_context, true, 16, JSON_THROW_ON_ERROR);
        $timing = $diagnostics['timing'];
        self::assertSame(4, $timing['outbound_calls']);
        self::assertSame(0, $timing['curl_observed_calls'], 'Fake HTTP must not invent cURL handshake timings.');
        foreach (['total_ms', 'target_lookup_ms', 'authorization_ms', 'credential_ms',
            'mcp_initialize_ms', 'mcp_classification_ms', 'mcp_execute_ms',
            'mcp_close_ms', 'dns_policy_ms', 'http_transport_ms'] as $key) {
            self::assertArrayHasKey($key, $timing);
            self::assertIsInt($timing[$key]);
            self::assertGreaterThanOrEqual(0, $timing[$key]);
        }
        self::assertStringNotContainsString('alpha-access', (string) $stored->diagnostic_context);
        self::assertStringNotContainsString('example.test', (string) $stored->diagnostic_context);

        $lookup = app(OperationDiagnosticsMcpToolHandlers::class)->read(
            $owner, (string) $stored->correlation_id,
        );
        self::assertTrue($lookup['ok']);
        self::assertSame($timing, $lookup['events'][0]['diagnostics']['timing']);
        self::assertSame('success', $lookup['events'][0]['outcome']);
    }

    public function test_optional_wordpress_timing_is_off_or_below_threshold_without_new_activity_details(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $handler = app(WordpressTargetMcpToolHandlers::class);

        config()->set('bridge.timing.enabled', false);
        self::assertTrue($handler->read($owner, 'alpha', 'demo/read')['ok']);
        config()->set('bridge.timing.enabled', true);
        config()->set('bridge.timing.minimum_ms', 1800000);
        self::assertTrue($handler->read($owner, 'alpha', 'demo/read')['ok']);

        $rows = DB::table('activity_events')->where('operation', 'wordpress-abilities-read')->get();
        self::assertCount(2, $rows);
        foreach ($rows as $row) {
            self::assertNull($row->diagnostic_context);
        }
    }

    public function test_optional_wordpress_timing_retains_failure_without_masking_pause_or_exposing_reference(): void
    {
        config()->set('bridge.timing.enabled', true);
        config()->set('bridge.timing.minimum_ms', 1800000);
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->pauseDuringCatalog = true;

        $result = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'demo/read', []);
        self::assertFalse($result['ok']);
        self::assertSame('target_paused', $result['error']['code']);
        self::assertArrayNotHasKey('diagnostic_reference', $result['error']);
        self::assertSame(['wp-ai-bridge/abilities-read'], array_column($this->downstream, 'ability'));
        self::assertSame('DELETE', $this->sessionTraffic[array_key_last($this->sessionTraffic)]['method']);

        $stored = DB::table('activity_events')
            ->where('operation', 'wordpress-ability-execute')->first();
        self::assertNotNull($stored);
        self::assertSame('target_paused', $stored->error_code);
        $diagnostics = json_decode((string) $stored->diagnostic_context, true, 16, JSON_THROW_ON_ERROR);
        self::assertSame(3, $diagnostics['timing']['outbound_calls']);
        self::assertArrayHasKey('mcp_classification_ms', $diagnostics['timing']);
        self::assertArrayHasKey('mcp_close_ms', $diagnostics['timing']);
        self::assertArrayNotHasKey('mcp_execute_ms', $diagnostics['timing']);
    }

    public function test_exact_target_inventory_read_and_readonly_execution_route_to_the_correct_bearer(): void
    {
        $owner = $this->user('owner');
        $alpha = $this->pair('alpha');
        $beta = $this->pair('beta');
        $baseline = DB::transactionLevel();
        $handlers = app(WordpressTargetMcpToolHandlers::class);

        $catalog = $handlers->read($owner, 'alpha', 'demo/read');
        self::assertTrue($catalog['ok']);
        self::assertSame('demo/read', $catalog['catalog']['items'][0]['name']);
        $readA = $handlers->execute($owner, 'alpha', 'demo/read', ['page' => 1]);
        $readB = $handlers->execute($owner, 'beta', 'demo/read', ['page' => 2]);
        self::assertTrue($readA['ok']);
        self::assertTrue($readB['ok']);
        self::assertSame('alpha.example.test', $readA['result']['host']);
        self::assertSame('beta.example.test', $readB['result']['host']);
        self::assertSame([$alpha->target_id, $beta->target_id], [$readA['target_id'], $readB['target_id']]);
        self::assertSame(['Bearer alpha-access', 'Bearer alpha-access', 'Bearer alpha-access', 'Bearer beta-access', 'Bearer beta-access'],
            array_column($this->downstream, 'authorization'));
        foreach ($this->downstream as $call) {
            self::assertSame($baseline, $call['transaction'], 'WordPress MCP transport ran under a database transaction.');
        }
    }

    public function test_pause_during_wordpress_classification_blocks_final_ability_dispatch(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->pauseDuringCatalog = true;

        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($owner, 'alpha', 'demo/read', []);

        self::assertFalse($result['ok']);
        self::assertSame('target_paused', $result['error']['code']);
        self::assertTrue(Target::query()->where('target_id', 'alpha')->firstOrFail()->operations_paused);
        self::assertSame(['wp-ai-bridge/abilities-read'], array_column($this->downstream, 'ability'));
        self::assertSame('DELETE', $this->sessionTraffic[array_key_last($this->sessionTraffic)]['method']);
    }

    public function test_execute_uses_one_legacy_session_for_classification_and_execution_then_closes_it(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->sessionTraffic = [];

        $result = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'demo/read', []);
        self::assertTrue($result['ok']);
        self::assertSame(
            ['initialize', 'tools/call', 'tools/call', 'DELETE'],
            array_column($this->sessionTraffic, 'method'),
        );
        self::assertSame(['', 'test-session', 'test-session', 'test-session'],
            array_column($this->sessionTraffic, 'session'));
        self::assertSame(['wp-ai-bridge/abilities-read', 'demo/read'],
            array_slice(array_column($this->downstream, 'ability'), -2));
    }

    public function test_selected_group_execution_has_bounded_membership_queries_and_keeps_denials(): void
    {
        $operator = $this->user('operator');
        $target = $this->pair('alpha');
        $group = TargetGroup::query()->create(['name' => 'Authorized operators']);
        $group->users()->attach($operator->getKey());
        $group->targets()->attach($target->getKey());

        $queries = [];
        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });
        $handlers = app(WordpressTargetMcpToolHandlers::class);
        self::assertTrue($handlers->execute($operator, 'alpha', 'demo/read', [])['ok']);
        $membershipQueries = array_filter($queries, static fn (string $sql): bool => str_contains($sql, 'target_group_users'));
        self::assertLessThanOrEqual(2, count($membershipQueries),
            'One Ability execution must not repeat group membership SQL per execution permission.');

        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
        ]);
        $outboundBefore = count($this->downstream);
        $denied = $handlers->execute($operator, 'alpha', 'demo/read', []);
        self::assertSame('forbidden', $denied['error']['code']);
        self::assertSame(['wp-ai-bridge/abilities-read'],
            array_slice(array_column($this->downstream, 'ability'), $outboundBefore));

        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => false,
        ]);
        $outboundBefore = count($this->downstream);
        self::assertSame('target_not_found', $handlers->execute($operator, 'alpha', 'demo/read', [])['error']['code']);
        self::assertCount($outboundBefore, $this->downstream);
    }

    public function test_enabled_timing_omits_pre_dispatch_rejection_details_and_references(): void
    {
        config()->set('bridge.timing.enabled', true);
        config()->set('bridge.timing.minimum_ms', 0);
        $owner = $this->user('owner');
        $target = $this->pair('alpha');
        $handler = app(WordpressTargetMcpToolHandlers::class);

        $notFound = $handler->read($owner, 'missing-target');
        self::assertSame('target_not_found', $notFound['error']['code']);

        $invalid = $handler->read($owner, 'alpha', per_page: 101);
        self::assertSame('invalid_input', $invalid['error']['code']);

        $operator = $this->user('operator');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);
        foreach ([
            GatewayPermission::WordpressAbilitiesExecuteReadonly,
            GatewayPermission::WordpressAbilitiesExecuteMutating,
            GatewayPermission::WordpressAbilitiesExecuteDestructive,
            GatewayPermission::WordpressAbilitiesExecuteUnclassified,
        ] as $permission) {
            DB::table('user_permission_denials')->insert([
                'user_id' => $operator->getKey(),
                'permission' => $permission->value,
            ]);
        }
        $forbidden = $handler->execute($operator, 'alpha', 'demo/read', []);
        self::assertSame('forbidden', $forbidden['error']['code']);

        Target::query()->where('target_id', 'alpha')->update(['operations_paused' => true]);
        $paused = $handler->read($owner, 'alpha');
        self::assertSame('target_paused', $paused['error']['code']);

        foreach ([$notFound, $invalid, $forbidden, $paused] as $result) {
            self::assertArrayNotHasKey('diagnostic_reference', $result['error']);
        }

        $rows = DB::table('activity_events')->whereIn('error_code', [
            'target_not_found', 'invalid_input', 'forbidden', 'target_paused',
        ])->get();
        self::assertCount(4, $rows);
        foreach ($rows as $row) {
            self::assertNull($row->diagnostic_context, 'Pre-dispatch rejection must not include timing data.');
        }
        self::assertSame([], $this->downstream);
    }

    public function test_target_scope_and_execution_class_denials_do_not_leak_or_send_unauthorized_requests(): void
    {
        $operator = $this->user('operator');
        $alpha = $this->pair('alpha');
        $this->pair('beta');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $alpha->getKey(),
            'allowed' => true,
        ]);
        $handlers = app(WordpressTargetMcpToolHandlers::class);
        $baseline = count($this->downstream);

        self::assertSame('target_not_found', $handlers->read($operator, 'beta')['error']['code']);
        self::assertSame('target_not_found', $handlers->execute($operator, 'beta', 'demo/read', [])['error']['code']);
        self::assertSame('target_not_found', $handlers->execute($operator, '../alpha', 'demo/read', [])['error']['code']);
        self::assertSame('invalid_input', $handlers->read($operator, 'alpha', per_page: 101)['error']['code']);
        self::assertSame('invalid_input', $handlers->execute($operator, 'alpha', 'demo/read', ['large' => str_repeat('x', 262144)])['error']['code']);
        self::assertCount($baseline, $this->downstream);

        self::assertTrue($handlers->execute($operator, 'alpha', 'demo/read', [])['ok']);
        $rejected = $handlers->execute($operator, 'alpha', 'demo/destroy', []);
        self::assertFalse($rejected['ok']);
        self::assertSame('forbidden', $rejected['error']['code']);
        self::assertSame(['wp-ai-bridge/abilities-read', 'demo/read', 'wp-ai-bridge/abilities-read'],
            array_slice(array_column($this->downstream, 'ability'), $baseline));

        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
        ]);
        $blocked = $handlers->execute($operator, 'alpha', 'demo/read', []);
        self::assertSame('forbidden', $blocked['error']['code']);
        self::assertStringNotContainsString('alpha-access', json_encode($blocked, JSON_THROW_ON_ERROR));
    }

    public function test_failed_ability_catalog_does_not_fall_back_to_unclassified_execution(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $handler = app(WordpressTargetMcpToolHandlers::class);

        foreach (['server_failure', 'network_failure', 'downstream_auth'] as $failure) {
            $executed = [];
            $this->downstream = [];
            // The setUp fake is catch-all; using fake() again only appends a
            // callback. Replace the factory so this test's failures are real.
            Http::swap(new HttpClientFactory);
            Http::preventStrayRequests();
            // Http::failedConnection() returns a deferred fake Closure,
            // unlike Http::response() which returns a PromiseInterface.
            Http::fake(function (Request $request) use ($failure, &$executed) {
                $payload = $request->data();
                $ability = $payload['params']['arguments']['ability_name'] ?? null;
                if (($payload['method'] ?? null) === 'tools/call') {
                    $executed[] = $ability;
                }
                if ($ability === 'wp-ai-bridge/abilities-read') {
                    return match ($failure) {
                        'server_failure' => Http::response(['error' => 'unavailable'], 503),
                        'network_failure' => Http::failedConnection(),
                        'downstream_auth' => Http::response(['error' => 'unauthorized'], 401),
                    };
                }

                return $this->bridgeResponse($request);
            });

            $result = $handler->execute($owner, 'alpha', 'demo/read', []);
            self::assertFalse($result['ok'], 'Failure case: '.$failure);
            self::assertSame(match ($failure) {
                'server_failure' => 'protocol_error',
                'network_failure' => 'network_failure',
                'downstream_auth' => 'downstream_auth',
            }, $result['error']['code']);
            self::assertSame(['wp-ai-bridge/abilities-read'], $executed,
                'Catalog errors must not use the unclassified execution permission as an escape hatch.');
            self::assertStringNotContainsString('alpha-access', json_encode($result, JSON_THROW_ON_ERROR));
        }
    }

    public function test_successful_catalog_with_missing_effect_annotations_preserves_explicit_unclassified_grant(): void
    {
        $administrator = $this->user('administrator');
        $target = $this->pair('alpha');
        DB::table('user_target_access')->insert([
            'user_id' => $administrator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);
        $executed = [];
        Http::swap(new HttpClientFactory);
        Http::preventStrayRequests();
        Http::fake(function (Request $request) use (&$executed): PromiseInterface {
            $payload = $request->data();
            $ability = $payload['params']['arguments']['ability_name'] ?? null;
            if ($ability === 'wp-ai-bridge/abilities-read') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => $payload['id'],
                    'result' => [
                        'isError' => false,
                        'structuredContent' => [
                            'success' => true,
                            'data' => ['items' => [[
                                'name' => 'plugin/new-ability',
                                'mcp_type' => 'tool',
                                'bridge_delegation' => 'ability_specific',
                            ]]],
                        ],
                    ],
                ], 200);
            }
            if ($ability !== null) {
                $executed[] = $ability;
            }

            return $this->bridgeResponse($request);
        });
        $handler = app(WordpressTargetMcpToolHandlers::class);
        $success = $handler->execute($administrator, 'alpha', 'plugin/new-ability', []);
        self::assertTrue($success['ok']);
        self::assertSame(['plugin/new-ability'], $executed);

        DB::table('user_permission_denials')->insert([
            'user_id' => $administrator->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteUnclassified->value,
        ]);
        $blocked = $handler->execute($administrator, 'alpha', 'plugin/new-ability', []);
        self::assertFalse($blocked['ok']);
        self::assertSame('forbidden', $blocked['error']['code']);
        self::assertSame(['plugin/new-ability'], $executed);
    }

    public function test_public_gateway_tool_manifest_contains_wp_and_ssh_without_unsupported_connectors(): void
    {
        $owner = $this->user('owner');
        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        self::assertIsString($host);
        $endpoint = app(GatewayMcpEndpoint::class);
        $headers = [
            'HTTP_HOST' => $host,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_MCP_PROTOCOL_VERSION' => '2025-11-25',
        ];

        $initialize = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize',
            'params' => [
                'protocolVersion' => '2025-11-25',
                'capabilities' => (object) [],
                'clientInfo' => ['name' => 'WordPress Target test', 'version' => '1.0'],
            ],
        ], JSON_THROW_ON_ERROR));
        $initialize->attributes->set('oauth_user', $owner);
        $initialized = $endpoint->handle($initialize);
        self::assertSame(200, $initialized->getStatusCode());
        $session = $initialized->headers->get('Mcp-Session-Id');
        self::assertNotEmpty($session);

        $headers['HTTP_MCP_SESSION_ID'] = $session;
        $request = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/list', 'params' => (object) [],
        ], JSON_THROW_ON_ERROR));
        $request->attributes->set('oauth_user', $owner);
        $response = $endpoint->handle($request);
        self::assertSame(200, $response->getStatusCode());

        // MCP transport returns a streamed response; getContent() is empty.
        ob_start();
        $response->sendContent();
        $body = (string) ob_get_clean();
        $document = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        $names = array_column($document['result']['tools'], 'name');
        foreach (['targets-list', 'target-context', 'wordpress-abilities-read', 'wordpress-ability-execute', 'wordpress-file-input', 'target-file-input', 'ssh-command-run', 'ssh-file-stat', 'ssh-file-list', 'ssh-file-read', 'ssh-file-write'] as $name) {
            self::assertContains($name, $names);
        }
        foreach (['site-ability-execute', 'agent-run-command'] as $name) {
            self::assertNotContains($name, $names);
        }
        $fileInput = collect($document['result']['tools'])->firstWhere('name', 'wordpress-file-input');
        self::assertSame(['file'], $fileInput['_meta']['openai/fileParams']);
        self::assertSame(['download_url', 'file_id'], $fileInput['inputSchema']['properties']['file']['required']);
        self::assertArrayNotHasKey('import_to_media', $fileInput['inputSchema']['properties']);
        self::assertFalse($fileInput['inputSchema']['additionalProperties']);
        self::assertSame(['download_url', 'file_id', 'mime_type', 'file_name'],
            array_keys($fileInput['inputSchema']['properties']['file']['properties']));
        self::assertFalse($fileInput['annotations']['readOnlyHint']);
        self::assertTrue($fileInput['annotations']['destructiveHint']);
        $genericFile = collect($document['result']['tools'])->firstWhere('name', 'target-file-input');
        self::assertSame(['file'], $genericFile['_meta']['openai/fileParams']);
        self::assertSame($fileInput['inputSchema']['properties']['file'],
            $genericFile['inputSchema']['properties']['file']);
        self::assertSame(['wordpress_media_stage', 'ssh_sftp_upload'],
            $genericFile['inputSchema']['properties']['mode']['enum']);
        $ssh = collect($document['result']['tools'])->firstWhere('name', 'ssh-command-run');
        self::assertSame(8192, $ssh['inputSchema']['properties']['command']['maxLength']);
        self::assertSame(15, $ssh['inputSchema']['properties']['timeout_seconds']['maximum']);

        app(OperationalSettings::class)->save($owner, [
            'wp_response_kib' => null,
            'wp_readonly_response_kib' => null,
            'wp_connect_timeout_seconds' => null,
            'wp_request_timeout_seconds' => null,
            'ssh_transfer_max_kib' => null,
            'ssh_transfer_max_seconds' => null,
            'ssh_command_timeout_seconds' => 30,
            'ssh_command_max_kib' => 64,
        ], 0);
        // An entirely new request/endpoint reads the effective Owner limits
        // without application restart or another release.
        $updatedRequest = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 3, 'method' => 'tools/list', 'params' => (object) [],
        ], JSON_THROW_ON_ERROR));
        $updatedRequest->attributes->set('oauth_user', $owner);
        $updatedResponse = app(GatewayMcpEndpoint::class)->handle($updatedRequest);
        self::assertSame(200, $updatedResponse->getStatusCode());
        ob_start();
        $updatedResponse->sendContent();
        $updatedBody = (string) ob_get_clean();
        $updatedDocument = json_decode($updatedBody, true, 32, JSON_THROW_ON_ERROR);
        $updatedSsh = collect($updatedDocument['result']['tools'])->firstWhere('name', 'ssh-command-run');
        self::assertSame(65536, $updatedSsh['inputSchema']['properties']['command']['maxLength']);
        self::assertSame(30, $updatedSsh['inputSchema']['properties']['timeout_seconds']['maximum']);
    }

    public function test_chatgpt_file_input_stages_complete_exact_bytes_without_native_media_effect(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = str_repeat("synthetic-binary\0\xff", 5000);
        $file = [
            'download_url' => 'https://files.oaiusercontent.com/private/file_abc?sig=signed%2Fopaque%3D&expires=123',
            'file_id' => 'file_abc', 'file_name' => 'synthetic.png', 'mime_type' => 'image/png',
        ];
        $result = app(WordpressFileInputMcpToolHandlers::class)->receive($owner, 'alpha', $file);
        self::assertTrue($result['ok'], json_encode($result, JSON_THROW_ON_ERROR));
        self::assertSame('verified_private_transfer', $result['state']);
        self::assertSame(str_repeat('a', 64), $result['transfer_id']);
        self::assertSame(strlen($this->chatFilePayload), $result['bytes']);
        self::assertSame(hash('sha256', $this->chatFilePayload), $result['sha256']);
        self::assertSame($this->chatFilePayload, $this->syntheticPrivateLease['payload']);
        self::assertSame(0, $this->syntheticImportCalls);
        self::assertSame(['limits', 'begin', 'append', 'append', 'verify'], $this->syntheticTransferActions);
        self::assertSame([
            'wp-ai-bridge/private-transfer', 'wp-ai-bridge/bridge-info', 'wp-ai-bridge/site-context',
        ], array_slice(array_values(array_unique(array_column($this->downstream, 'ability'))), 1, 3));
    }

    public function test_file_input_replay_after_lost_response_cannot_republish_native_media(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'repeated-opaque-file-content';
        $file = [
            'download_url' => 'https://files.oaiusercontent.com/private/file_abc?sig=valid',
            'file_id' => 'file_abc', 'file_name' => 'same.png',
        ];
        $fileInput = app(WordpressFileInputMcpToolHandlers::class);
        $first = $fileInput->receive($owner, 'alpha', $file);
        self::assertTrue($first['ok']);
        self::assertSame(0, $this->syntheticImportCalls);
        $firstId = $first['transfer_id'];

        // Different, explicitly authorized native step; simulate a successful
        // Bridge commit whose response is lost to the caller.
        $this->syntheticImportUnknown = true;
        $unknown = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'wp-ai-bridge/transfer-media-import', [
            'transfer_id' => $firstId, 'filename' => 'same.png',
        ]);
        self::assertFalse($unknown['ok']);
        self::assertSame(1, $this->syntheticImportCalls);
        $this->syntheticImportUnknown = false;
        $status = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'wp-ai-bridge/private-transfer', [
            'action' => 'status', 'transfer_id' => $firstId,
        ]);
        self::assertTrue($status['ok']);
        self::assertSame($firstId, $status['result']['transfer_id']);
        self::assertSame('committed', $status['result']['state']);
        $this->pair('beta');
        $crossTarget = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'beta', 'wp-ai-bridge/transfer-media-import', [
            'transfer_id' => $firstId, 'filename' => 'same.png',
        ]);
        self::assertFalse($crossTarget['ok'], 'A different WordPress OAuth Target must not consume the other Target lease.');
        self::assertSame(1, $this->syntheticImportCalls);
        $sameLeaseReplay = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'wp-ai-bridge/transfer-media-import', [
            'transfer_id' => $firstId, 'filename' => 'same.png',
        ]);
        self::assertFalse($sameLeaseReplay['ok'], 'An immutable Bridge claim must block another native effect.');
        self::assertSame(1, $this->syntheticImportCalls);

        // Simulate a client repeating the entire top-level file-input request.
        // The only second effect is a new expiring, unpublished private lease.
        $second = $fileInput->receive($owner, 'alpha', $file);
        self::assertTrue($second['ok']);
        self::assertNotSame($firstId, $second['transfer_id']);
        self::assertSame(2, $this->syntheticBeginCount);
        self::assertSame(1, $this->syntheticImportCalls);

        // A distinct new, explicit native import remains possible, and the
        // original immutable Bridge claim is not bypassed by file-input.
        $separate = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'wp-ai-bridge/transfer-media-import', [
            'transfer_id' => $second['transfer_id'], 'filename' => 'same.png',
        ]);
        self::assertTrue($separate['ok']);
        self::assertSame('committed', $separate['result']['state']);
        self::assertSame($second['transfer_id'], $separate['result']['transfer_id']);
        self::assertSame(2, $this->syntheticImportCalls);
        $originalStillCommitted = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'wp-ai-bridge/private-transfer', [
            'action' => 'status', 'transfer_id' => $firstId,
        ]);
        self::assertTrue($originalStillCommitted['ok']);
        self::assertSame('committed', $originalStillCommitted['result']['state']);
        $originalReplayAfterNew = app(WordpressTargetMcpToolHandlers::class)->execute($owner, 'alpha', 'wp-ai-bridge/transfer-media-import', [
            'transfer_id' => $firstId, 'filename' => 'same.png',
        ]);
        self::assertFalse($originalReplayAfterNew['ok']);
        self::assertSame(2, $this->syntheticImportCalls);
    }

    public function test_chatgpt_file_parameter_invalid_begin_receipts_never_report_success(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'begin-receipt-check';
        $file = ['download_url' => 'https://files.oaiusercontent.com/private/file?sig=x', 'file_id' => 'file'];
        $handler = app(WordpressFileInputMcpToolHandlers::class);
        foreach ([
            ['purpose' => 'text'], ['total_bytes' => 987], ['sha256' => str_repeat('0', 64)],
            ['state' => 'committed'], ['received_bytes' => 1], ['action' => 'verify'],
        ] as $fault) {
            $this->syntheticBeginOverrides = $fault;
            $result = $handler->receive($owner, 'alpha', $file);
            self::assertFalse($result['ok'], json_encode($fault, JSON_THROW_ON_ERROR));
            self::assertSame('transfer_receipt_unknown', $result['error']['code']);
            self::assertFalse($result['error']['retry_safe']);
            self::assertSame($this->syntheticPrivateLease['id'], $result['error']['transfer_id']);
            self::assertSame(0, $this->syntheticImportCalls);
        }
        $this->syntheticBeginOverrides = [];
    }

    public function test_chatgpt_file_parameter_malformed_begin_lease_id_is_nonretryable(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'admission-with-malformed-lease-id';
        $this->syntheticBeginOverrides = ['transfer_id' => 'bad-lease-id'];
        $result = app(WordpressFileInputMcpToolHandlers::class)->receive($owner, 'alpha', [
            'download_url' => 'https://files.oaiusercontent.com/private/x?sig=y', 'file_id' => 'file_id',
        ]);
        self::assertFalse($result['ok']);
        self::assertSame('transfer_receipt_unknown', $result['error']['code']);
        self::assertArrayNotHasKey('transfer_id', $result['error']);
        self::assertFalse($result['error']['retry_safe']);
        self::assertSame(1, $this->syntheticBeginCount);
        self::assertSame(['limits', 'begin'], $this->syntheticTransferActions);
        self::assertSame(0, $this->syntheticImportCalls);
    }

    public function test_chatgpt_file_parameter_invalid_verify_receipts_never_report_success(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'verify-receipt-check';
        $file = ['download_url' => 'https://files.oaiusercontent.com/private/file?sig=x', 'file_id' => 'file'];
        $handler = app(WordpressFileInputMcpToolHandlers::class);
        foreach ([
            ['transfer_id' => str_repeat('f', 64)], ['purpose' => 'text'],
            ['total_bytes' => 99], ['received_bytes' => 99], ['sha256' => str_repeat('0', 64)],
            ['state' => 'committed'], ['complete' => false], ['action' => 'status'],
        ] as $fault) {
            $this->syntheticVerifyOverrides = $fault;
            $result = $handler->receive($owner, 'alpha', $file);
            self::assertFalse($result['ok'], json_encode($fault, JSON_THROW_ON_ERROR));
            self::assertSame('transfer_integrity_unknown', $result['error']['code']);
            self::assertFalse($result['error']['retry_safe']);
            self::assertSame($this->syntheticPrivateLease['id'], $result['error']['transfer_id']);
            self::assertSame(0, $this->syntheticImportCalls);
        }
        $this->syntheticVerifyOverrides = [];
    }

    public function test_chatgpt_file_parameter_builder_write_disabled_denies_before_http_download(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'never-download-private';
        $this->syntheticBuilderWriteEnabled = false;
        $result = app(WordpressFileInputMcpToolHandlers::class)->receive($owner, 'alpha', [
            'download_url' => 'https://files.oaiusercontent.com/private/file_abc?sig=valid', 'file_id' => 'file_abc',
        ]);
        self::assertSame('media_permission_denied', $result['error']['code']);
        self::assertSame(['limits'], $this->syntheticTransferActions);
        self::assertSame(0, $this->syntheticBeginCount);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
    }

    public function test_chatgpt_file_parameter_upload_capability_denied_before_http_download(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'never-download-private';
        $this->syntheticUploadFilesAllowed = false;
        $result = app(WordpressFileInputMcpToolHandlers::class)->receive($owner, 'alpha', [
            'download_url' => 'https://files.oaiusercontent.com/private/file_abc?sig=valid', 'file_id' => 'file_abc',
        ]);
        self::assertSame('media_permission_denied', $result['error']['code']);
        self::assertSame(['limits'], $this->syntheticTransferActions);
        self::assertSame(0, $this->syntheticBeginCount);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
    }

    public function test_chatgpt_file_parameter_gateway_destructive_permission_denied_before_http_download(): void
    {
        $owner = $this->user('administrator');
        $target = $this->pair('alpha');
        DB::table('user_target_access')->insert([
            'user_id' => $owner->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        $this->chatFilePayload = 'never-download-private';
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $owner->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteDestructive->value,
        ]);
        $result = app(WordpressFileInputMcpToolHandlers::class)->receive($owner, 'alpha', [
            'download_url' => 'https://files.oaiusercontent.com/private/file_abc?sig=valid', 'file_id' => 'file_abc',
        ]);
        self::assertFalse($result['ok']);
        self::assertSame('limits', $result['error']['phase']);
        self::assertSame(0, $this->syntheticBeginCount);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
    }

    public function test_chatgpt_file_parameter_gateway_readonly_permission_denied_before_http_download(): void
    {
        $owner = $this->user('administrator');
        $target = $this->pair('alpha');
        DB::table('user_target_access')->insert([
            'user_id' => $owner->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        $this->chatFilePayload = 'never-download-private';
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $owner->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
        ]);
        $result = app(WordpressFileInputMcpToolHandlers::class)->receive($owner, 'alpha', [
            'download_url' => 'https://files.oaiusercontent.com/private/file_abc?sig=valid', 'file_id' => 'file_abc',
        ]);
        self::assertFalse($result['ok']);
        self::assertSame('media_group_preflight', $result['error']['phase']);
        self::assertSame(0, $this->syntheticBeginCount);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
    }

    public function test_chatgpt_file_parameter_paused_or_revoked_target_does_not_download(): void
    {
        $owner = $this->user('owner');
        $target = $this->pair('alpha');
        $this->chatFilePayload = 'should-stay-private';
        $file = ['download_url' => 'https://files.oaiusercontent.com/private/opaque?sig=x', 'file_id' => 'opaque'];
        $handler = app(WordpressFileInputMcpToolHandlers::class);
        $target->forceFill(['operations_paused' => true])->save();
        $paused = $handler->receive($owner, 'alpha', $file);
        self::assertFalse($paused['ok']);
        self::assertSame('limits', $paused['error']['phase']);
        $target->forceFill(['operations_paused' => false])->save();
        $owner->forceFill(['access_enabled' => false])->save();
        $revoked = $handler->receive($owner, 'alpha', $file);
        self::assertFalse($revoked['ok']);
        self::assertSame('limits', $revoked['error']['phase']);
        self::assertSame(0, $this->syntheticBeginCount);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
    }

    public function test_mcp_tool_schema_rejects_removed_inline_native_import_switch(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'must-not-publish';
        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        self::assertIsString($host);
        $request = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], [
            'HTTP_HOST' => $host,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_MCP_PROTOCOL_VERSION' => '2026-07-28',
            'HTTP_MCP_METHOD' => 'tools/call',
            'HTTP_MCP_NAME' => 'wordpress-file-input',
        ], json_encode([
            'jsonrpc' => '2.0', 'id' => 45, 'method' => 'tools/call',
            'params' => [
                'name' => 'wordpress-file-input',
                'arguments' => [
                    'target_id' => 'alpha',
                    'file' => [
                        'download_url' => 'https://files.oaiusercontent.com/private/file?sig=x',
                        'file_id' => 'file',
                    ],
                    'import_to_media' => true,
                ],
                '_meta' => [
                    'io.modelcontextprotocol/protocolVersion' => '2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities' => (object) [],
                    'io.modelcontextprotocol/clientInfo' => ['name' => 'extra-field-rejected', 'version' => '1.0'],
                ],
            ],
        ], JSON_THROW_ON_ERROR));
        $request->attributes->set('oauth_user', $owner);
        $response = app(GatewayMcpEndpoint::class)->handle($request);
        self::assertSame(400, $response->getStatusCode(), 'Unexpected extra import field must be rejected by the actual MCP tool schema.');
        ob_start();
        $response->sendContent();
        $result = json_decode((string) ob_get_clean(), true, 32, JSON_THROW_ON_ERROR);
        self::assertTrue(($result['result']['isError'] ?? false) === true || isset($result['error']), json_encode($result, JSON_THROW_ON_ERROR));
        self::assertSame(0, $this->syntheticBeginCount);
        self::assertSame(0, $this->syntheticImportCalls);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
    }

    public function test_chatgpt_file_parameter_invalid_inputs_and_wrong_target_do_not_fetch_file(): void
    {
        $owner = $this->user('owner');
        $this->chatFilePayload = 'must-not-fetch';
        $handler = app(WordpressFileInputMcpToolHandlers::class);
        $file = [
            'download_url' => 'https://files.oaiusercontent.com/private/file_abc?sig=valid',
            'file_id' => 'file_abc', 'file_name' => 'safe.png',
        ];
        $missing = $handler->receive($owner, 'unknown', $file);
        self::assertFalse($missing['ok']);
        self::assertSame('limits', $missing['error']['phase']);
        $invalid = $handler->receive($owner, 'unknown', [
            ...$file, 'download_url' => 'https://evil.example.test/internal',
        ]);
        self::assertSame('invalid_file_input', $invalid['error']['code']);
        $unsafe = $handler->receive($owner, 'unknown', [...$file, 'file_name' => '../evil.png']);
        self::assertSame('invalid_filename', $unsafe['error']['code']);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
        self::assertSame(0, $this->syntheticImportCalls);
    }

    public function test_target_file_input_wordpress_accepts_binary_larger_than_old_256_kib_limit(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        config()->set('bridge.file_input.max_bytes', 1048576);
        $this->chatFilePayload = str_repeat("\x00\xff\xa1", 100000);
        $result = app(TargetFileInputMcpToolHandlers::class)->receive(
            $owner, 'alpha', [
                'download_url' => 'https://files.oaiusercontent.com/private/large?sig=opaque',
                'file_id' => 'file_binary',
            ], 'wordpress_media_stage',
        );
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame(300000, $result['bytes']);
        self::assertSame(hash('sha256', $this->chatFilePayload), $result['sha256']);
        self::assertSame($this->chatFilePayload, $this->syntheticPrivateLease['payload']);
        self::assertSame(0, $this->syntheticImportCalls);
    }

    public function test_target_file_input_denies_ssh_mode_and_untrusted_destination_without_fetch(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $file = [
            'download_url' => 'https://files.oaiusercontent.com/private/file?sig=x',
            'file_id' => 'file_test',
        ];
        $handler = app(TargetFileInputMcpToolHandlers::class);
        config()->set('ssh.file_transfer.enabled', false);
        $unsupported = $handler->receive($owner, 'alpha', $file, 'ssh_sftp_upload', [
            'path' => '/home/user/test.bin', 'private_staging_dir' => '/home/user/.private',
        ]);
        self::assertSame('unsupported_mode', $unsupported['error']['code']);

        config()->set('ssh.file_transfer.enabled', true);
        $wrongTarget = $handler->receive($owner, 'alpha', $file, 'ssh_sftp_upload', [
            'path' => '/home/user/test.bin', 'private_staging_dir' => '/home/user/.private',
        ]);
        self::assertSame('target_not_found', $wrongTarget['error']['code']);
        $missing = $handler->receive($owner, 'alpha', $file, 'ssh_sftp_upload', [
            'path' => '../unsafe', 'private_staging_dir' => '/home/user/.private',
        ]);
        self::assertSame('invalid_destination', $missing['error']['code']);
        $mixedMode = $handler->receive($owner, 'alpha', $file, 'wordpress_media_stage', [
            'path' => '/home/user/test.bin', 'private_staging_dir' => '/home/user/.private',
        ]);
        self::assertSame('invalid_destination', $mixedMode['error']['code']);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'files.oaiusercontent.com'));
        self::assertSame(0, $this->syntheticBeginCount);
    }

    public function test_chatgpt_file_input_oversized_download_does_not_allocate_private_lease(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        config()->set('bridge.file_input.max_bytes', 300000);
        $this->chatFilePayload = str_repeat('x', 300001);
        $result = app(WordpressFileInputMcpToolHandlers::class)->receive($owner, 'alpha', [
            'download_url' => 'https://files.oaiusercontent.com/private/huge?sig=short-lived',
            'file_id' => 'file_huge', 'file_name' => 'oversized.pdf',
        ]);
        self::assertFalse($result['ok']);
        self::assertSame('response_too_large', $result['error']['code']);
        self::assertSame(['limits'], $this->syntheticTransferActions);
        self::assertSame([], $this->syntheticPrivateLease);
        self::assertSame(0, $this->syntheticImportCalls);
    }

    public function test_chatgpt_file_input_executes_through_real_mcp_tool_dispatch(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'small-real-mcp-tool-dispatch';
        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        self::assertIsString($host);
        $request = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], [
            'HTTP_HOST' => $host,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_MCP_PROTOCOL_VERSION' => '2026-07-28',
            'HTTP_MCP_METHOD' => 'tools/call',
            'HTTP_MCP_NAME' => 'wordpress-file-input',
        ], json_encode([
            'jsonrpc' => '2.0', 'id' => 44, 'method' => 'tools/call',
            'params' => [
                'name' => 'wordpress-file-input',
                'arguments' => [
                    'target_id' => 'alpha',
                    'file' => [
                        'download_url' => 'https://files.oaiusercontent.com/private/abc?sig=short-lived',
                        'file_id' => 'file_abc',
                    ],
                ],
                '_meta' => [
                    'io.modelcontextprotocol/protocolVersion' => '2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities' => (object) [],
                    'io.modelcontextprotocol/clientInfo' => ['name' => 'file-param-test', 'version' => '1.0'],
                ],
            ],
        ], JSON_THROW_ON_ERROR));
        $request->attributes->set('oauth_user', $owner);
        $response = app(GatewayMcpEndpoint::class)->handle($request);
        self::assertSame(200, $response->getStatusCode());
        ob_start();
        $response->sendContent();
        $json = json_decode((string) ob_get_clean(), true, 32, JSON_THROW_ON_ERROR);
        self::assertFalse($json['result']['isError'] ?? false, json_encode($json, JSON_THROW_ON_ERROR));
        $received = $json['result']['structuredContent'];
        self::assertTrue($received['ok']);
        self::assertSame('verified_private_transfer', $received['state']);
        self::assertSame(hash('sha256', $this->chatFilePayload), $received['sha256']);
        self::assertSame($this->chatFilePayload, $this->syntheticPrivateLease['payload']);
        self::assertSame(0, $this->syntheticImportCalls);
    }

    public function test_target_file_input_executes_through_real_mcp_tool_dispatch(): void
    {
        $owner = $this->user('owner');
        $this->pair('alpha');
        $this->chatFilePayload = 'small-real-mcp-tool-dispatch';
        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        self::assertIsString($host);
        $request = \Illuminate\Http\Request::create('/mcp', 'POST', [], [], [], [
            'HTTP_HOST' => $host,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_MCP_PROTOCOL_VERSION' => '2026-07-28',
            'HTTP_MCP_METHOD' => 'tools/call',
            'HTTP_MCP_NAME' => 'target-file-input',
        ], json_encode([
            'jsonrpc' => '2.0', 'id' => 44, 'method' => 'tools/call',
            'params' => [
                'name' => 'target-file-input',
                'arguments' => [
                    'target_id' => 'alpha',
                    'mode' => 'wordpress_media_stage',
                    'file' => [
                        'download_url' => 'https://files.oaiusercontent.com/private/abc?sig=short-lived',
                        'file_id' => 'file_abc',
                    ],
                ],
                '_meta' => [
                    'io.modelcontextprotocol/protocolVersion' => '2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities' => (object) [],
                    'io.modelcontextprotocol/clientInfo' => ['name' => 'file-param-test', 'version' => '1.0'],
                ],
            ],
        ], JSON_THROW_ON_ERROR));
        $request->attributes->set('oauth_user', $owner);
        $response = app(GatewayMcpEndpoint::class)->handle($request);
        self::assertSame(200, $response->getStatusCode());
        ob_start();
        $response->sendContent();
        $json = json_decode((string) ob_get_clean(), true, 32, JSON_THROW_ON_ERROR);
        self::assertFalse($json['result']['isError'] ?? false, json_encode($json, JSON_THROW_ON_ERROR));
        $received = $json['result']['structuredContent'];
        self::assertTrue($received['ok']);
        self::assertSame('verified_private_transfer', $received['state']);
        self::assertSame(hash('sha256', $this->chatFilePayload), $received['sha256']);
        self::assertSame($this->chatFilePayload, $this->syntheticPrivateLease['payload']);
        self::assertSame(0, $this->syntheticImportCalls);
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => 'WordPress '.$role,
            'email' => Str::random(14).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ], []);
    }

    private function pair(string $name): Target
    {
        $target = app(WpAiBridgeTargetRegistration::class)
            ->register($name, 'WP '.$name, 'https://'.$name.'.example.test');
        $connections = app(WpAiBridgeTargetConnectionService::class);
        $url = $connections->begin($target);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $connections->completeCallback((string) $query['state'], $name.'-code',
            'https://'.$name.'.example.test', null);

        return $target;
    }

    /** @param array<string, mixed> $parameters
     * @return array<string, mixed>
     */
    private function syntheticTransfer(array $parameters, string $origin): array
    {
        $action = (string) ($parameters['action'] ?? '');
        $this->syntheticTransferActions[] = $action;
        switch ($action) {
            case 'limits':
                return ['max_chunk_bytes' => 49152];
            case 'begin':
                $this->syntheticBeginCount++;
                $id = $this->syntheticBeginCount === 1
                    ? str_repeat('a', 64)
                    : hash('sha256', 'synthetic-private-lease-'.$this->syntheticBeginCount);
                $this->syntheticPrivateLease = [
                    'id' => $id, 'payload' => '', 'total' => $parameters['total_bytes'],
                    'sha256' => $parameters['sha256'], 'source_host' => $origin,
                ];
                $this->syntheticLeases[$id] = $this->syntheticPrivateLease;

                return array_replace([
                    'action' => 'begin', 'transfer_id' => $id,
                    'purpose' => 'media', 'state' => 'open',
                    'received_bytes' => 0, 'total_bytes' => $parameters['total_bytes'],
                    'sha256' => $parameters['sha256'], 'max_chunk_bytes' => 49152,
                ], $this->syntheticBeginOverrides);
            case 'append':
                if ($parameters['transfer_id'] !== $this->syntheticPrivateLease['id']
                    || $parameters['offset'] !== strlen($this->syntheticPrivateLease['payload'])) {
                    throw new \RuntimeException('Test fake rejected changed transfer/offset.');
                }
                $chunk = base64_decode($parameters['content_base64'], true);
                if (! is_string($chunk)) {
                    throw new \RuntimeException('Invalid fixture chunk encoding.');
                }
                $this->syntheticPrivateLease['payload'] .= $chunk;
                $this->syntheticLeases[$this->syntheticPrivateLease['id']] = $this->syntheticPrivateLease;

                return [
                    'action' => 'append', 'transfer_id' => $this->syntheticPrivateLease['id'],
                    'purpose' => 'media', 'state' => 'open',
                    'received_bytes' => strlen($this->syntheticPrivateLease['payload']),
                    'total_bytes' => $this->syntheticPrivateLease['total'],
                    'sha256' => $this->syntheticPrivateLease['sha256'],
                ];
            case 'verify':
                if ($parameters['transfer_id'] !== $this->syntheticPrivateLease['id']) {
                    throw new \RuntimeException('Verification of wrong synthetic lease.');
                }

                return array_replace([
                    'action' => 'verify', 'transfer_id' => $this->syntheticPrivateLease['id'],
                    'purpose' => 'media', 'state' => 'verified', 'complete' => true,
                    'received_bytes' => strlen($this->syntheticPrivateLease['payload']),
                    'total_bytes' => $this->syntheticPrivateLease['total'],
                    'sha256' => hash('sha256', $this->syntheticPrivateLease['payload']),
                ], $this->syntheticVerifyOverrides);
            case 'status':
                $id = $parameters['transfer_id'] ?? null;
                $committed = is_string($id) ? ($this->syntheticCommittedLeases[$id] ?? null) : null;
                if (is_array($committed) && $committed['source_host'] === $origin) {
                    return [
                        'action' => 'status', 'transfer_id' => $id,
                        'purpose' => 'media', 'state' => 'committed',
                        'total_bytes' => $committed['total'],
                        'sha256' => $committed['sha256'],
                    ];
                }
                throw new \RuntimeException('Cannot inspect unknown synthetic lease.');
            default:
                throw new \RuntimeException('Unexpected synthetic operation.');
        }
    }

    private function bridgeResponse(Request $request): PromiseInterface
    {
        $host = (string) parse_url($request->url(), PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($request->url(), PHP_URL_PATH);

        if ($host === 'files.oaiusercontent.com' && $this->chatFilePayload !== null) {
            return Http::response($this->chatFilePayload, 200, ['Content-Type' => 'application/octet-stream']);
        }
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
            return Http::response([
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'access_token' => explode('.', $host)[0].'-access',
                'refresh_token' => explode('.', $host)[0].'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/mcp') {
            $this->sessionTraffic[] = [
                'host' => $host,
                'method' => $request->method() === 'DELETE' ? 'DELETE' : (string) ($request->data()['method'] ?? ''),
                'session' => (string) ($request->header('Mcp-Session-Id')[0] ?? ''),
            ];
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/mcp' && $request->method() === 'POST') {
            $payload = $request->data();
            if (($payload['method'] ?? null) === 'initialize') {
                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25', 'capabilities' => (object) []],
                ], 200, ['Mcp-Session-Id' => 'test-session']);
            }
            if (($payload['method'] ?? null) === 'tools/call') {
                $ability = (string) ($payload['params']['arguments']['ability_name'] ?? '');
                $this->downstream[] = [
                    'host' => $host,
                    'ability' => $ability,
                    'authorization' => $request->header('Authorization')[0] ?? '',
                    'transaction' => DB::transactionLevel(),
                ];
                if ($ability === 'wp-ai-bridge/abilities-read') {
                    if ($this->pauseDuringCatalog) {
                        DB::table('targets')->where('target_id', explode('.', $host)[0])
                            ->update(['operations_paused' => true]);
                    }
                    $wanted = (string) ($payload['params']['arguments']['parameters']['name'] ?? 'demo/read');
                    $isDestructive = in_array($wanted, ['demo/destroy', 'wp-ai-bridge/private-transfer'], true);
                    $isReadonly = in_array($wanted, ['demo/read', 'wp-ai-bridge/bridge-info', 'wp-ai-bridge/site-context'], true);

                    $data = ['items' => [[
                        'name' => $wanted,
                        'mcp_type' => 'tool',
                        'bridge_delegation' => 'ability_specific',
                        'annotations' => ['readonly' => $isReadonly, 'destructive' => $isDestructive],
                    ]]];
                } elseif ($this->chatFilePayload !== null && $ability === 'wp-ai-bridge/bridge-info') {
                    $data = ['access_groups' => ['site_read' => true, 'builder_write' => $this->syntheticBuilderWriteEnabled]];
                } elseif ($this->chatFilePayload !== null && $ability === 'wp-ai-bridge/site-context') {
                    $data = ['current_user' => ['id' => 7, 'capabilities' => ['upload_files' => $this->syntheticUploadFilesAllowed]]];
                } elseif ($this->chatFilePayload !== null && $ability === 'wp-ai-bridge/private-transfer') {
                    $parameters = $payload['params']['arguments']['parameters'] ?? [];
                    $data = $this->syntheticTransfer($parameters, $host);
                } elseif ($this->chatFilePayload !== null && $ability === 'wp-ai-bridge/transfer-media-import') {
                    $parameters = $payload['params']['arguments']['parameters'] ?? [];
                    $transferId = $parameters['transfer_id'] ?? null;
                    $lease = is_string($transferId) ? ($this->syntheticLeases[$transferId] ?? null) : null;
                    if (! is_array($lease) || $lease['source_host'] !== $host
                        || isset($this->syntheticCommittedLeases[$transferId])) {
                        return Http::response(['jsonrpc' => '2.0', 'id' => $payload['id'] ?? 2,
                            'result' => ['isError' => true, 'content' => [['type' => 'text', 'text' => 'immutable native claim fence']]]], 200);
                    }
                    // Model an irreversible WordPress Media commit with a stable
                    // per-transfer native fence, even if its response is lost.
                    $this->syntheticImportCalls++;
                    $this->syntheticCommittedLeases[$transferId] = $lease;
                    if ($this->syntheticImportUnknown) {
                        return Http::response(['jsonrpc' => '2.0', 'id' => $payload['id'] ?? 2,
                            'result' => ['isError' => true, 'content' => [['type' => 'text', 'text' => 'unknown native result']]]], 200);
                    }
                    $data = [
                        'transfer_id' => $transferId, 'state' => 'committed',
                        'media_id' => 500 + $this->syntheticImportCalls,
                        'filename' => (string) ($parameters['filename'] ?? ''),
                        'bytes' => strlen($lease['payload']),
                        'sha256' => hash('sha256', $lease['payload']),
                    ];
                } else {
                    $data = ['host' => $host, 'ability' => $ability];
                }

                return Http::response([
                    'jsonrpc' => '2.0',
                    'id' => $payload['id'] ?? 2,
                    'result' => [
                        'isError' => false,
                        'structuredContent' => ['success' => true, 'data' => $data],
                    ],
                ], 200);
            }
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/mcp' && $request->method() === 'DELETE') {
            return Http::response('', 200);
        }

        return Http::response(['error' => 'missing'], 404);
    }
}
