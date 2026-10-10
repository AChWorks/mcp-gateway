<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\TargetGroup;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Mcp\GatewayMcpEndpoint;
use App\Models\User;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
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
            public function resolve(string $host): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->bridgeResponse($request));
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
        DB::listen(static function (\Illuminate\Database\Events\QueryExecuted $query) use (&$queries): void {
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

    public function test_public_gateway_tool_manifest_contains_exact_wp_names_and_no_unsupported_connectors(): void
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
        foreach (['targets-list', 'target-context', 'wordpress-abilities-read', 'wordpress-ability-execute'] as $name) {
            self::assertContains($name, $names);
        }
        foreach (['site-ability-execute', 'ssh-command-run', 'agent-run-command'] as $name) {
            self::assertNotContains($name, $names);
        }
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

    private function bridgeResponse(Request $request): PromiseInterface
    {
        $host = (string) parse_url($request->url(), PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($request->url(), PHP_URL_PATH);

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
                    $wanted = (string) ($payload['params']['arguments']['parameters']['name'] ?? 'demo/read');
                    $isDestructive = $wanted === 'demo/destroy';
                    $isReadonly = $wanted === 'demo/read';

                    $data = ['items' => [[
                        'name' => $wanted,
                        'mcp_type' => 'tool',
                        'bridge_delegation' => 'ability_specific',
                        'annotations' => ['readonly' => $isReadonly, 'destructive' => $isDestructive],
                    ]]];
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
