<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Access\UserAccessManager;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\League\Entities\ClientEntity;
use App\Infrastructure\OAuth\League\Entities\ScopeEntity;
use App\Infrastructure\OAuth\League\Repositories\AccessTokenRepository;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use App\Models\User;
use DateTimeImmutable;
use GuzzleHttp\Psr7\Response;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use League\OAuth2\Server\CryptKey;
use Mcp\Client;
use Mcp\Client\Transport\HttpTransport;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Tests\TestCase;

/**
 * Supplemental exact-main mixed-connector acceptance against real loopback
 * OpenSSH, a protocol-accurate fake WordPress Bridge transport, the real OAuth
 * resource middleware, and the real StreamableHTTP MCP router.
 *
 * This test never reaches a real WordPress site and does not relax production
 * private-IP egress policy: a loopback-only SSH dial override exists in this
 * disposable test application container only.
 */
final class MixedTargetAuthenticatedAcceptanceTest extends TestCase
{
    use RefreshDatabase;

    private const CLIENT_ID = 'https://acceptance.example.test/client';

    private string $privateToken = '';

    private string $lastIssuedAccessTokenId = '';

    private int $outboundWpCalls = 0;

    private bool $newAbilityPublished = false;

    private string $sshUser;

    protected function setUp(): void
    {
        parent::setUp();
        if (getenv('SSH_FIXTURE_ENABLED') !== '1') {
            $this->markTestSkipped('Requires disposable real loopback OpenSSH fixture.');
        }

        $this->sshUser = $this->fixture('SSH_FIXTURE_USER');
        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.name', 'Gateway acceptance');
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/targets/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');

        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return ['127.0.0.1'];
            }
        });
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'mixed-wp.example.test' ? ['1.1.1.1'] : [];
            }
        });

        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->fakeWordPressBridge($request));

        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);
        Artisan::call('gateway:oauth-keygen', ['--force' => true]);
        $this->configureAndRegisterTestClient();
    }

    public function test_one_valid_oauth_token_routes_wp_and_real_ssh_end_to_end(): void
    {
        $owner = $this->user('owner');
        $wordpress = $this->registerWordPress();
        $ssh = $this->registerAndVerifySsh();
        $token = $this->issueAccessToken($owner);
        $toolResponse = $this->callMcp($token, 'tools/list');
        self::assertSame(200, $toolResponse['http_status']);
        $tools = array_column($toolResponse['payload']['result']['tools'] ?? [], 'name');
        foreach (['targets-list', 'target-context', 'wordpress-abilities-read', 'wordpress-ability-execute',
            'ssh-command-run', 'ssh-file-stat', 'ssh-file-list', 'ssh-file-read', 'ssh-file-write'] as $tool) {
            self::assertContains($tool, $tools, 'One authenticated client must see both families.');
        }

        $inventory = $this->tool($token, 'targets-list', ['limit' => 10]);
        self::assertTrue($inventory['ok'] ?? false, json_encode($inventory));
        $targets = collect($inventory['targets'] ?? [])->keyBy('target_id');
        self::assertTrue($targets->has($wordpress->target_id));
        self::assertTrue($targets->has($ssh->target_id));
        self::assertSame('wp_ai_bridge', $targets[$wordpress->target_id]['connector_type']);
        self::assertSame('ssh_direct', $targets[$ssh->target_id]['connector_type']);

        $catalog = $this->tool($token, 'wordpress-abilities-read', [
            'target_id' => $wordpress->target_id, 'ability' => 'demo/read',
        ]);
        self::assertTrue($catalog['ok'] ?? false, json_encode($catalog));
        self::assertSame('demo/read', $catalog['catalog']['items'][0]['name']);

        $wpResult = $this->tool($token, 'wordpress-ability-execute', [
            'target_id' => $wordpress->target_id, 'ability' => 'demo/read', 'input' => (object) [],
        ]);
        self::assertTrue($wpResult['ok'] ?? false, json_encode($wpResult));
        self::assertSame('demo/read', $wpResult['result']['ability'] ?? null);

        // New downstream Ability name must be discovered/executed without a
        // Gateway code change or client reconnection.
        $this->newAbilityPublished = true;
        $novel = 'futureprovider/newly-published-read';
        $newCatalog = $this->tool($token, 'wordpress-abilities-read', [
            'target_id' => $wordpress->target_id, 'ability' => $novel,
        ]);
        self::assertTrue($newCatalog['ok'] ?? false, json_encode($newCatalog));
        self::assertSame($novel, $newCatalog['catalog']['items'][0]['name']);
        $newExecution = $this->tool($token, 'wordpress-ability-execute', [
            'target_id' => $wordpress->target_id, 'ability' => $novel, 'input' => (object) [],
        ]);
        self::assertTrue($newExecution['ok'] ?? false, json_encode($newExecution));
        self::assertSame($novel, $newExecution['result']['ability'] ?? null);

        $sshCommand = $this->tool($token, 'ssh-command-run', [
            'target_id' => $ssh->target_id,
            'command' => "printf 'mixed-gateway-ssh-ok'",
        ]);
        self::assertTrue($sshCommand['ok'] ?? false, json_encode($sshCommand));
        self::assertSame('mixed-gateway-ssh-ok', $sshCommand['result']['stdout'] ?? null);
        self::assertSame(0, $sshCommand['result']['exit_code'] ?? null);

        $path = '/home/'.$this->sshUser.'/mcp-mixed-'.bin2hex(random_bytes(6)).'.bin';
        $binary = "\x00\xff\x10\x02hello\x00";
        $before = $this->outboundWpCalls;
        try {
            $write = $this->tool($token, 'ssh-file-write', [
                'target_id' => $ssh->target_id,
                'path' => $path, 'content_base64' => base64_encode($binary),
            ]);
            self::assertTrue($write['ok'] ?? false, json_encode($write));
            self::assertSame(strlen($binary), $write['result']['bytes_written'] ?? null);

            $stat = $this->tool($token, 'ssh-file-stat', ['target_id' => $ssh->target_id, 'path' => $path]);
            self::assertTrue($stat['ok'] ?? false, json_encode($stat));
            self::assertSame(strlen($binary), $stat['result']['file']['size'] ?? null);

            $read = $this->tool($token, 'ssh-file-read', [
                'target_id' => $ssh->target_id, 'path' => $path,
            ]);
            self::assertTrue($read['ok'] ?? false, json_encode($read));
            self::assertSame($binary, base64_decode($read['result']['data'] ?? '', true));
        } finally {
            $remove = $this->tool($token, 'ssh-command-run', [
                'target_id' => $ssh->target_id, 'command' => 'rm -f -- '.escapeshellarg($path),
            ]);
            self::assertTrue($remove['ok'] ?? false, json_encode($remove));
        }

        self::assertSame($before, $this->outboundWpCalls, 'SSH family must never trigger WP outbound traffic.');
        self::assertGreaterThan(0, $this->outboundWpCalls, 'WordPress fake must actually receive requests.');
        self::assertSame('connected', $ssh->fresh()->connection_state->value);
        self::assertSame('connected', $wordpress->fresh()->connection_state->value);
    }

    public function test_same_oauth_edge_enforces_cross_target_visibility_and_default_ssh_denials(): void
    {
        $wordpress = $this->registerWordPress();
        $ssh = $this->registerAndVerifySsh();
        $operator = $this->user('operator');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $wordpress->getKey(),
            'allowed' => true,
        ]);
        $token = $this->issueAccessToken($operator);
        $inventory = $this->tool($token, 'targets-list', ['limit' => 10]);
        self::assertTrue($inventory['ok'] ?? false);
        self::assertSame([$wordpress->target_id], array_column($inventory['targets'], 'target_id'));

        $before = $this->outboundWpCalls;
        $hidden = $this->tool($token, 'ssh-command-run', [
            'target_id' => $ssh->target_id, 'command' => "printf 'should-not-run'",
        ]);
        self::assertSame('target_not_found', $hidden['error']['code'] ?? null);
        self::assertSame($before, $this->outboundWpCalls);
        $fakeCrossFamily = $this->tool($token, 'ssh-file-read', [
            'target_id' => $wordpress->target_id, 'path' => '/tmp/mcp-not-applicable',
        ]);
        self::assertSame('target_not_found', $fakeCrossFamily['error']['code'] ?? null);
        $accessible = $this->tool($token, 'wordpress-ability-execute', [
            'target_id' => $wordpress->target_id, 'ability' => 'demo/read', 'input' => (object) [],
        ]);
        self::assertTrue($accessible['ok'] ?? false, json_encode($accessible));

        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $ssh->getKey(),
            'allowed' => true,
        ]);
        $visibleButDenied = $this->tool($token, 'ssh-command-run', [
            'target_id' => $ssh->target_id, 'command' => "printf 'should-not-run'",
        ]);
        self::assertSame('target_not_found', $visibleButDenied['error']['code'] ?? null);
        self::assertTrue(DB::table('user_permission_denials')
            ->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshCommandRun->value)
            ->exists());
        // The same OAuth token cannot lift connector-specific denied capabilities.
        $stillWp = $this->tool($token, 'wordpress-abilities-read', [
            'target_id' => $wordpress->target_id, 'ability' => 'demo/read',
        ]);
        self::assertTrue($stillWp['ok'] ?? false);
    }

    public function test_existing_signed_bearer_loses_both_targets_when_operator_disabled(): void
    {
        $owner = $this->user('owner');
        $this->registerWordPress();
        $this->registerAndVerifySsh();
        $token = $this->issueAccessToken($owner);
        $ok = $this->tool($token, 'targets-list', ['limit' => 10]);
        self::assertTrue($ok['ok'] ?? false);
        $owner->forceFill(['access_enabled' => false])->save();
        $blocked = $this->callMcp($token, 'tools/call', [
            'name' => 'targets-list', 'arguments' => (object) [],
        ], 'targets-list');
        self::assertSame(401, $blocked['http_status']);
    }

    public function test_mid_ssh_handshake_ai_or_oauth_revocation_stops_each_effectful_family(): void
    {
        $owner = $this->user('owner');
        $ssh = $this->registerAndVerifySsh();
        $cases = [
            ['ssh-command-run', 'ai_disabled'],
            ['ssh-command-run', 'access_token'],
            ['ssh-file-write', 'ai_disabled'],
            ['ssh-file-write', 'consent'],
            ['ssh-job-start', 'ai_disabled'],
            ['ssh-job-start', 'access_token'],
        ];
        foreach ($cases as [$tool, $revocation]) {
            $owner->forceFill(['ai_access_enabled' => true])->save();
            $bearer = $this->issueAccessToken($owner);
            $tokenId = $this->lastIssuedAccessTokenId;
            $consentId = (string) DB::table('oauth_access_tokens')
                ->where('id', $tokenId)->value('authorization_id');
            $path = '/home/'.$this->sshUser.'/mcp-revoked-'.bin2hex(random_bytes(9));
            $mutated = false;

            // This policy is test-only and is reached AFTER MCP bearer
            // admission, during an actual pinned SSH connection setup. The
            // final post-login effect fence must see the revoked database
            // state even though the human role/Target permission is unchanged.
            $revoke = static function () use ($owner, $revocation, $tokenId, $consentId, &$mutated): void {
                $mutated = true;
                if ($revocation === 'ai_disabled') {
                    $owner->forceFill(['ai_access_enabled' => false])->save();
                } elseif ($revocation === 'consent') {
                    DB::table('oauth_authorizations')->where('id', $consentId)
                        ->update(['revoked_at' => now()]);
                } else {
                    DB::table('oauth_access_tokens')->where('id', $tokenId)
                        ->update(['revoked_at' => now()]);
                }
            };
            $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class($revoke) implements SshDialAddressPolicy
            {
                private bool $called = false;

                public function __construct(private readonly \Closure $revoke) {}

                public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
                {
                    if (! $this->called) {
                        $this->called = true;
                        ($this->revoke)();
                    }

                    return ['127.0.0.1'];
                }
            });

            $arguments = match ($tool) {
                'ssh-command-run' => ['target_id' => $ssh->target_id,
                    'command' => 'printf should-never-run > '.escapeshellarg($path)],
                'ssh-file-write' => ['target_id' => $ssh->target_id,
                    'path' => $path, 'content_base64' => base64_encode('should-never-write')],
                default => ['target_id' => $ssh->target_id, 'request_id' => (string) Str::uuid(),
                    'script' => 'printf should-never-launch > '.escapeshellarg($path)],
            };
            $denied = $this->tool($bearer, $tool, $arguments);
            self::assertTrue($mutated, $tool.' / '.$revocation);
            self::assertFalse($denied['ok'] ?? true, $tool.' / '.$revocation.' '.json_encode($denied));

            // The dial policy must not revoke the independent verification
            // connection. Restore it before the next authenticated request.
            $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
            {
                public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
                {
                    return ['127.0.0.1'];
                }
            });

            if ($tool === 'ssh-command-run' && $revocation === 'ai_disabled') {
                // AI disable alone cannot change the existing human command
                // permission. Test the real human SSH operation after the
                // MCP request loop, without replacing its live HTTP context.
                self::assertTrue(app(AccessControl::class)
                    ->allows($owner, GatewayPermission::SshCommandRun, $ssh));
            }

            // A new, authorized HTTP request checks the actual remote host.
            // This is stronger than asserting the handler merely returned an
            // error: the revoked request created no command, file or Job effect.
            $owner->forceFill(['ai_access_enabled' => true])->save();
            $verificationBearer = $this->issueAccessToken($owner);
            $checked = $this->tool($verificationBearer, 'ssh-command-run', [
                'target_id' => $ssh->target_id,
                'command' => 'test ! -e '.escapeshellarg($path),
            ]);
            self::assertTrue($checked['ok'] ?? false, json_encode($checked));
            self::assertSame(0, $checked['result']['exit_code'] ?? null);
        }

        // Last, exercise the actual human application runtime with AI off.
        // This is intentionally outside the MCP request loop: replacing the
        // current request with a human route in the middle of a StreamableHTTP
        // exchange would make later HTTP transport test calls ambiguous.
        $owner->forceFill(['ai_access_enabled' => false])->save();
        $this->app->instance('request', \Illuminate\Http\Request::create('/admin/targets', 'POST'));
        $human = app(SshCommandRuntime::class)->run(
            $owner, $ssh, 'printf human-ssh-still-allowed',
        );
        self::assertSame('completed', $human['status']);
        self::assertSame(0, $human['exit_code']);
        self::assertSame('human-ssh-still-allowed', $human['stdout']);
    }

    public function test_official_mcp_sdk_client_calls_both_families_over_authenticated_http_transport(): void
    {
        $owner = $this->user('owner');
        $wordpress = $this->registerWordPress();
        $ssh = $this->registerAndVerifySsh();
        $token = $this->issueAccessToken($owner);

        // The SDK's real PSR-18 HttpTransport supplies its own protocol headers,
        // JSON RPC, initialization, tool calls and session lifecycle. Its HTTP
        // connector is adapted to the real Laravel route/kernel only to share
        // this PHPUnit application's WP fake; SSH performs actual OpenSSH I/O.
        $httpClient = new class($this->app) implements ClientInterface
        {
            public function __construct(private Application $app) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $server = [
                    'HTTP_HOST' => $request->getUri()->getHost(),
                    'CONTENT_TYPE' => $request->getHeaderLine('Content-Type'),
                    'HTTP_ACCEPT' => $request->getHeaderLine('Accept'),
                    'HTTP_AUTHORIZATION' => $request->getHeaderLine('Authorization'),
                ];
                $laravel = \Illuminate\Http\Request::create(
                    (string) $request->getUri(),
                    $request->getMethod(), [], [], [], $server,
                    (string) $request->getBody(),
                );
                foreach ($request->getHeaders() as $name => $values) {
                    $laravel->headers->set($name, implode(', ', $values));
                }
                $kernel = $this->app->make(Kernel::class);
                $response = $kernel->handle($laravel);
                if ($response instanceof StreamedResponse) {
                    ob_start();
                    try {
                        $response->sendContent();
                    } finally {
                        $content = (string) ob_get_clean();
                    }
                } else {
                    $content = (string) $response->getContent();
                }

                return new Response(
                    $response->getStatusCode(), $response->headers->all(), $content,
                );
            }
        };

        $transport = new HttpTransport(
            endpoint: (string) config('oauth.resource'),
            headers: ['Authorization' => 'Bearer '.$token],
            httpClient: $httpClient,
        );
        $client = Client::builder()
            ->setClientInfo('mixed-acceptance-official-sdk', '1.0.0')
            ->setInitTimeout(6)
            ->setRequestTimeout(20)
            ->setMaxRetries(0)
            ->build();

        try {
            $client->connect($transport);
            $tools = array_column(array_map(
                static fn ($tool): array => ['name' => $tool->name],
                $client->listTools()->tools,
            ), 'name');
            self::assertContains('wordpress-ability-execute', $tools);
            self::assertContains('ssh-command-run', $tools);
            self::assertContains('ssh-file-read', $tools);
            $list = $client->callTool('targets-list', []);
            self::assertTrue($list->structuredContent['ok'] ?? false);
            self::assertCount(2, $list->structuredContent['targets'] ?? []);

            $wp = $client->callTool('wordpress-ability-execute', [
                'target_id' => $wordpress->target_id, 'ability' => 'demo/read',
                'input' => (object) [],
            ]);
            self::assertFalse($wp->isError);
            self::assertTrue($wp->structuredContent['ok'] ?? false);
            self::assertSame('demo/read', $wp->structuredContent['result']['ability'] ?? null);

            $sshCommand = $client->callTool('ssh-command-run', [
                'target_id' => $ssh->target_id,
                'command' => "printf 'official-sdk-live-ssh-ok'",
            ]);
            self::assertFalse($sshCommand->isError);
            self::assertTrue($sshCommand->structuredContent['ok'] ?? false);
            self::assertSame('official-sdk-live-ssh-ok', $sshCommand->structuredContent['result']['stdout'] ?? null);
        } finally {
            $client->disconnect();
        }
    }

    private function configureAndRegisterTestClient(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsArray($details['rsa'] ?? null);
        $encode = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        config()->set('oauth.client_profiles', [
            ...config('oauth.client_profiles'),
            'acceptance' => [
                'client_id' => self::CLIENT_ID,
                'display_name' => 'Disposable mixed acceptance client',
                'strategy' => 'pinned_private_key_jwt',
                'enabled' => true,
                'redirect_uris' => ['https://acceptance.example.test/callback'],
                'jwks' => ['keys' => [[
                    'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256',
                    'kid' => 'test-only-rsa-key',
                    'n' => $encode($details['rsa']['n']),
                    'e' => $encode($details['rsa']['e']),
                ]]],
            ],
        ]);
        app(ClientProfileRegistry::class)->register('acceptance');
    }

    private function registerWordPress(): Target
    {
        $target = app(WpAiBridgeTargetRegistration::class)->register(
            'mixed-wp', 'Mixed WP fixture', 'https://mixed-wp.example.test',
        );
        $connections = app(WpAiBridgeTargetConnectionService::class);
        $authorize = $connections->begin($target);
        parse_str((string) parse_url($authorize, PHP_URL_QUERY), $query);
        self::assertIsString($query['state'] ?? null);
        $connections->completeCallback(
            (string) $query['state'],
            'fixture-wp-auth-code',
            'https://mixed-wp.example.test',
            null,
        );

        return $target->fresh();
    }

    private function registerAndVerifySsh(): Target
    {
        $target = app(SshTargetRegistration::class)->register(
            'mixed-ssh', 'Mixed SSH fixture', 'fixture.example.test',
            (int) $this->fixture('SSH_FIXTURE_PORT_MODERN'),
            $this->sshUser,
            trim((string) file_get_contents($this->fixture('SSH_FIXTURE_ED25519_HOST_PUB'))),
            'password', $this->fixture('SSH_FIXTURE_PASSWORD'), null,
        );
        self::assertSame('127.0.0.1', app(SshTargetConnectionService::class)->test($target));

        return $target->fresh();
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => 'Mixed fixture '.$role,
            'email' => 'mixed-'.Str::random(12).'@example.test',
            'password' => 'test-only-not-used',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
            // This actor deliberately exercises OAuth + MCP; human-only users remain default-denied.
            'ai_access_enabled' => true,
        ], []);
    }

    private function issueAccessToken(User $user): string
    {
        app(OAuthAuthorizationStore::class)->approve(
            (int) $user->getKey(), self::CLIENT_ID, (string) config('oauth.resource'), ['mcp'],
        );
        $token = app(AccessTokenRepository::class)->getNewToken(
            new ClientEntity(
                identifier: self::CLIENT_ID,
                name: 'Disposable mixed acceptance client',
                redirectUris: ['https://acceptance.example.test/callback'],
            ),
            [new ScopeEntity('mcp')],
            (string) $user->getKey(),
        );
        $this->lastIssuedAccessTokenId = bin2hex(random_bytes(20));
        $token->setIdentifier($this->lastIssuedAccessTokenId);
        $token->setExpiryDateTime((new DateTimeImmutable)->modify('+15 minutes'));
        $token->setPrivateKey(new CryptKey((string) config('oauth.keys.private')));
        app(AccessTokenRepository::class)->persistNewAccessToken($token);

        return $token->toString();
    }

    /**
     * @param  array<string,mixed>  $params
     * @return array{http_status:int,payload:array<string,mixed>}
     */
    private function callMcp(string $token, string $method, array $params = [], ?string $toolName = null): array
    {
        $headers = [
            'Authorization' => 'Bearer '.$token,
            'Host' => (string) parse_url((string) config('oauth.resource'), PHP_URL_HOST),
            'MCP-Protocol-Version' => '2026-07-28',
            'Mcp-Method' => $method,
        ];
        if ($toolName !== null) {
            $headers['Mcp-Name'] = $toolName;
        }
        $payload = [
            'jsonrpc' => '2.0',
            'id' => random_int(1, 1000000),
            'method' => $method,
        ];
        if (in_array($method, ['tools/call', 'tools/list'], true)) {
            $payload['params'] = [
                ...$params,
                '_meta' => [
                    'io.modelcontextprotocol/protocolVersion' => '2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities' => (object) [],
                    'io.modelcontextprotocol/clientInfo' => [
                        'name' => 'mixed-acceptance', 'version' => '1.0.0',
                    ],
                ],
            ];
        }
        $response = $this->withHeaders($headers)->postJson('/mcp', $payload);

        $status = $response->getStatusCode();
        if ($status === 401) {
            return ['http_status' => $status, 'payload' => []];
        }

        // The MCP endpoint is a streamed Symfony response. Decode its
        // captured bytes explicitly rather than having TestResponse::json()
        // replace malformed/empty wire data with a misleading dynamic
        // "StreamedResponse::$exception" property error.
        $body = $response->baseResponse instanceof StreamedResponse
            ? $response->streamedContent() : $response->getContent();
        $payload = json_decode((string) $body, true);
        self::assertIsArray($payload, sprintf(
            'Invalid streamed MCP response (HTTP %d, Content-Type %s): %s',
            $status, (string) $response->headers->get('Content-Type'), substr((string) $body, 0, 500),
        ));

        return ['http_status' => $status, 'payload' => $payload];
    }

    /** @param array<string,mixed> $args @return array<string,mixed> */
    private function tool(string $token, string $name, array $args): array
    {
        $call = $this->callMcp(
            $token, 'tools/call', ['name' => $name, 'arguments' => $args === [] ? (object) [] : $args], $name,
        );
        self::assertSame(200, $call['http_status'], json_encode($call['payload']));
        $result = $call['payload']['result']['structuredContent'] ?? null;
        self::assertIsArray($result, json_encode($call['payload']));

        return $result;
    }

    private function fakeWordPressBridge(Request $request)
    {
        $host = (string) parse_url($request->url(), PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($request->url(), PHP_URL_PATH);
        if ($host !== 'mixed-wp.example.test') {
            return Http::response(['error' => 'unexpected_target'], 404);
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
                'token_type' => 'Bearer', 'expires_in' => 3600,
                'access_token' => 'mixed-fixture-access',
                'refresh_token' => 'mixed-fixture-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }
        if ($path !== '/wp-json/wp-ai-bridge/v1/mcp') {
            return Http::response(['error' => 'missing'], 404);
        }
        $this->outboundWpCalls++;
        if ($request->method() === 'DELETE') {
            return Http::response('', 200);
        }
        $payload = $request->data();
        if (($payload['method'] ?? null) === 'initialize') {
            return Http::response([
                'jsonrpc' => '2.0', 'id' => $payload['id'] ?? 1,
                'result' => [
                    'protocolVersion' => '2025-11-25',
                    'serverInfo' => ['name' => 'wp-ai-bridge', 'version' => 'acceptance'],
                    'capabilities' => ['tools' => (object) []],
                ],
            ], 200, ['Mcp-Session-Id' => 'mixed-fixture-session']);
        }
        if (($payload['method'] ?? null) !== 'tools/call'
            || ($payload['params']['name'] ?? null) !== 'mcp-adapter-execute-ability') {
            return Http::response(['error' => 'bad_mcp_method'], 400);
        }
        $ability = (string) ($payload['params']['arguments']['ability_name'] ?? '');
        if ($ability === 'wp-ai-bridge/abilities-read') {
            $parameters = $payload['params']['arguments']['parameters'] ?? [];
            $asked = (string) ($parameters['name'] ?? 'demo/read');
            $exists = $asked === 'demo/read'
                || ($this->newAbilityPublished && $asked === 'futureprovider/newly-published-read');
            $items = $exists ? [[
                'name' => $asked,
                'namespace' => explode('/', $asked)[0],
                'mcp_type' => 'tool',
                'annotations' => ['readonly' => true, 'destructive' => false, 'idempotent' => true],
                'bridge_delegation' => 'ability_specific',
                'execution_permission' => 'not_evaluated',
            ]] : [];
            $data = [
                'items' => $items,
                'page' => 1, 'per_page' => 10,
                'total' => count($items), 'total_pages' => 1,
                'execution_permission' => 'not_evaluated',
            ];
        } elseif ($ability === 'demo/read' || ($this->newAbilityPublished && $ability === 'futureprovider/newly-published-read')) {
            $data = ['ability' => $ability, 'site' => 'mixed-wp', 'read_only' => true];
        } else {
            return Http::response(['error' => 'no_such_ability'], 404);
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

    private function fixture(string $name): string
    {
        $value = getenv($name);
        self::assertIsString($value, $name.' unavailable');
        self::assertNotSame('', $value);

        return $value;
    }
}
