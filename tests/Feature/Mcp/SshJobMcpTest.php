<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Mcp\GatewayMcpEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class SshJobMcpTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // Deterministic deny-only synthetic network policy: no real outbound
        // SSH traffic during these authorization/idempotency unit fixtures.
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return [];
            }
        });
    }

    public function test_unsupported_host_fails_closed_and_exact_start_intent_is_durable_once(): void
    {
        $user = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'chatgpt-test-client');
        $requestId = (string) Str::uuid();
        $tool = app(SshJobMcpToolHandlers::class);

        $first = $tool->start($user, $target->target_id, $client, $requestId, 'echo safe', 30);
        self::assertFalse($first['ok']);
        self::assertSame('job_unsupported', $first['error']['code']);
        $id = $first['result']['job_id'];
        self::assertSame('unsupported', $first['result']['status']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
        self::assertArrayNotHasKey('script', (array) DB::table('ssh_command_jobs')->sole());
        self::assertStringNotContainsString('echo safe', json_encode(DB::table('ssh_command_jobs')->sole()));

        // The same request key does NOT re-probe/re-launch, even within the
        // same second; a changed script or runtime is a conflict.
        $duplicate = $tool->start($user, $target->target_id, $client, $requestId, 'echo safe', 30);
        self::assertSame($id, $duplicate['result']['job_id']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
        self::assertSame('invalid_input',
            $tool->start($user, $target->target_id, $client, $requestId, 'echo changed', 30)['error']['code']);
        self::assertSame('invalid_input',
            $tool->start($user, $target->target_id, $client, $requestId, 'echo safe', 31)['error']['code']);

        $status = $tool->status($user, $target->target_id, $client, $id);
        self::assertSame('unsupported', $status['result']['status']);
        self::assertFalse($status['result']['retry_safe']);
    }

    public function test_job_authorization_remains_bound_to_user_client_target_and_config(): void
    {
        $user = $this->user('owner');
        $other = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'client-a');
        $id = app(SshJobMcpToolHandlers::class)->start(
            $user, $target->target_id, $client, (string) Str::uuid(), 'echo confidential',
        )['result']['job_id'];
        $tool = app(SshJobMcpToolHandlers::class);

        self::assertSame('target_not_found',
            $tool->status($other, $target->target_id, $client, $id)['error']['code']);
        self::assertSame('target_not_found',
            $tool->status($user, $target->target_id, hash('sha256', 'other-client'), $id)['error']['code']);
        self::assertSame('target_not_found',
            $tool->output($other, $target->target_id, $client, $id)['error']['code']);
        self::assertSame('target_not_found',
            $tool->cancel($other, $target->target_id, $client, $id)['error']['code']);

        DB::table('ssh_direct_target_configs')->where('target_record_id', $target->getKey())
            ->update(['username' => 'rotated-account']);
        self::assertSame('target_not_found',
            $tool->status($user, $target->target_id, $client, $id)['error']['code']);
    }

    public function test_job_input_and_per_principal_active_admission_are_bounded(): void
    {
        $user = $this->user('owner');
        $target = $this->target();
        $tool = app(SshJobMcpToolHandlers::class);
        $client = hash('sha256', 'limit');
        foreach ([
            [str_repeat('a', 16385), 30],
            ["echo\0danger", 30],
            ['  ', 30],
            ['echo safe', 15],
            ['echo safe', 301],
        ] as [$script, $seconds]) {
            self::assertSame('invalid_input',
                $tool->start($user, $target->target_id, $client, (string) Str::uuid(), $script, $seconds)['error']['code']);
        }
        self::assertSame(0, DB::table('ssh_command_jobs')->count());

        $binding = hash('sha256', implode("\0", [
            (string) $target->getKey(), $target->target_id,
            'fixture.example.test', '22', 'fixture-user', 'password',
            'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32)),
        ]));
        for ($i = 0; $i < 2; $i++) {
            DB::table('ssh_command_jobs')->insert([
                'id' => (string) Str::ulid(),
                'target_record_id' => $target->getKey(),
                'user_id' => $user->getKey(),
                'client_identity_hash' => $client,
                'request_id' => (string) Str::uuid(),
                'script_digest' => str_repeat('a', 64),
                'target_binding_hash' => $binding,
                'status' => 'running',
                'runtime_seconds' => 60,
                'expires_at' => now()->addHour(),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
        self::assertSame('rate_limited',
            $tool->start($user, $target->target_id, $client, (string) Str::uuid(), 'echo third')['error']['code']);
        self::assertSame(2, DB::table('ssh_command_jobs')->count());
    }

    public function test_expired_unknown_job_stays_recoverable_and_does_not_get_replayed_or_pruned(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'client-once');
        $script = 'echo uncertain';
        $requestId = (string) Str::uuid();
        $id = app(SshJobMcpToolHandlers::class)->start(
            $owner, $target->target_id, $client, $requestId, $script,
        )['result']['job_id'];

        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'status' => 'launch_unknown',
            'unit_mode' => 'user',
            'expires_at' => now()->subDay(),
        ]);
        $tool = app(SshJobMcpToolHandlers::class);
        self::assertSame($id, $tool->start(
            $owner, $target->target_id, $client, $requestId, $script,
        )['result']['job_id']);
        self::assertSame('launch_unknown',
            $tool->status($owner, $target->target_id, $client, $id)['result']['status']);
        $cancel = $tool->cancel($owner, $target->target_id, $client, $id);
        self::assertTrue($cancel['ok']);
        self::assertSame('cancel_requested', $cancel['result']['status']);
        self::assertFalse($cancel['result']['complete']);
        // The remote unit was uncontactable: a stop was not verified.
        self::assertSame(0, app(SshJobCoordinator::class)->prune());
        self::assertSame('cancel_requested', DB::table('ssh_command_jobs')->where('id', $id)->value('status'));
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
    }

    public function test_expired_unsupported_intent_prunes_without_remote_cleanup(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'unsupported');
        $id = app(SshJobMcpToolHandlers::class)->start(
            $owner, $target->target_id, $client, (string) Str::uuid(), 'echo never-run',
        )['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $id)->update(['expires_at' => now()->subDay()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, DB::table('ssh_command_jobs')->count());
    }

    public function test_migration_rollback_refuses_to_discard_even_terminal_no_replay_handles(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $id = app(SshJobMcpToolHandlers::class)->start(
            $owner, $target->target_id, hash('sha256', 'rollback-client'),
            (string) Str::uuid(), 'echo already-done',
        )['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $id)->update(['status' => 'completed']);

        $migration = require database_path('migrations/2026_10_15_010000_create_ssh_command_jobs.php');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Reconcile and prune every SSH Job');
        $migration->down();
    }

    public function test_public_manifest_advertises_bounded_job_family_with_correct_mutability(): void
    {
        $owner = $this->user('owner');
        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        self::assertIsString($host);
        $headers = [
            'HTTP_HOST' => $host,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_MCP_PROTOCOL_VERSION' => '2025-11-25',
        ];
        $init = Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize',
            'params' => [
                'protocolVersion' => '2025-11-25',
                'capabilities' => (object) [],
                'clientInfo' => ['name' => 'Job test', 'version' => '1.0'],
            ],
        ], JSON_THROW_ON_ERROR));
        $init->attributes->set('oauth_user', $owner);
        $init->attributes->set('oauth_client_id', 'client-test');
        $init->attributes->set('oauth_client_profile_key', 'chatgpt');
        $endpoint = app(GatewayMcpEndpoint::class);
        $response = $endpoint->handle($init);
        self::assertSame(200, $response->getStatusCode());
        $session = $response->headers->get('Mcp-Session-Id');
        self::assertNotEmpty($session);
        $headers['HTTP_MCP_SESSION_ID'] = $session;
        $list = Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/list', 'params' => (object) [],
        ], JSON_THROW_ON_ERROR));
        $list->attributes->set('oauth_user', $owner);
        $list->attributes->set('oauth_client_id', 'client-test');
        $list->attributes->set('oauth_client_profile_key', 'chatgpt');
        $listing = $endpoint->handle($list);
        ob_start();
        $listing->sendContent();
        $body = (string) ob_get_clean();
        $data = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        $byName = collect($data['result']['tools'])->keyBy('name');
        foreach (['ssh-job-start', 'ssh-job-status', 'ssh-job-output', 'ssh-job-cancel'] as $name) {
            self::assertTrue($byName->has($name));
        }
        self::assertSame(16384, $byName['ssh-job-start']['inputSchema']['properties']['script']['maxLength']);
        self::assertSame(300, $byName['ssh-job-start']['inputSchema']['properties']['max_runtime_seconds']['maximum']);
        self::assertFalse($byName['ssh-job-start']['annotations']['readOnlyHint']);
        self::assertTrue($byName['ssh-job-status']['annotations']['readOnlyHint']);
        self::assertTrue($byName['ssh-job-cancel']['annotations']['destructiveHint']);

        // New MCP requests publish the current Owner-configured maximum,
        // never a hardcoded 300s schema that contradicts real runtime.
        DB::table('operational_settings')->where('id', 1)
            ->update(['ssh_job_max_runtime_seconds' => 7200]);
        // The test directly invokes the endpoint twice in one Laravel
        // container; in real HTTP handling scoped settings reset per request.
        $this->app->forgetInstance(OperationalSettings::class);
        $next = Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 3, 'method' => 'tools/list', 'params' => (object) [],
        ], JSON_THROW_ON_ERROR));
        $next->attributes->set('oauth_user', $owner);
        $next->attributes->set('oauth_client_id', 'client-test');
        $next->attributes->set('oauth_client_profile_key', 'chatgpt');
        $updated = app(GatewayMcpEndpoint::class)->handle($next);
        ob_start();
        $updated->sendContent();
        $updatedData = json_decode((string) ob_get_clean(), true, 32, JSON_THROW_ON_ERROR);
        self::assertSame(200, $updated->getStatusCode());
        $changed = collect($updatedData['result']['tools'])->keyBy('name');
        self::assertSame(7200, $changed['ssh-job-start']['inputSchema']['properties']['max_runtime_seconds']['maximum']);
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => $role,
            'email' => $role.'-job-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }

    private function target(): Target
    {
        $hostKey = 'ssh-ed25519 '.base64_encode(
            pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32),
        );
        $target = app(SshTargetRegistration::class)->register(
            'ssh-job-demo', 'SSH Job demo', 'fixture.example.test', 22,
            'fixture-user', $hostKey, 'password', 'test-secret', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target;
    }
}
