<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class SshCommandMcpTest extends TestCase
{
    use RefreshDatabase;

    public function test_ssh_command_is_exact_target_and_default_deny_before_transport(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $target = $this->target();
        $other = Target::query()->create(['target_id' => 'wp-target', 'display_name' => 'WP', 'connector_type' => 'wp_ai_bridge']);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);

        $handler = app(SshCommandMcpToolHandlers::class);
        $command = 'echo private-command-sensitive-material';
        self::assertSame('target_not_found', $handler->run($operator, 'ssh-command', $command)['error']['code']);
        self::assertSame('target_not_found', $handler->run($operator, 'ssh-missing', $command)['error']['code']);
        self::assertSame('target_not_found', $handler->run($owner, '../ssh-command', $command)['error']['code']);
        self::assertSame('target_not_found', $handler->run($owner, $other->target_id, $command)['error']['code']);
        self::assertSame('invalid_input', $handler->run($owner, 'ssh-command', str_repeat('z', 8193))['error']['code']);
        self::assertSame('invalid_input', $handler->run($owner, 'ssh-command', "echo\0hack")['error']['code']);
        self::assertSame('invalid_input', $handler->run($owner, 'ssh-command', 'echo valid', 21)['error']['code']);
        self::assertSame('invalid_input', $handler->run($owner, 'ssh-command', '  ')['error']['code']);

        $events = DB::table('activity_events')->where('operation', 'ssh-command-run')->get();
        self::assertCount(8, $events);
        self::assertStringNotContainsString($command, json_encode($events, JSON_THROW_ON_ERROR));
    }

    public function test_selected_target_and_explicit_capability_are_both_required_without_network_leakage(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $target = $this->target();
        // A previously successful pinned-host login is a prerequisite before
        // command/SFTP runtime reaches outbound egress policy.
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        // Fixture policy forbids every dial. Even authorized calls must fail
        // without contacting a live server or exposing transport details.
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new RuntimeException('fixture transport must stay offline');
            }
        });

        $handler = app(SshCommandMcpToolHandlers::class);
        $command = 'sudo -n id # no command allowlist';
        self::assertSame('target_not_found', $handler->run($operator, $target->target_id, $command)['error']['code']);

        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshCommandRun->value)->delete();
        $authorized = $handler->run($operator, $target->target_id, $command);
        self::assertSame('egress_denied', $authorized['error']['code']);
        self::assertSame('SSH command could not be started safely.', $authorized['error']['message']);
        self::assertStringNotContainsString($command, json_encode($authorized, JSON_THROW_ON_ERROR));
        $diagnostics = app(OperationDiagnosticsMcpToolHandlers::class)
            ->read($owner, $authorized['error']['diagnostic_reference']);
        self::assertTrue($diagnostics['ok']);
        self::assertSame('gateway_admission', $diagnostics['events'][0]['diagnostics']['failure_origin']);
        self::assertSame('connection_setup', $diagnostics['events'][0]['diagnostics']['failure_stage']);
        self::assertTrue($diagnostics['events'][0]['diagnostics']['request_not_sent']);

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        self::assertSame('target_not_found', $handler->run($operator, $target->target_id, $command)['error']['code']);
        self::assertStringNotContainsString($command, json_encode(
            DB::table('activity_events')->where('operation', 'ssh-command-run')->get(), JSON_THROW_ON_ERROR,
        ));
    }

    public function test_owner_ssh_command_limits_apply_as_utf8_bytes_without_remote_retry(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new RuntimeException('fixture transport must remain offline');
            }
        });

        $handler = app(SshCommandMcpToolHandlers::class);
        self::assertSame('invalid_input',
            $handler->run($owner, $target->target_id, str_repeat('a', 8193))['error']['code']);
        self::assertSame('invalid_input',
            $handler->run($owner, $target->target_id, str_repeat('é', 4097))['error']['code']);
        self::assertSame('egress_denied',
            $handler->run($owner, $target->target_id, str_repeat('a', 8192))['error']['code']);

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

        self::assertSame('egress_denied',
            $handler->run($owner, $target->target_id, str_repeat('a', 65536), 30)['error']['code']);
        self::assertSame('egress_denied',
            $handler->run($owner, $target->target_id, str_repeat('é', 32768), 21)['error']['code']);
        foreach ([
            [str_repeat('a', 65537), 10],
            ['echo okay', 31],
            [str_repeat('é', 32769), 10],
        ] as [$command, $seconds]) {
            $result = $handler->run($owner, $target->target_id, $command, $seconds);
            self::assertSame('invalid_input', $result['error']['code']);
            self::assertSame([
                'max_command_bytes' => 65536,
                'max_timeout_seconds' => 30,
            ], $result['error']['effective_limits']);
            self::assertStringNotContainsString($command,
                json_encode($result, JSON_THROW_ON_ERROR));
        }
    }

    public function test_exact_512_kib_command_and_600_second_boundary_apply_before_transport(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_command_timeout_seconds' => 600, 'ssh_command_max_kib' => 512,
        ]);
        $this->app->forgetInstance(OperationalSettings::class);
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new RuntimeException('Isolated deny-only synthetic policy.');
            }
        });
        $handler = app(SshCommandMcpToolHandlers::class);
        foreach ([str_repeat('x', 524288), str_repeat('é', 262144)] as $accepted) {
            self::assertSame('egress_denied', $handler->run($owner, $target->target_id, $accepted, 600)['error']['code']);
        }
        foreach ([[str_repeat('x', 524289), 600], [str_repeat('é', 262145), 600], ['echo x', 601]] as [$command, $seconds]) {
            $result = $handler->run($owner, $target->target_id, $command, $seconds);
            self::assertSame('invalid_input', $result['error']['code']);
            self::assertSame(['max_command_bytes' => 524288, 'max_timeout_seconds' => 600],
                $result['error']['effective_limits']);
        }
        self::assertSame(0, DB::table('activity_events')->where('operation', 'ssh-command-run')
            ->where('outcome', 'unknown')->count());
    }

    public function test_php_worker_deadline_rejects_long_command_before_remote_dispatch(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('operational_settings')->where('id', 1)->update(['ssh_command_timeout_seconds' => 600]);
        $this->app->forgetInstance(OperationalSettings::class);
        $old = (string) ini_get('max_execution_time');
        try {
            ini_set('max_execution_time', '30');
            foreach ([35, 600] as $requestedSeconds) {
                $result = app(SshCommandMcpToolHandlers::class)->run(
                    $owner, $target->target_id, 'echo bounded', $requestedSeconds,
                );
                self::assertSame('timeout_unsupported', $result['error']['code']);
                $activity = DB::table('activity_events')->where('operation', 'ssh-command-run')
                    ->latest('created_at')->first();
                self::assertSame('timeout_unsupported', $activity->error_code);
                self::assertSame('failure', $activity->outcome);
            }
        } finally {
            ini_set('max_execution_time', $old);
        }
    }

    private function target(): Target
    {
        return app(SshTargetRegistration::class)->register(
            'ssh-command', 'SSH command', '127.0.0.1', 22, 'deploy',
            'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32)),
            'password', 'fixture-only-password', null,
        );
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => $role,
            'email' => Str::random(14).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ], []);
    }
}
