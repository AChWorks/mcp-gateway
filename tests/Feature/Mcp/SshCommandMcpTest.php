<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
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
        $operator = $this->user('operator');
        $target = $this->target();
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        // Fixture policy forbids every dial. Even authorized calls must fail
        // without contacting a live server or exposing transport details.
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint): array
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

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        self::assertSame('target_not_found', $handler->run($operator, $target->target_id, $command)['error']['code']);
        self::assertStringNotContainsString($command, json_encode(
            DB::table('activity_events')->where('operation', 'ssh-command-run')->get(), JSON_THROW_ON_ERROR,
        ));
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
