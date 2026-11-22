<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\SshOperatorMcpToolHandlers;
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

final class SshOperatorMcpTest extends TestCase
{
    use RefreshDatabase;

    public function test_every_operator_capability_respects_exact_target_scope_and_existing_grants(): void
    {
        $operator = $this->user('operator');
        $owner = $this->user('owner');
        $target = $this->target();
        $wp = Target::query()->create([
            'target_id' => 'wp-only', 'display_name' => 'WordPress only',
            'connector_type' => 'wp_ai_bridge',
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        $this->denyOutbound();
        $tools = app(SshOperatorMcpToolHandlers::class);
        $id = $target->target_id;

        foreach ([
            $tools->system($operator, $id),
            $tools->network($operator, $id, 'dns', 'localhost'),
            $tools->logs($operator, $id),
            $tools->logs($operator, $id, 'file', path: '/private/fixture.log'),
            $tools->patch($operator, $id, '/private/fixture.conf', 'old', 'new'),
            $tools->verify($operator, $id, 'service_state', 'active', service: 'ssh.service'),
        ] as $denied) {
            self::assertFalse($denied['ok']);
            self::assertSame('target_not_found', $denied['error']['code']);
        }

        self::assertSame('target_not_found', $tools->system($owner, $wp->target_id)['error']['code']);
        self::assertSame('target_not_found', $tools->network($owner, '../bad', 'tcp', 'localhost')['error']['code']);
        self::assertSame('target_not_found', $tools->patch($operator, $wp->target_id, '/etc/a', 'x', 'y')['error']['code']);

        // Command permission can be granted without SFTP read/write. Existing
        // role ceiling + Target scope + direct denials still apply.
        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshCommandRun->value)->delete();
        self::assertSame('egress_denied', $tools->system($operator, $id)['error']['code']);
        self::assertSame('egress_denied', $tools->network($operator, $id, 'dns', 'localhost')['error']['code']);
        self::assertSame('egress_denied', $tools->verify(
            $operator, $id, 'service_state', 'active', service: 'ssh.service',
        )['error']['code']);
        self::assertSame('egress_denied', $tools->logs($operator, $id)['error']['code']);
        self::assertSame('target_not_found', $tools->logs($operator, $id, 'file', path: '/private/fixture.log')['error']['code']);
        self::assertSame('target_not_found', $tools->patch($operator, $id, '/private/fixture', 'x', 'y')['error']['code']);

        // Neither transport denial nor failed validation may leak commands,
        // file contents or URL data into general-purpose Activity records.
        $activity = json_encode(DB::table('activity_events')
            ->where('operation', 'like', 'ssh-%')->get(), JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('/private/fixture', $activity);
        self::assertStringNotContainsString('ssh.service', $activity);
    }

    public function test_patch_apply_requires_both_file_grants_and_prior_preview_digest(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $this->denyOutbound();
        $tools = app(SshOperatorMcpToolHandlers::class);
        $id = $target->target_id;

        self::assertSame('invalid_input', $tools->patch(
            $owner, $id, '/etc/fixture.conf', 'old', 'new', true,
        )['error']['code']);
        self::assertSame('invalid_input', $tools->patch(
            $owner, $id, '/etc/fixture.conf', 'old', 'new', true, 'bad-sha',
        )['error']['code']);
        self::assertSame('egress_denied', $tools->patch(
            $owner, $id, '/etc/fixture.conf', 'old', 'new', false,
        )['error']['code']);

        // No write permission can be inferred from read permission or the
        // existence of an apparently well-formed client supplied digest.
        $operator = $this->user('operator');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshFileRead->value)->delete();
        self::assertSame('target_not_found', $tools->patch(
            $operator, $id, '/etc/fixture.conf', 'old', 'new', true, str_repeat('a', 64),
        )['error']['code']);

        $target->forceFill(['operations_paused' => true])->save();
        self::assertSame('target_paused', $tools->patch(
            $owner, $id, '/etc/fixture.conf', 'old', 'new',
        )['error']['code']);
    }

    public function test_validation_rejects_dangerous_network_source_and_service_parameters_without_dial(): void
    {
        $owner = $this->user('owner');
        $id = $this->target()->target_id;
        $this->denyOutbound();
        $tools = app(SshOperatorMcpToolHandlers::class);

        self::assertSame('invalid_input', $tools->system(
            $owner, $id, ['service'], 'daemon; touch /tmp/bad',
        )['error']['code']);
        self::assertSame('invalid_input', $tools->network(
            $owner, $id, 'tcp', 'host; whoami', 443,
        )['error']['code']);
        self::assertSame('invalid_input', $tools->network(
            $owner, $id, 'udp_dns', '127.0.0.1', 53,
        )['error']['code']);
        self::assertSame('invalid_input', $tools->logs(
            $owner, $id, since: 'yesterday',
        )['error']['code']);
        self::assertSame('invalid_input', $tools->verify(
            $owner, $id, 'service_state', 'active', service: '--fake',
        )['error']['code']);
        self::assertSame('egress_denied', $tools->verify(
            $owner, $id, 'tcp_open', 'open', host: '127.0.0.1', port: 443,
        )['error']['code']);
        self::assertSame('invalid_input', $tools->verify(
            $owner, $id, 'http_status', '200', host: '127.0.0.1', port: 443,
            path: "/health\nunsafe",
        )['error']['code']);
        self::assertSame('egress_denied', $tools->verify(
            $owner, $id, 'http_status', '200', host: '127.0.0.1', port: 443,
            path: '/health',
        )['error']['code']);

        self::assertSame('invalid_input', $tools->logs(
            $owner, $id, 'file', path: '/tmp/log', level: 'err',
        )['error']['code']);
    }

    private function target(): Target
    {
        $target = app(SshTargetRegistration::class)->register(
            'ssh-ops', 'SSH operator', '127.0.0.1', 22, 'deploy',
            'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32)),
            'password', 'fixture-only-password', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target;
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

    private function denyOutbound(): void
    {
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new RuntimeException('Isolated fixture: no outbound connections.');
            }
        });
    }
}
