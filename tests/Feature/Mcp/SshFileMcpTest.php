<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\SshFileMcpToolHandlers;
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

final class SshFileMcpTest extends TestCase
{
    use RefreshDatabase;

    public function test_nonowners_stay_default_denied_and_unauthorized_targets_are_not_enumerable(): void
    {
        $operator = $this->user('operator');
        $owner = $this->user('owner');
        $target = $this->target();
        $wordpress = Target::query()->create([
            'target_id' => 'wp-sftp-mismatch', 'display_name' => 'WP', 'connector_type' => 'wp_ai_bridge',
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        $files = app(SshFileMcpToolHandlers::class);
        $secret = '/home/secret-private-path';

        self::assertSame('target_not_found', $files->stat($operator, $target->target_id, $secret)['error']['code']);
        self::assertSame('target_not_found', $files->list($operator, $target->target_id, $secret)['error']['code']);
        self::assertSame('target_not_found', $files->read($operator, $target->target_id, $secret)['error']['code']);
        self::assertSame('target_not_found', $files->write($operator, $target->target_id, $secret, 'AA==')['error']['code']);
        self::assertSame('target_not_found', $files->stat($owner, $wordpress->target_id, '/')['error']['code']);
        self::assertSame('target_not_found', $files->stat($owner, '../ssh-file', '/')['error']['code']);
        self::assertSame('target_not_found', $files->stat($owner, 'missing-ssh-file', '/')['error']['code']);

        foreach (DB::table('activity_events')->where('operation', 'like', 'ssh-file-%')->get() as $event) {
            self::assertStringNotContainsString($secret, (string) json_encode($event, JSON_THROW_ON_ERROR));
        }
    }

    public function test_exact_read_write_permissions_are_independent_and_validation_precedes_transport(): void
    {
        $operator = $this->user('operator');
        $owner = $this->user('owner');
        $target = $this->target();
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint): array
            {
                throw new RuntimeException('Fixture: no remote network allowed.');
            }
        });

        $files = app(SshFileMcpToolHandlers::class);
        $id = $target->target_id;
        self::assertSame('invalid_input', $files->stat($owner, $id, '../etc/passwd')['error']['code']);
        self::assertSame('invalid_input', $files->list($owner, $id, '/', 101)['error']['code']);
        self::assertSame('invalid_input', $files->read($owner, $id, '/', -1)['error']['code']);
        self::assertSame('invalid_input', $files->read($owner, $id, '/', 0, 16385)['error']['code']);
        self::assertSame('invalid_input', $files->read($owner, $id, '/', 0, 1, 10)['error']['code']);
        self::assertSame('invalid_input', $files->write($owner, $id, '/sample', '!!!!')['error']['code']);
        self::assertSame('invalid_input', $files->write($owner, $id, '/sample', 'AA==', true)['error']['code']);
        self::assertSame('invalid_input', $files->write($owner, $id, '/sample', base64_encode(str_repeat('z', 16385)))['error']['code']);
        self::assertSame('egress_denied', $files->stat($owner, $id, '/')['error']['code']);

        // Read only: the explicit global read grant cannot elevate write.
        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshFileRead->value)->delete();
        self::assertSame('egress_denied', $files->read($operator, $id, '/sample')['error']['code']);
        self::assertSame('target_not_found', $files->write($operator, $id, '/sample', 'AA==')['error']['code']);

        // Explicit target-level denial prevents even an otherwise allowed read.
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshFileRead->value,
        ]);
        self::assertSame('target_not_found', $files->stat($operator, $id, '/')['error']['code']);
        DB::table('user_target_permission_denials')->where('user_id', $operator->getKey())->delete();

        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshFileWrite->value)->delete();
        self::assertSame('egress_denied', $files->write($operator, $id, '/sample', 'AA==')['error']['code']);
        $activity = (string) json_encode(DB::table('activity_events')->where('operation', 'like', 'ssh-file-%')->get(), JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('Fixture: no remote network allowed.', $activity);
        self::assertStringNotContainsString('/sample', $activity);
    }

    private function target(): Target
    {
        return app(SshTargetRegistration::class)->register(
            'ssh-file', 'SSH file', '127.0.0.1', 22, 'deploy',
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
