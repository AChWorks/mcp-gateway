<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\TargetMcpToolHandlers;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TargetTransferCapabilitiesTest extends TestCase
{
    use RefreshDatabase;

    public function test_ssh_sidecar_is_discovered_only_when_enabled_with_actual_per_mode_budgets(): void
    {
        $owner = $this->user('owner');
        $ssh = $this->target('secure-ssh', 'ssh_direct');
        $handlers = app(TargetMcpToolHandlers::class);

        config()->set('ssh.file_transfer.enabled', false);
        $disabled = $handlers->targetContext($owner, $ssh->target_id)['target']['file_transfer'];
        self::assertSame(1, $disabled['schema_version']);
        self::assertSame([], $disabled['whole_file_modes']);
        self::assertSame(['mcp_range_read', 'mcp_single_window_write'],
            array_column($disabled['native_interfaces'], 'kind'));
        self::assertSame(16384, $disabled['native_interfaces'][0]['max_raw_bytes_per_call']);
        self::assertNull($disabled['native_interfaces'][0]['object_size_limit']);
        self::assertFalse($disabled['model_file_consumption_verified']);

        config()->set('ssh.file_transfer.enabled', true);
        config()->set('ssh.file_transfer.max_bytes', 5 * 1024 * 1024 + 13);
        config()->set('ssh.file_transfer.max_seconds', 23);
        $context = $handlers->targetContext($owner, $ssh->target_id);
        $mode = $context['target']['file_transfer']['whole_file_modes'][0];
        self::assertSame('ssh_https_raw_binary_v1', $mode['id']);
        self::assertSame('authenticated_https_binary', $mode['transport']);
        self::assertSame('same_origin_as_mcp_resource', $mode['origin']);
        self::assertSame('/mcp/file-transfer/ssh/secure-ssh/upload', $mode['endpoints']['upload']['path']);
        self::assertSame('/mcp/file-transfer/ssh/secure-ssh/download', $mode['endpoints']['download']['path']);
        self::assertSame(5 * 1024 * 1024 + 13, $mode['max_object_bytes']);
        self::assertSame(23, $mode['max_operation_seconds']);
        self::assertSame('this_synchronous_ssh_mode_only', $mode['bounds_scope']);
        self::assertFalse($mode['resume']);
        self::assertFalse($mode['model_attachment_handoff_verified']);
        self::assertArrayNotHasKey('url', $mode['endpoints']['upload']);
        self::assertStringNotContainsString('password', json_encode($mode, JSON_THROW_ON_ERROR));
    }

    public function test_permissions_filter_direction_and_hide_unauthorized_targets(): void
    {
        $operator = $this->user('operator');
        $ssh = $this->target('selected-ssh', 'ssh_direct');
        $other = $this->target('hidden-ssh', 'ssh_direct');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $ssh->getKey(), 'allowed' => true,
        ]);
        // Operator creation is secure-default-deny for SSH; opt in exactly
        // these two permissions before narrowing this Target to read-only.
        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->whereIn('permission', [
                GatewayPermission::SshFileRead->value, GatewayPermission::SshFileWrite->value,
            ])->delete();
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $ssh->getKey(),
            'permission' => GatewayPermission::SshFileWrite->value,
        ]);
        config()->set('ssh.file_transfer.enabled', true);
        $handlers = app(TargetMcpToolHandlers::class);
        $context = $handlers->targetContext($operator, 'selected-ssh');
        self::assertTrue($context['ok']);
        $transfer = $context['target']['file_transfer'];
        self::assertSame(['mcp_range_read'], array_column($transfer['native_interfaces'], 'kind'));
        self::assertCount(1, $transfer['whole_file_modes']);
        self::assertSame(['download'], array_keys($transfer['whole_file_modes'][0]['endpoints']));

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $ssh->getKey(),
            'permission' => GatewayPermission::SshFileRead->value,
        ]);
        $denied = $handlers->targetContext($operator, 'selected-ssh')['target']['file_transfer'];
        self::assertSame([], $denied['whole_file_modes']);
        self::assertSame([], $denied['native_interfaces']);

        $hidden = $handlers->targetContext($operator, $other->target_id);
        self::assertSame($handlers->targetContext($operator, 'no-such-ssh'), $hidden);
        self::assertSame('target_not_found', $hidden['error']['code']);
    }

    public function test_wordpress_native_abilities_never_inherit_ssh_limits_or_claim_binary_file_mode(): void
    {
        $owner = $this->user('owner');
        $wp = $this->target('site-wp', 'wp_ai_bridge');
        config()->set('ssh.file_transfer.enabled', true);
        config()->set('ssh.file_transfer.max_bytes', 1048576);
        $transfer = app(TargetMcpToolHandlers::class)
            ->targetContext($owner, $wp->target_id)['target']['file_transfer'];

        self::assertSame([], $transfer['whole_file_modes']);
        self::assertSame('mcp_target_abilities', $transfer['native_interfaces'][0]['kind']);
        self::assertSame('wordpress-abilities-read', $transfer['native_interfaces'][0]['discovery_tool']);
        self::assertSame('wordpress-ability-execute', $transfer['native_interfaces'][0]['execution_tool']);
        self::assertSame('per_discovered_ability_and_effective_transport',
            $transfer['native_interfaces'][0]['operation_limits']);
        self::assertFalse($transfer['native_interfaces'][0]['raw_whole_file_http']);
        self::assertArrayNotHasKey('max_object_bytes', $transfer);
        self::assertFalse($transfer['model_file_consumption_verified']);

        $viewer = $this->user('viewer');
        DB::table('user_target_access')->insert([
            'user_id' => $viewer->getKey(), 'target_record_id' => $wp->getKey(), 'allowed' => true,
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $viewer->getKey(), 'target_record_id' => $wp->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
        ]);
        $limited = app(TargetMcpToolHandlers::class)
            ->targetContext($viewer, $wp->target_id)['target']['file_transfer'];
        self::assertNull($limited['native_interfaces'][0]['execution_tool']);

        // A high-trust execution-only grant must not be hidden merely
        // because it is not one of the common readonly/mutating classes.
        // Use an administrator with Selected scope to prove that the
        // destructive-only permission remains a real executable native mode.
        $admin = $this->user('administrator');
        DB::table('user_target_access')->insert([
            'user_id' => $admin->getKey(), 'target_record_id' => $wp->getKey(), 'allowed' => true,
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $admin->getKey(), 'target_record_id' => $wp->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesInspect->value,
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $admin->getKey(), 'target_record_id' => $wp->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $admin->getKey(), 'target_record_id' => $wp->getKey(),
            'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
        ]);
        $executeOnly = app(TargetMcpToolHandlers::class)
            ->targetContext($admin, $wp->target_id)['target']['file_transfer'];
        self::assertSame([], $executeOnly['whole_file_modes']);
        self::assertNull($executeOnly['native_interfaces'][0]['discovery_tool']);
        self::assertSame('wordpress-ability-execute', $executeOnly['native_interfaces'][0]['execution_tool']);
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => 'Capability '.$role,
            'email' => Str::random(14).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ], []);
    }

    private function target(string $id, string $type): Target
    {
        return Target::query()->create([
            'target_id' => $id, 'display_name' => $id, 'connector_type' => $type,
        ]);
    }
}
