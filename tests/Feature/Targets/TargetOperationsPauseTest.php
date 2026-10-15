<?php

namespace Tests\Feature\Targets;

use App\Application\Files\SshWholeFileTransfer;
use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshFileMcpToolHandlers;
use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Mcp\TargetMcpToolHandlers;
use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TargetOperationsPauseTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_toggles_one_target_without_touching_connection_credentials_or_assignments(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $wp = $this->target('wp-a', 'wp_ai_bridge');
        $ssh = $this->target('ssh-b', 'ssh_direct');
        $wp->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        $credential = TargetCredential::query()->create([
            'target_record_id' => $wp->getKey(),
            'connector_type' => 'wp_ai_bridge',
            'purpose' => 'fixture',
            'encrypted_payload' => 'opaque-fixture-not-a-real-token',
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $wp->getKey(),
            'allowed' => true,
        ]);
        self::assertFalse($wp->fresh()->operations_paused);
        self::assertFalse($ssh->fresh()->operations_paused);

        $this->actingAs($owner)->get('/admin/targets')->assertOk()
            ->assertSee('Pause')->assertSee('Gateway operations');
        $this->post(route('admin.targets.operations.update', $wp), ['state' => 'paused'])
            ->assertRedirect(route('admin.targets.show', $wp));
        $this->post(route('admin.targets.operations.update', $wp), ['state' => 'paused'])
            ->assertRedirect(route('admin.targets.show', $wp));

        self::assertTrue($wp->fresh()->operations_paused);
        self::assertFalse($ssh->fresh()->operations_paused);
        self::assertSame(TargetConnectionState::Connected, $wp->fresh()->connection_state);
        self::assertSame('opaque-fixture-not-a-real-token', $credential->fresh()->encrypted_payload);
        self::assertSame(1, DB::table('user_target_access')->where('target_record_id', $wp->getKey())->count());
        self::assertSame(1, DB::table('activity_events')->where('operation', 'target-operations-pause')->count());
        $this->get(route('admin.targets.show', $wp))->assertOk()
            ->assertSee('Resume Target operations')->assertSee('New Gateway operations against this Target are blocked');

        $this->post(route('admin.targets.operations.update', $wp), ['state' => 'enabled'])
            ->assertRedirect(route('admin.targets.show', $wp));
        self::assertFalse($wp->fresh()->operations_paused);
        self::assertSame('opaque-fixture-not-a-real-token', $credential->fresh()->encrypted_payload);
        self::assertSame(1, DB::table('activity_events')->where('operation', 'target-operations-resume')->count());
    }

    public function test_pause_control_is_owner_only_validated_and_web_csrf_protected(): void
    {
        $wp = $this->target('wp-c', 'wp_ai_bridge');
        $operator = $this->user('operator');
        $this->actingAs($operator)->post(route('admin.targets.operations.update', $wp), ['state' => 'paused'])
            ->assertForbidden();
        $this->get(route('admin.targets.show', $wp))->assertForbidden();
        self::assertFalse($wp->fresh()->operations_paused);

        $this->actingAs($this->user('owner'));
        $this->post(route('admin.targets.operations.update', $wp), ['state' => 'invalid'])
            ->assertSessionHasErrors('state');
        self::assertFalse($wp->fresh()->operations_paused);

        $route = Route::getRoutes()->getByName('admin.targets.operations.update');
        self::assertNotNull($route);
        self::assertContains('web', $route->middleware());
        self::assertContains('auth', $route->middleware());
        self::assertSame(['POST'], $route->methods());
    }

    public function test_paused_state_is_visible_only_in_authorized_inventory_and_suppresses_discovery(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $wp = $this->target('wp-d', 'wp_ai_bridge');
        $ssh = $this->target('ssh-e', 'ssh_direct');
        $wp->forceFill(['operations_paused' => true])->save();
        $handlers = app(TargetMcpToolHandlers::class);

        $list = $handlers->targetsList($owner);
        self::assertTrue($list['ok']);
        $items = collect($list['targets'])->keyBy('target_id');
        self::assertTrue($items['wp-d']['operations_paused']);
        self::assertFalse($items['ssh-e']['operations_paused']);
        $wpContext = $handlers->targetContext($owner, 'wp-d');
        self::assertTrue($wpContext['target']['operations_paused']);
        self::assertSame([], $wpContext['target']['file_transfer']['native_interfaces']);
        self::assertSame([], $wpContext['target']['file_transfer']['whole_file_modes']);
        self::assertFalse($handlers->targetContext($owner, 'ssh-e')['target']['operations_paused']);

        // Unauthorized identifiers never reveal that they are paused.
        self::assertSame('target_not_found', $handlers->targetContext($operator, 'wp-d')['error']['code']);
        self::assertSame('target_not_found', app(WordpressTargetMcpToolHandlers::class)
            ->read($operator, 'wp-d')['error']['code']);
        self::assertSame([], $handlers->targetsList($operator)['targets']);
    }

    public function test_paused_wp_ssh_jobs_and_file_stages_fail_before_remote_egress(): void
    {
        $owner = $this->user('owner');
        $wp = $this->target('wp-f', 'wp_ai_bridge');
        $ssh = $this->target('ssh-g', 'ssh_direct');
        $ssh->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        // A stale hydrated Target cannot bypass a pause set in another request.
        $staleSsh = $ssh->fresh();
        $wp->forceFill(['operations_paused' => true])->save();
        DB::table('targets')->where('id', $ssh->getKey())->update(['operations_paused' => true]);

        $wpTools = app(WordpressTargetMcpToolHandlers::class);
        self::assertSame('target_paused', $wpTools->read($owner, 'wp-f')['error']['code']);
        self::assertSame('target_paused', $wpTools->execute($owner, 'wp-f', 'demo/read', [])['error']['code']);

        self::assertSame('target_paused', app(SshCommandMcpToolHandlers::class)
            ->run($owner, 'ssh-g', 'echo not-sent')['error']['code']);
        self::assertSame('target_paused', app(SshFileMcpToolHandlers::class)
            ->stat($owner, 'ssh-g', '/not-sent')['error']['code']);
        self::assertSame('target_paused', app(SshJobMcpToolHandlers::class)
            ->start($owner, 'ssh-g', hash('sha256', 'client'), (string) Str::uuid(), 'echo no-launch')['error']['code']);
        self::assertSame(0, DB::table('ssh_command_jobs')->count());

        try {
            app(SshCommandRuntime::class)->run($owner, $staleSsh, 'echo no-exec');
            self::fail('A stale Target cannot authorize remote exec after a pause.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_paused', $exception->reason);
        }
        try {
            app(SshFileRuntime::class)->stat($owner, $staleSsh, '/no-stat');
            self::fail('A stale Target cannot authorize SFTP after a pause.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_paused', $exception->reason);
        }
        try {
            app(SshWholeFileTransfer::class)->target($owner, 'ssh-g', GatewayPermission::SshFileRead);
            self::fail('A paused Target cannot authorize raw file ingress or egress.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_paused', $exception->reason);
        }

        config()->set('ssh.file_transfer.enabled', true);
        $this->actingAs($owner)->post(route('admin.targets.ssh-files.download', $ssh), [
            'path' => '/no-remote',
        ])->assertRedirect()->assertSessionHasErrors('file_exchange');
    }

    public function test_pause_migration_rollback_refuses_fail_open_when_a_target_is_paused(): void
    {
        $target = $this->target('rollback-pause', 'ssh_direct');
        $target->forceFill(['operations_paused' => true])->save();

        $migration = require database_path('migrations/2026_10_16_000000_add_target_operations_paused.php');
        $this->expectException(\RuntimeException::class);
        $migration->down();
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => 'Test '.$role,
            'email' => Str::random(12).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ]);
    }

    private function target(string $id, string $connector): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => 'Test '.$id,
            'connector_type' => $connector,
        ]);
    }
}
