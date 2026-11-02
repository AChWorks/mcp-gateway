<?php

namespace Tests\Feature\Admin;

use App\Application\Access\UserAccessManager;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Tests\TestCase;

final class SshManagedReverseAdminTest extends TestCase
{
    use RefreshDatabase;

    private string $keyFile;

    protected function setUp(): void
    {
        parent::setUp();
        $dir = storage_path('framework/testing/reverse-admin-'.bin2hex(random_bytes(8)));
        File::ensureDirectoryExists($dir, 0700);
        $this->keyFile = $dir.'/authorized_keys';
        config()->set('ssh.managed_reverse.authorized_keys_file', $this->keyFile);
        config()->set('ssh.managed_reverse.host_manifest_file', $dir.'/manifest.json');
        config()->set('app.url', 'https://gateway.example.test');
        config()->set('ssh.reverse_approved_routes', '{}');
        file_put_contents($this->keyFile, '');
        file_put_contents($dir.'/manifest.json', json_encode([
            'version' => 1, 'control_port' => 7770,
            'control_user' => 'mcp-reverse', 'control_host_key' => $this->publicKey(41),
            'authorized_keys_file' => $this->keyFile,
        ], JSON_THROW_ON_ERROR));
    }

    protected function tearDown(): void
    {
        File::deleteDirectory(dirname($this->keyFile));
        parent::tearDown();
    }

    private function publicKey(int $byte): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr($byte), 32));
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => ucfirst($role),
            'email' => Str::random(12).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ], []);
    }

    private function settings(bool $enabled): array
    {
        return [
            'revision' => 0,
            'enabled' => $enabled ? '1' : '0',
            'control_host' => 'gateway.example.test',
            'control_port' => 7770,
            'control_user' => 'mcp-reverse',
            'control_host_key' => $this->publicKey(41),
            'current_password' => 'StrongPassword!234',
        ];
    }

    private function enrollmentFields(): array
    {
        return [
            'target_id' => 'managed-target',
            'display_name' => 'Managed Reverse Target',
            'ssh_host' => '2606:4700:4700::1111',
            'ssh_port' => 22,
            'ssh_username' => 'deploy',
            'ssh_host_key' => $this->publicKey(52),
            'ssh_trust_confirmed' => 'yes',
            'current_password' => 'StrongPassword!234',
        ];
    }

    public function test_non_owner_cannot_view_configure_or_enroll_managed_reverse(): void
    {
        $this->get('/admin/settings/reverse-ssh')->assertRedirect('/admin/login');
        $this->actingAs($this->user('administrator'));
        $this->get('/admin/settings/reverse-ssh')->assertForbidden();
        $this->get('/admin/targets/create/managed-reverse')->assertForbidden();
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertForbidden();
        $this->post('/admin/targets/managed-reverse', $this->enrollmentFields())->assertForbidden();
    }

    public function test_settings_are_off_by_default_and_require_owner_password_bootstrap_and_revision(): void
    {
        $this->actingAs($this->user('owner'));
        $this->get('/admin/settings/reverse-ssh')->assertOk()->assertSee('Disabled');
        $fields = $this->settings(true);
        $fields['current_password'] = 'wrong-password';
        $this->put('/admin/settings/reverse-ssh', $fields)->assertSessionHasErrors('current_password');
        self::assertSame(0, SshManagedReverseGateway::query()->count());

        $fields = $this->settings(true);
        $this->put('/admin/settings/reverse-ssh', $fields)->assertRedirect('/admin/settings/reverse-ssh');
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertSame(1, SshManagedReverseGateway::query()->sole()->revision);
        $this->put('/admin/settings/reverse-ssh', $fields)->assertSessionHasErrors('revision');
        $fields['revision'] = 1;
        $fields['enabled'] = '0';
        $this->put('/admin/settings/reverse-ssh', $fields)->assertRedirect('/admin/settings/reverse-ssh');
        self::assertFalse(SshManagedReverseGateway::active());
    }

    public function test_owner_generates_one_command_only_after_approved_bootstrap_and_real_pin(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/targets/managed-reverse', $this->enrollmentFields())
            ->assertSessionHasErrors('site');
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());

        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $reply = $this->post('/admin/targets/managed-reverse', $this->enrollmentFields())
            ->assertOk()
            ->assertSee('Pending Setup created')
            ->assertSee('sha256sum -c -')
            ->assertSee('sudo bash')
            ->assertSee('id -u')
            ->assertSee('--target-user');
        self::assertStringContainsString('no-store', $reply->headers->get('Cache-Control'));
        self::assertSame('pending', SshManagedReverseEnrollment::query()->sole()->state);
        self::assertSame('pending', SshManagedReverseEnrollment::query()->sole()->target->connection_state->value);
        self::assertSame('reverse', SshTargetConfig::query()->sole()->route_mode);
        self::assertStringNotContainsString('BEGIN OPENSSH PRIVATE KEY', $reply->getContent());
        $this->get('/admin/targets/create/managed-reverse')->assertOk()
            ->assertDontSee('sha256sum -c -');
    }

    public function test_public_claim_is_scoped_one_use_replay_denied_and_does_not_connect_target(): void
    {
        $this->actingAs($this->user('owner'));
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'target-claim', 'Claim Target', '8.8.8.8', 22, 'deploy', $this->publicKey(52),
        );
        $enrollment = $started['enrollment'];
        $url = '/reverse-ssh/enroll/'.$enrollment->id.'/claim';
        $this->postJson($url, [
            'token' => str_repeat('0', 64), 'public_key' => $this->publicKey(61),
        ])->assertStatus(409)->assertJsonPath('error', 'enrollment_rejected');
        $response = $this->postJson($url, [
            'token' => $started['token'], 'public_key' => $this->publicKey(61),
        ])->assertOk()
            ->assertJsonPath('state', 'control_key_activated')
            ->assertJsonPath('verified', false)
            ->assertJsonPath('target_port', 22);
        self::assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        self::assertArrayNotHasKey('token', $response->json());
        self::assertStringNotContainsString($started['token'], $response->getContent());
        $this->postJson($url, [
            'token' => $started['token'], 'public_key' => $this->publicKey(61),
        ])->assertStatus(409);
        self::assertSame('pending', $enrollment->target->fresh()->connection_state->value);
        self::assertSame('active', $enrollment->fresh()->state);
    }

    public function test_owner_revocation_fences_keys_and_credential_and_blocks_bypass_by_disconnect(): void
    {
        $this->actingAs($this->user('owner'));
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'managed-revoked', 'Revoke Target', '8.8.8.8', 22, 'deploy', $this->publicKey(52),
        );
        $row = $started['enrollment'];
        app(SshManagedReverseEnrollmentService::class)->claim(
            $row->id, $started['token'], $this->publicKey(61),
        );
        $target = $row->target;
        $this->post('/admin/targets/'.$target->target_id.'/disconnect')
            ->assertSessionHasErrors('target');
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
        $url = '/admin/targets/'.$target->target_id.'/reverse-ssh/revoke';
        $this->post($url, [
            'confirm_target_id' => $target->target_id, 'current_password' => 'wrong-password',
        ])->assertSessionHasErrors('current_password');
        self::assertSame('active', $row->fresh()->state);

        $this->post($url, [
            'confirm_target_id' => $target->target_id,
            'current_password' => 'StrongPassword!234',
        ])->assertRedirect('/admin/targets/'.$target->target_id);
        self::assertSame('revoked', $row->fresh()->state);
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertSame('disconnected', $target->fresh()->connection_state->value);
        self::assertSame(0, TargetCredential::query()->where('target_record_id', $target->id)->count());
        self::assertSame(1, SshTargetConfig::query()->sole()->binding_revision);
        $this->post('/admin/targets/'.$target->target_id.'/disconnect')->assertRedirect();
    }

    public function test_owner_forget_requires_managed_route_revocation_first(): void
    {
        $this->actingAs($this->user('owner'));
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'managed-forget', 'Forget Target', '8.8.8.8', 22, 'deploy', $this->publicKey(52),
        );
        $payload = [
            'confirm_target_id' => 'managed-forget',
            'confirm_local_only' => 'yes',
            'confirm_remote_revocation_unknown' => 'yes',
            'current_password' => 'StrongPassword!234',
        ];
        $this->delete('/admin/targets/managed-forget/forget', $payload)->assertSessionHasErrors('target');
        self::assertSame('pending', $started['enrollment']->fresh()->state);
    }
}
