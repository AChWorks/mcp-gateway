<?php

namespace Tests\Feature\Admin;

use App\Application\Access\UserAccessManager;
use App\Application\Targets\SshManagedReverseAuthorizedKeys;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Application\Targets\SshManagedReverseHostReadiness;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use RuntimeException;
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

    private function fixtureLocalReady(): void
    {
        $ready = \Mockery::mock(SshManagedReverseHostReadiness::class);
        $ready->shouldReceive('assess')->andReturnUsing(static fn ($gateway) => [
            'state' => $gateway?->enabled ? 'Ready' : 'Disabled',
            'reason' => 'Isolated enabled-host data fixture',
            'external' => 'Not verified',
        ]);
        app()->instance(SshManagedReverseHostReadiness::class, $ready);
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

    public function test_add_target_owns_direct_managed_and_manual_mode_without_new_connector(): void
    {
        $this->actingAs($this->user('owner'));
        $this->get('/admin/targets/create')->assertOk()
            ->assertSee('data-target-ssh-shortcut="direct"', false)
            ->assertSee('data-target-ssh-shortcut="managed"', false)
            ->assertSee('data-target-ssh-shortcut="manual"', false)
            ->assertSee('SSH connection methods');
        $normal = $this->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()->assertSee('name="connector_type"', false)
            ->assertSee('name="ssh_mode" aria-describedby="ssh-mode-help" disabled', false)
            ->assertSee('Managed Reverse SSH — one-command setup')
            ->assertSee('Manual Reverse SSH (advanced)')
            ->assertSee('data-ssh-reverse-route', false)
            ->assertSee('data-ssh-managed', false);
        self::assertMatchesRegularExpression('/data-ssh-reverse-route\s+hidden/', $normal->getContent());
        self::assertMatchesRegularExpression('/data-ssh-managed\s+hidden/', $normal->getContent());
        self::assertStringContainsString('action="'.route('admin.targets.store').'"', $normal->getContent());
        $managed = $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertOk()->assertSee('option value="managed" selected', false)
            ->assertSee('Create Pending Setup and installer command')
            ->assertSee('Open System Reverse SSH settings');
        self::assertStringContainsString('action="'.route('admin.reverse-ssh.targets.store').'"',
            $managed->getContent());
        $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=manual')
            ->assertOk()->assertSee('Gateway-approved loopback listener port');
        $this->get('/admin/targets/create/managed-reverse')
            ->assertRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed');
    }

    public function test_manual_reverse_native_validation_round_trip_keeps_the_selected_mode(): void
    {
        $this->actingAs($this->user('owner'));
        $input = [
            'connector_type' => 'ssh_direct',
            'target_id' => 'manual-native',
            'display_name' => 'Manual no-JS',
            'ssh_host' => 'server.example.test',
            'ssh_port' => 'invalid-port',
            'ssh_username' => 'deploy',
            'ssh_route_mode' => 'reverse',
            'ssh_reverse_port' => '24023',
            'ssh_tunnel_identity' => 'manual-native',
            // No ssh_mode: the no-JavaScript selector is intentionally disabled.
        ];

        $preflight = $this->post(route('admin.targets.preflight'), $input)
            ->assertAdminRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=manual')
            ->assertSessionHasErrors('ssh_port');
        $this->get((string) $preflight->headers->get('Location'))
            ->assertOk()->assertSee('option value="manual" selected', false)
            ->assertSee('Gateway-approved loopback listener port');

        $registration = $this->post(route('admin.targets.store'), $input)
            ->assertAdminRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=manual')
            ->assertSessionHasErrors('ssh_port');
        $this->get((string) $registration->headers->get('Location'))
            ->assertOk()->assertSee('option value="manual" selected', false)
            ->assertSee('Gateway-approved tunnel identity');
        self::assertSame(0, DB::table('targets')->count());
    }

    public function test_managed_enrollment_errors_return_to_canonical_target_form_without_secrets(): void
    {
        $this->actingAs($this->user('owner'));
        $fields = $this->enrollmentFields() + ['connector_type' => 'ssh_direct', 'ssh_mode' => 'managed'];
        $fields['ssh_username'] = 'browser@example.test';
        $response = $this->post('/admin/targets/managed-reverse', $fields)
            ->assertAdminRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertSessionHasErrors('ssh_username')
            ->assertSessionHas('_old_input.target_id', 'managed-target')
            ->assertSessionHas('_old_input.ssh_username', 'browser@example.test')
            ->assertSessionMissing('_old_input.current_password');
        $this->get((string) $response->headers->get('Location'))
            ->assertOk()->assertSee('Enter the existing SSH OS account name')
            ->assertSee('browser@example.test')
            ->assertDontSee('StrongPassword!234');
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());
    }

    public function test_saved_gateway_configuration_shows_summary_until_explicit_edit(): void
    {
        $this->actingAs($this->user('owner'));
        SshManagedReverseGateway::query()->create([
            'id' => 1, 'enabled' => false,
            'control_host' => 'gateway.example.test', 'control_port' => 7770,
            'control_user' => 'mcp-reverse', 'control_host_key' => $this->publicKey(41),
            'revision' => 1, 'publication_pending' => false,
        ]);
        $this->get('/admin/settings/reverse-ssh')
            ->assertOk()->assertSee('Saved Gateway Reverse SSH settings')
            ->assertSee('Edit settings')->assertSee('Disabled')
            ->assertSee('SHA256:')->assertDontSee('name="current_password"', false);
        $this->get('/admin/settings/reverse-ssh?edit=1')
            ->assertOk()->assertSee('Cancel editing')
            ->assertSee('name="current_password"', false)
            ->assertSee('gateway.example.test');
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
        $this->put('/admin/settings/reverse-ssh', $fields)->assertAdminRedirect('/admin/settings/reverse-ssh');
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertSame(1, SshManagedReverseGateway::query()->sole()->revision);
        $this->put('/admin/settings/reverse-ssh', $fields)->assertSessionHasErrors('revision');
        $fields['revision'] = 1;
        $fields['enabled'] = '0';
        $this->put('/admin/settings/reverse-ssh', $fields)->assertAdminRedirect('/admin/settings/reverse-ssh');
        self::assertFalse(SshManagedReverseGateway::active());
    }

    public function test_managed_enrollment_requires_local_ready_at_post_not_only_saved_enabled_configuration(): void
    {
        $this->actingAs($this->user('owner'));
        $payload = $this->enrollmentFields();

        // Unconfigured and explicitly disabled do not create Pending state.
        $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertOk()->assertSee('data-managed-ready="false"', false)
            ->assertSee('Open System Reverse SSH settings');
        $this->post('/admin/targets/managed-reverse', $payload)->assertSessionHasErrors('site');
        $this->put('/admin/settings/reverse-ssh', $this->settings(false))->assertRedirect();
        $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertOk()->assertSee('data-managed-ready="false"', false);
        $this->post('/admin/targets/managed-reverse', $payload)->assertSessionHasErrors('site');

        // An enabled Gateway with no local listener is Degraded, not Ready.
        $enabled = $this->settings(true);
        $enabled['revision'] = 1;
        $this->put('/admin/settings/reverse-ssh', $enabled)->assertRedirect();
        $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertOk()->assertSee('data-managed-ready="false"', false)
            ->assertSee('not Ready (Degraded)');
        $this->post('/admin/targets/managed-reverse', $payload)->assertSessionHasErrors('site');
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());

        // A publication receipt or missing manifest independently closes
        // admission without creating a Target or one-time installer token.
        $gateway = SshManagedReverseGateway::query()->sole();
        $gateway->forceFill(['publication_pending' => true])->save();
        $this->post('/admin/targets/managed-reverse', $payload)->assertSessionHasErrors('site');
        $gateway->forceFill(['publication_pending' => false])->save();
        $manifest = dirname($this->keyFile).'/manifest.json';
        $savedManifest = file_get_contents($manifest);
        unlink($manifest);
        $this->post('/admin/targets/managed-reverse', $payload)->assertSessionHasErrors('site');
        file_put_contents($manifest, $savedManifest);

        // A root-owned manifest describing a different pinned control host
        // must also fail closed before any Target/credential is written.
        $mismatched = json_decode($savedManifest, true, 8, JSON_THROW_ON_ERROR);
        $mismatched['control_host_key'] = $this->publicKey(42);
        file_put_contents($manifest, json_encode($mismatched, JSON_THROW_ON_ERROR));
        $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertOk()->assertSee('data-managed-ready="false"', false);
        $this->post('/admin/targets/managed-reverse', $payload)->assertSessionHasErrors('site');
        file_put_contents($manifest, $savedManifest);

        self::assertSame(0, SshManagedReverseEnrollment::query()->count());
        self::assertSame(0, DB::table('targets')->count());

        // Simulate an actual Ready GET, followed by degraded local host state
        // before the next POST. Presentation is never authorization.
        $this->fixtureLocalReady();
        $ready = $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertOk()->assertSee('data-managed-ready="true"', false);
        self::assertStringNotContainsString('disabled data-target-submit', $ready->getContent());
        $lost = \Mockery::mock(SshManagedReverseHostReadiness::class);
        $lost->shouldReceive('assess')->andReturn([
            'state' => 'Degraded',
            'reason' => 'Pinned local control SSHD handshake failed after page render.',
            'external' => 'Not verified',
        ]);
        app()->instance(SshManagedReverseHostReadiness::class, $lost);
        $this->post('/admin/targets/managed-reverse', $payload)->assertSessionHasErrors('site');
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());
        self::assertSame(0, DB::table('targets')->count());
    }

    public function test_owner_generates_one_command_only_after_approved_bootstrap_and_real_pin(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/targets/managed-reverse', $this->enrollmentFields())
            ->assertSessionHasErrors('site');
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());

        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $this->fixtureLocalReady();
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
        $this->get('/admin/targets/create/managed-reverse')
            ->assertRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed');
        $this->get('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed')
            ->assertOk()->assertDontSee('sha256sum -c -');
    }

    public function test_public_claim_is_scoped_one_use_replay_denied_and_does_not_connect_target(): void
    {
        $this->actingAs($this->user('owner'));
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $this->fixtureLocalReady();
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
        $this->fixtureLocalReady();
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
        ])->assertAdminRedirect('/admin/targets/'.$target->target_id);
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
        $this->fixtureLocalReady();
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

    public function test_owner_reissues_expired_pending_command_on_same_target_with_new_port_and_key(): void
    {
        $this->actingAs($this->user('owner'));
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $this->fixtureLocalReady();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'retry-target', 'Retry Target', '8.8.8.8', 22, 'deploy.prod', $this->publicKey(52),
        );
        $row = $started['enrollment'];
        $oldPort = $row->listener_port;
        $oldEnrollmentId = $row->id;
        $url = '/admin/targets/retry-target/reverse-ssh/reissue';
        $this->get('/admin/targets/retry-target')->assertOk()
            ->assertSee('Retry Pending Setup without deleting this Target')
            ->assertSee('Reissue one-use install command');
        $this->post($url, [
            'confirm_target_id' => 'wrong',
            'current_password' => 'StrongPassword!234',
        ])->assertSessionHasErrors('confirm_target_id');
        $reply = $this->post($url, [
            'confirm_target_id' => 'retry-target',
            'current_password' => 'StrongPassword!234',
        ])->assertOk()->assertSee('Pending Setup created')
            ->assertSee('deploy.prod')->assertSee('--target-user');
        self::assertStringContainsString('no-store', $reply->headers->get('Cache-Control'));
        self::assertSame(1, SshManagedReverseEnrollment::query()->count());
        $newEnrollment = SshManagedReverseEnrollment::query()->sole();
        self::assertNotSame($oldEnrollmentId, $newEnrollment->id);
        self::assertStringContainsString($newEnrollment->id, $reply->getContent());
        self::assertNotSame($oldPort, $newEnrollment->listener_port);
        self::assertNull($row->fresh(), 'Old Target-side installation namespace must be retired.');
        self::assertSame(1, $row->target->sshConfig->fresh()->binding_revision);
        self::assertSame(1, DB::table('ssh_reverse_managed_retired_ports')
            ->where('listener_port', $oldPort)->count());
        self::assertSame('pending', $newEnrollment->state);
    }

    public function test_failed_host_revocation_publication_keeps_owner_retry_visible_and_fences_local_authority(): void
    {
        $this->actingAs($this->user('owner'));
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $this->fixtureLocalReady();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'partial-revoke', 'Partial Revoke', '8.8.8.8', 22, 'deploy', $this->publicKey(52),
        );
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        $writer = new class extends SshManagedReverseAuthorizedKeys
        {
            public bool $fail = true;

            protected function publish(string $contents): void
            {
                if ($this->fail) {
                    throw new RuntimeException('Injected host publication failure');
                }

                parent::publish($contents);
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        $url = '/admin/targets/partial-revoke/reverse-ssh/revoke';
        $payload = ['confirm_target_id' => 'partial-revoke', 'current_password' => 'StrongPassword!234'];
        $this->post($url, $payload)->assertSessionHasErrors('target');
        self::assertSame('revoked', $started['enrollment']->fresh()->state);
        self::assertTrue($started['enrollment']->fresh()->publication_pending);
        self::assertSame(0, TargetCredential::query()->count());
        $this->get('/admin/targets/partial-revoke')->assertOk()
            ->assertSee('Retry host key revocation')
            ->assertSee('publication of the updated control key reader is still pending');
        $this->delete('/admin/targets/partial-revoke/forget', [
            'confirm_target_id' => 'partial-revoke',
            'confirm_local_only' => 'yes',
            'confirm_remote_revocation_unknown' => 'yes',
            'current_password' => 'StrongPassword!234',
        ])->assertSessionHasErrors('target');
        $writer->fail = false;
        $this->post($url, $payload)->assertRedirect();
        self::assertFalse($started['enrollment']->fresh()->publication_pending);
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertSame(1, $started['enrollment']->target->sshConfig->fresh()->binding_revision);
    }

    #[RunInSeparateProcess]
    public function test_owner_settings_fail_closed_when_php_open_basedir_blocks_the_root_owned_manifest(): void
    {
        $this->actingAs($this->user('owner'));
        self::assertNotFalse(ini_set('open_basedir', base_path().PATH_SEPARATOR.sys_get_temp_dir()));
        config()->set('ssh.managed_reverse.host_manifest_file', '/etc/mcp-gateway-reverse/manifest.json');

        $this->get('/admin/settings/reverse-ssh')->assertOk()
            ->assertSee('Needs host setup')->assertSee('Trusted host manifest missing or invalid')
            ->assertSee('open_basedir');
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))
            ->assertSessionHasErrors('enabled');
        self::assertSame(0, SshManagedReverseGateway::query()->count());
    }

    public function test_owner_settings_truthfully_distinguish_host_absence_and_stopped_local_sshd(): void
    {
        $this->actingAs($this->user('owner'));
        $manifest = dirname($this->keyFile).'/manifest.json';
        $original = file_get_contents($manifest);
        unlink($manifest);
        $this->get('/admin/settings/reverse-ssh')->assertOk()
            ->assertSee('Needs host setup')->assertSee('Trusted host manifest missing');
        file_put_contents($manifest, $original);
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        // No OpenSSH listener was started by a PHP feature test.
        $this->get('/admin/settings/reverse-ssh')->assertOk()
            ->assertSee('Degraded')->assertSee('Local control SSHD listener not reachable')
            ->assertSee('Remote Target reachability')
            ->assertSee('sudo systemctl status');
        file_put_contents(dirname($this->keyFile).'/manifest.json', json_encode([
            'version' => 1, 'control_port' => 7770,
            'control_user' => 'other-control',
            'control_host_key' => $this->publicKey(41),
            'authorized_keys_file' => $this->keyFile,
        ], JSON_THROW_ON_ERROR));
        $this->get('/admin/settings/reverse-ssh')->assertOk()
            ->assertSee('Control SSHD host identity, username or port differs');
    }

    public function test_global_publication_receipt_requires_owner_reconciliation(): void
    {
        $this->actingAs($this->user('owner'));
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $this->fixtureLocalReady();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'global-receipt', 'Global Receipt', '8.8.8.8', 22, 'deploy', $this->publicKey(52),
        );
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        $disable = $this->settings(false);
        $disable['revision'] = 1;
        $this->put('/admin/settings/reverse-ssh', $disable)->assertRedirect();
        self::assertSame('', file_get_contents($this->keyFile));
        $writer = new class extends SshManagedReverseAuthorizedKeys
        {
            protected function publish(string $contents): void
            {
                throw new RuntimeException('Fixture publication unavailable');
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        $enable = $this->settings(true);
        $enable['revision'] = 2;
        $failedSave = $this->put('/admin/settings/reverse-ssh', $enable)
            ->assertSessionHasErrors('site')
            ->assertSessionHas('reverse_ssh_operation', 'save_publication_failed');
        self::assertTrue(SshManagedReverseGateway::query()->sole()->publication_pending);
        self::assertSame(3, SshManagedReverseGateway::query()->sole()->revision);
        $this->get((string) $failedSave->headers->get('Location'))
            ->assertOk()->assertSee('Configuration Save could not complete key publication.')
            ->assertSee('Current saved revision: 3')
            ->assertSee('Pending reconciliation')
            ->assertSee('Reconcile restricted public keys')
            ->assertDontSee('The host repair did not complete.');
        $failedRepair = $this->post('/admin/settings/reverse-ssh/repair', [
            'current_password' => 'StrongPassword!234',
        ])->assertSessionHasErrors('site')
            ->assertSessionHas('reverse_ssh_operation', 'repair_failed');
        $this->get((string) $failedRepair->headers->get('Location'))
            ->assertOk()->assertSee('Owner Repair could not complete key publication.')
            ->assertSee('Current saved revision: 3');
        self::assertFalse(SshManagedReverseGateway::active());
        self::assertSame('', file_get_contents($this->keyFile));
        app()->forgetInstance(SshManagedReverseAuthorizedKeys::class);
        $this->post('/admin/settings/reverse-ssh/repair', [
            'current_password' => 'StrongPassword!234',
        ])->assertRedirect();
        self::assertFalse(SshManagedReverseGateway::query()->sole()->publication_pending);
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
    }
}
