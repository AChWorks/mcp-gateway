<?php

namespace Tests\Feature\Admin;

use App\Application\Access\UserAccessManager;
use App\Application\Batch\TargetBatchBinding;
use App\Application\Targets\SshManagedReverseAuthorizedKeys;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Application\Targets\SshManagedReverseHostReadiness;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\SshVerificationState;
use App\Application\Targets\TargetTransportBinding;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
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
            ->assertSee('Open Connectivity Reverse SSH settings');
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

    public function test_target_creator_can_enroll_but_cannot_configure_reverse_infrastructure(): void
    {
        $this->get('/admin/settings/reverse-ssh')->assertRedirect('/admin/login');
        $this->actingAs($this->user('administrator'));
        $this->get('/admin/settings/reverse-ssh')->assertForbidden();
        $this->get('/admin/targets/create/managed-reverse')->assertRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed');
        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertForbidden();
        $this->post('/admin/targets/managed-reverse', $this->enrollmentFields())->assertSessionHasErrors('site');
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());
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
            ->assertSee('Open Connectivity Reverse SSH settings');
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

    public function test_target_creator_generates_one_command_only_after_approved_bootstrap_and_real_pin(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/targets/managed-reverse', $this->enrollmentFields())
            ->assertSessionHasErrors('site');
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());

        $this->put('/admin/settings/reverse-ssh', $this->settings(true))->assertRedirect();
        $this->fixtureLocalReady();
        $administrator = $this->user('administrator');
        $administrator->forceFill(['self_created_target_access' => true])->save();
        $this->actingAs($administrator);
        $this->post('/admin/targets/managed-reverse', [...$this->enrollmentFields(), 'connection_relay_id' => 'invalid'])->assertSessionHasErrors('connection_relay_id');
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
        self::assertSame($administrator->id, SshManagedReverseEnrollment::query()->sole()->target->created_by_user_id);
        self::assertSame('reverse', Target::query()->sole()->transportKind());
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

    public function test_owner_revocation_fences_control_key_but_preserves_login_credential(): void
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
        $ciphertext = TargetCredential::query()->where('target_record_id', $target->id)->sole()->encrypted_payload;
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
        self::assertSame('pending', $target->fresh()->connection_state->value);
        self::assertSame($ciphertext, TargetCredential::query()->where('target_record_id', $target->id)->sole()->encrypted_payload);
        self::assertSame(3, Target::query()->sole()->transport_revision);
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
            ->assertSee('Reissue Managed Reverse route (advanced)')
            ->assertSee('Reissue setup command');
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
        self::assertSame(2, $row->target->fresh()->transport_revision);
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
        $writer = new class(app(TargetTransportBinding::class)) extends SshManagedReverseAuthorizedKeys
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
        self::assertSame(1, TargetCredential::query()->count());
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
        self::assertSame(3, $started['enrollment']->target->fresh()->transport_revision);
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
        // The development server may legitimately have a real SSHD listener
        // on the old test port 7770. Choose a fresh loopback port for this
        // no-listener test, while keeping manifest and setting consistent.
        $reservation = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($reservation);
        $reservedAddress = stream_socket_get_name($reservation, false);
        self::assertIsString($reservedAddress);
        $port = (int) substr(strrchr($reservedAddress, ':'), 1);
        self::assertGreaterThan(1023, $port);
        fclose($reservation);
        $storedManifest = json_decode($original, true, 8, JSON_THROW_ON_ERROR);
        $storedManifest['control_port'] = $port;
        file_put_contents($manifest, json_encode($storedManifest, JSON_THROW_ON_ERROR));
        $settings = $this->settings(true);
        $settings['control_port'] = $port;
        $this->put('/admin/settings/reverse-ssh', $settings)->assertRedirect();
        // No fixture listener was started on the reserved ephemeral port.
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

    public function test_failed_save_and_repair_keep_operation_identity_with_one_use_feedback_across_tabs(): void
    {
        $this->actingAs($this->user('owner'));
        $writer = new class(app(TargetTransportBinding::class)) extends SshManagedReverseAuthorizedKeys
        {
            protected function publish(string $contents): void
            {
                throw new RuntimeException('Disposable key publication failure');
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);

        foreach ([['repair', 'save'], ['save', 'repair']] as $order) {
            $revision = SshManagedReverseGateway::query()->find(1)?->revision ?? 0;
            $input = $this->settings(true);
            $input['revision'] = $revision;
            $save = $this->put('/admin/settings/reverse-ssh', $input)
                ->assertSessionHasErrors('site');
            $repair = $this->post('/admin/settings/reverse-ssh/repair', [
                'current_password' => 'StrongPassword!234',
            ])->assertSessionHasErrors('site');

            $urls = [
                'save' => (string) $save->headers->get('Location'),
                'repair' => (string) $repair->headers->get('Location'),
            ];
            self::assertStringContainsString('_admin_feedback=', $urls['save']);
            self::assertStringContainsString('_admin_feedback=', $urls['repair']);
            self::assertNotSame($urls['save'], $urls['repair']);
            self::assertSame($revision + 1, SshManagedReverseGateway::query()->sole()->revision);
            self::assertTrue(SshManagedReverseGateway::query()->sole()->publication_pending);

            // An unrelated same-session GET ages the native Laravel flash.
            // Each tab must still see *only* the operation-bound errors.
            $this->get('/admin/targets')->assertOk()
                ->assertDontSee('could not complete key publication.');
            foreach ($order as $operation) {
                $page = $this->get($urls[$operation])->assertOk()
                    ->assertSee('Current saved revision: '.($revision + 1))
                    ->assertSee('Pending reconciliation')
                    ->assertSee('Reconcile restricted public keys');
                if ($operation === 'save') {
                    $page->assertSee('Configuration Save could not complete key publication.')
                        ->assertDontSee('Owner Repair could not complete key publication.')
                        ->assertDontSee('The host repair did not complete.');
                } else {
                    $page->assertSee('Owner Repair could not complete key publication.')
                        ->assertDontSee('Configuration Save could not complete key publication.');
                }
            }
            foreach ($urls as $url) {
                $this->get($url)->assertOk()
                    ->assertDontSee('Configuration Save could not complete key publication.')
                    ->assertDontSee('Owner Repair could not complete key publication.');
            }
        }
    }

    public function test_global_disable_and_reenable_fence_old_bindings_without_touching_other_paths_or_login(): void
    {
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/reverse-ssh';
        $this->put($url, $this->settings(true))->assertSessionHasNoErrors();
        $this->fixtureLocalReady();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'aba-managed', 'Managed', '8.8.8.8', 2222, 'deploy', $this->publicKey(52),
        );
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        $target = Target::query()->where('target_id', 'aba-managed')->sole();
        $config = $target->sshConfig;
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $verification = app(SshVerificationState::class);
        $initial = $verification->begin($target, $config, $credential);
        $verification->succeeded($target, $config, $credential, $initial, '127.0.0.1');
        $target->refresh();
        $config->refresh();
        $oldAttempt = $verification->begin($target, $config, $credential);
        $binding = SshTargetBinding::hash($target, $config);
        $batch = app(TargetBatchBinding::class);
        $batchBinding = $batch->hash($target);
        self::assertNotNull($batchBinding);
        $epoch = $target->transport_revision;
        $keyPolicy = file_get_contents($this->keyFile);
        self::assertStringContainsString($this->publicKey(61), $keyPolicy);

        config()->set('ssh.reverse_approved_routes', json_encode([
            'manual-unaffected' => ['port' => 62441, 'tunnel_identity' => 'manual-fixture'],
        ], JSON_THROW_ON_ERROR));
        $registration = app(SshTargetRegistration::class);
        $manual = $registration->register('manual-unaffected', 'Manual', '1.1.1.1', 22,
            'deploy', $this->publicKey(52), 'password', 'fixture', null,
            routeMode: 'reverse', reversePort: 62441, tunnelIdentity: 'manual-fixture');
        $direct = $registration->register('direct-unaffected', 'Direct', '8.8.4.4', 2222,
            'deploy', $this->publicKey(52), 'password', 'fixture', null);
        $otherBindings = [SshTargetBinding::hash($manual, $manual->sshConfig), SshTargetBinding::hash($direct, $direct->sshConfig)];

        $this->put($url, [...$this->settings(true), 'revision' => 1])->assertSessionHasNoErrors();
        self::assertSame(1, SshManagedReverseGateway::query()->sole()->revision);
        self::assertSame($epoch, $target->fresh()->transport_revision);
        self::assertSame($keyPolicy, file_get_contents($this->keyFile));

        // Fail the actual key publication AFTER the disable intent commits.
        app()->instance(SshManagedReverseAuthorizedKeys::class, new class(app(TargetTransportBinding::class)) extends SshManagedReverseAuthorizedKeys
        {
            protected function publish(string $contents): void
            {
                throw new RuntimeException('Disposable disable publication failure');
            }
        });
        $this->put($url, [...$this->settings(false), 'revision' => 1])->assertSessionHasErrors('site');
        self::assertFalse(SshManagedReverseGateway::active());
        self::assertTrue(SshManagedReverseGateway::query()->sole()->publication_pending);
        self::assertSame($epoch + 1, $target->fresh()->transport_revision);
        self::assertSame($keyPolicy, file_get_contents($this->keyFile));
        $policy = app(SshReverseRoutePolicy::class);
        try {
            $policy->forTarget($target->fresh());
            self::fail('A stale published key cannot authorize a disabled managed route.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('reverse_route_not_approved', $exception->reason);
        }

        app()->forgetInstance(SshManagedReverseAuthorizedKeys::class);
        $this->post($url.'/repair', ['current_password' => 'StrongPassword!234'])->assertSessionHasNoErrors();
        self::assertSame('', file_get_contents($this->keyFile));
        $this->put($url, [...$this->settings(false), 'revision' => 2])->assertSessionHasNoErrors();
        self::assertSame(2, SshManagedReverseGateway::query()->sole()->revision);
        self::assertSame($epoch + 1, $target->fresh()->transport_revision);

        $disabledTarget = $target->fresh();
        $disabledConfig = $config->fresh();
        $disabledAttempt = $verification->begin($disabledTarget, $disabledConfig, $credential);
        $disabledBinding = SshTargetBinding::hash($disabledTarget, $disabledConfig);
        $disabledBatch = $batch->hash($disabledTarget);
        $this->put($url, [...$this->settings(true), 'revision' => 2])->assertSessionHasNoErrors();
        $fresh = $target->fresh();
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertNotNull($policy->forTarget($fresh));
        self::assertSame($keyPolicy, file_get_contents($this->keyFile));
        self::assertSame($epoch + 2, $fresh->transport_revision);
        self::assertSame($target->reverse_listener_port, $fresh->reverse_listener_port);
        self::assertSame($target->reverse_tunnel_identity, $fresh->reverse_tunnel_identity);
        self::assertSame('connected', $fresh->connection_state->value);
        self::assertSame($credential->encrypted_payload, $credential->fresh()->encrypted_payload);
        self::assertNotSame($binding, SshTargetBinding::hash($fresh, $config->fresh()));
        self::assertNotNull($batch->hash($fresh));
        self::assertNotSame($batchBinding, $batch->hash($fresh));
        self::assertNotSame($disabledBinding, SshTargetBinding::hash($fresh, $config->fresh()));
        self::assertNotSame($disabledBatch, $batch->hash($fresh));
        $verification->failed($disabledTarget, $disabledConfig, $credential, $disabledAttempt, 'tcp_unreachable');
        try {
            $verification->succeeded($disabledTarget, $disabledConfig, $credential, $disabledAttempt, '127.0.0.1');
            self::fail('A verification captured while disabled must not revive after Enable.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_changed', $exception->reason);
        }
        self::assertNull($fresh->last_tested_at);
        self::assertSame($otherBindings, [SshTargetBinding::hash($manual->fresh(), $manual->sshConfig), SshTargetBinding::hash($direct->fresh(), $direct->sshConfig)]);

        $verification->failed($target, $config, $credential, $oldAttempt, 'tcp_unreachable');
        try {
            $verification->succeeded($target, $config, $credential, $oldAttempt, '127.0.0.1');
            self::fail('An old verification cannot revive after disable and reenable.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_changed', $exception->reason);
        }
        self::assertNull($target->fresh()->last_tested_at);
        self::assertNull($target->fresh()->last_error_code);
    }

    public function test_global_disable_commits_even_when_publication_lock_is_unsafe_and_enable_fails_closed(): void
    {
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/reverse-ssh';
        $this->put($url, $this->settings(true))->assertSessionHasNoErrors();
        $this->fixtureLocalReady();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'unsafe-global-lock', 'Managed', '8.8.8.8', 2222, 'deploy', $this->publicKey(52),
        );
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        $target = $started['enrollment']->target->fresh();
        $epoch = $target->transport_revision;
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $cipher = $credential->encrypted_payload;
        $policy = file_get_contents($this->keyFile);
        $lock = $this->keyFile.'.sync.lock';
        self::assertTrue(unlink($lock));
        self::assertTrue(symlink($this->keyFile, $lock));
        self::assertTrue(app(SshManagedReverseAuthorizedKeys::class)->canPublish(),
            'A writable reader is not proof that its independent lock is safe.');

        $disable = [...$this->settings(false), 'revision' => 1];
        $response = $this->put($url, $disable)->assertSessionHasErrors('site');
        $this->get((string) $response->headers->get('Location'))->assertOk()
            ->assertSee('The settings save committed locally');
        $gateway = SshManagedReverseGateway::query()->sole();
        self::assertFalse($gateway->enabled);
        self::assertTrue($gateway->publication_pending);
        self::assertSame(2, $gateway->revision);
        self::assertSame($epoch + 1, $target->fresh()->transport_revision);
        self::assertSame($cipher, $credential->fresh()->encrypted_payload);
        self::assertSame($policy, file_get_contents($this->keyFile));
        try {
            app(SshReverseRoutePolicy::class)->forTarget($target->fresh());
            self::fail('Unsafe host lock must not preserve local route authority.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('reverse_route_not_approved', $e->reason);
        }

        // Stale input still fails, even in degraded-reader mode.
        $this->put($url, $disable)->assertSessionHasErrors('revision');
        $enable = [...$this->settings(true), 'revision' => 2];
        $response = $this->put($url, $enable)->assertSessionHasErrors('site');
        $this->get((string) $response->headers->get('Location'))->assertOk()
            ->assertSee('The settings save did not commit');
        self::assertFalse($gateway->fresh()->enabled);
        self::assertSame(2, $gateway->fresh()->revision);
        self::assertSame($epoch + 1, $target->fresh()->transport_revision);

        self::assertTrue(unlink($lock));
        $this->post($url.'/repair', ['current_password' => 'StrongPassword!234'])->assertSessionHasNoErrors();
        self::assertFalse($gateway->fresh()->publication_pending);
        self::assertSame('', file_get_contents($this->keyFile));
        $this->put($url, $enable)->assertSessionHasNoErrors();
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertSame($epoch + 2, $target->fresh()->transport_revision);
        self::assertSame($cipher, $credential->fresh()->encrypted_payload);
        self::assertSame($policy, file_get_contents($this->keyFile));
    }

    public function test_disable_during_claim_publication_keeps_claim_pending_until_actual_enable_receipt(): void
    {
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/reverse-ssh';
        $this->put($url, $this->settings(true))->assertSessionHasNoErrors();
        $this->fixtureLocalReady();
        $started = app(SshManagedReverseEnrollmentService::class)->begin(
            'claim-disable-race', 'Claim Disable Race', '8.8.8.8', 22, 'deploy', $this->publicKey(52),
        );
        $target = $started['enrollment']->target->fresh();
        $epoch = $target->transport_revision;
        $writer = new class(app(TargetTransportBinding::class)) extends SshManagedReverseAuthorizedKeys
        {
            public ?\Closure $afterPublish = null;

            protected function publish(string $contents): void
            {
                parent::publish($contents);
                $callback = $this->afterPublish;
                $this->afterPublish = null;
                $callback?->__invoke();
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        $writer->afterPublish = function () use ($url): void {
            $this->put($url, [...$this->settings(false), 'revision' => 1])->assertSessionHasNoErrors();
        };
        try {
            app(SshManagedReverseEnrollmentService::class)->claim(
                $started['enrollment']->id, $started['token'], $this->publicKey(61),
            );
            self::fail('A superseded claim receipt must not activate a disabled route.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('policy changed during publication', $exception->getMessage());
        }
        $claim = $started['enrollment']->fresh();
        self::assertSame('claimed', $claim->state);
        self::assertTrue($claim->publication_pending);
        self::assertNull($claim->token_hash);
        self::assertNull($claim->activated_at);
        self::assertFalse(SshManagedReverseGateway::active());
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertSame($epoch + 1, $target->fresh()->transport_revision);
        self::assertTrue($writer->isReconciled());

        $this->put($url, [...$this->settings(true), 'revision' => 2])->assertSessionHasNoErrors();
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertSame('active', $claim->fresh()->state);
        self::assertFalse($claim->fresh()->publication_pending);
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
        self::assertSame($epoch + 2, $target->fresh()->transport_revision);
    }

    public function test_scoped_revoke_cannot_finalize_pending_global_enable(): void
    {
        $this->assertScopedRevocationDoesNotEnable(false);
    }

    public function test_scoped_revoke_cannot_finalize_global_enable_committed_before_publication_lock(): void
    {
        $this->assertScopedRevocationDoesNotEnable(true);
    }

    private function assertScopedRevocationDoesNotEnable(bool $interleave): void
    {
        $owner = $this->user('owner');
        $admin = $this->user('administrator');
        $this->actingAs($owner);
        $url = '/admin/settings/reverse-ssh';
        $this->put($url, $this->settings(true))->assertSessionHasNoErrors();
        $this->fixtureLocalReady();
        $service = app(SshManagedReverseEnrollmentService::class);
        $a = $service->begin('scope-a', 'Scoped A', '8.8.8.8', 22, 'deploy', $this->publicKey(52));
        $b = $service->begin('scope-b', 'Scoped B', '8.8.4.4', 22, 'deploy', $this->publicKey(52));
        $service->claim($a['enrollment']->id, $a['token'], $this->publicKey(61));
        $service->claim($b['enrollment']->id, $b['token'], $this->publicKey(62));
        $targetA = $a['enrollment']->target->fresh();
        $targetB = $b['enrollment']->target->fresh();
        $epochA = $targetA->transport_revision;
        $epochB = $targetB->transport_revision;
        $credentials = DB::table('target_credentials')->orderBy('id')->get()->toArray();
        $history = DB::table('activity_events')->orderBy('id')->get()->keyBy('id')->all();

        $manager = app(UserAccessManager::class);
        $manager->updateTargetRule($admin, $targetA, 'allow', [], true, $manager->targetRuleRevision($admin, $targetA));
        $this->actingAs($admin)->post($url.'/repair', [
            'current_password' => 'StrongPassword!234',
        ])->assertForbidden();
        $this->post('/admin/targets/scope-b/reverse-ssh/revoke', [
            'confirm_target_id' => 'scope-b', 'current_password' => 'StrongPassword!234',
        ])->assertForbidden();

        $writer = new class(app(TargetTransportBinding::class)) extends SshManagedReverseAuthorizedKeys
        {
            public bool $fail = false;

            public bool $failAfterPublish = false;

            public ?\Closure $beforeLock = null;

            public function withPolicyLock(callable $operation): mixed
            {
                $callback = $this->beforeLock;
                $this->beforeLock = null;
                $callback?->__invoke();

                return parent::withPolicyLock($operation);
            }

            protected function publish(string $contents): void
            {
                if ($this->fail && ! $this->failAfterPublish) {
                    throw new RuntimeException('Fixture global Enable publication failure');
                }

                parent::publish($contents);
                if ($this->fail) {
                    throw new RuntimeException('Fixture interrupted after publishing global Enable bytes');
                }
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        $failedEnable = function () use ($writer, $owner, $admin, $url, $interleave): void {
            $this->actingAs($owner)->put($url, [...$this->settings(false), 'revision' => 1])->assertSessionHasNoErrors();
            $writer->fail = true;
            $writer->failAfterPublish = $interleave;
            $this->put($url, [...$this->settings(true), 'revision' => 2])->assertSessionHasErrors('site');
            $writer->fail = false;
            self::assertFalse(SshManagedReverseGateway::active());
            self::assertTrue(SshManagedReverseGateway::query()->sole()->publication_pending);
            if ($interleave) {
                self::assertStringContainsString($this->publicKey(62), file_get_contents($this->keyFile));
            } else {
                self::assertSame('', file_get_contents($this->keyFile));
            }
            $this->actingAs($admin);
        };
        if ($interleave) {
            // The scoped local revoke commits before the publication lock.
            // Model an Owner operation that wins that lock before the revoke
            // publication starts. A pre-lock check cannot authorize activation.
            $writer->beforeLock = function () use ($a, $failedEnable): void {
                self::assertSame('revoked', $a['enrollment']->fresh()->state);
                self::assertTrue($a['enrollment']->fresh()->publication_pending);
                $failedEnable();
            };
        } else {
            $failedEnable();
        }

        $this->post('/admin/targets/scope-a/reverse-ssh/revoke', [
            'confirm_target_id' => 'scope-a', 'current_password' => 'StrongPassword!234',
        ])->assertAdminRedirect('/admin/targets/scope-a')->assertSessionHasNoErrors();

        $gateway = SshManagedReverseGateway::query()->sole();
        self::assertSame(3, $gateway->revision);
        self::assertTrue($gateway->enabled);
        self::assertTrue($gateway->publication_pending);
        self::assertFalse(SshManagedReverseGateway::active());
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertSame('revoked', $a['enrollment']->fresh()->state);
        self::assertFalse($a['enrollment']->fresh()->publication_pending);
        self::assertSame($epochA + ($interleave ? 1 : 2), $targetA->fresh()->transport_revision);
        self::assertSame($epochB + 1, $targetB->fresh()->transport_revision);
        try {
            app(SshReverseRoutePolicy::class)->forTarget($targetB->fresh());
            self::fail('Scoped revoke restored an unrelated managed route.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('reverse_route_not_approved', $exception->reason);
        }

        $this->actingAs($owner)->post($url.'/repair', [
            'current_password' => 'StrongPassword!234',
        ])->assertSessionHasNoErrors();
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertSame(3, $gateway->fresh()->revision);
        self::assertSame($epochB + 2, $targetB->fresh()->transport_revision);
        self::assertSame($epochA + ($interleave ? 1 : 2), $targetA->fresh()->transport_revision);
        self::assertSame('revoked', $a['enrollment']->fresh()->state);
        self::assertStringNotContainsString($this->publicKey(61), file_get_contents($this->keyFile));
        self::assertStringContainsString($this->publicKey(62), file_get_contents($this->keyFile));
        self::assertNotNull(app(SshReverseRoutePolicy::class)->forTarget($targetB->fresh()));
        self::assertEquals($credentials, DB::table('target_credentials')->orderBy('id')->get()->toArray());
        self::assertEquals($history, DB::table('activity_events')->whereIn('id', array_keys($history))->orderBy('id')->get()->keyBy('id')->all());
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
        $waiting = app(SshManagedReverseEnrollmentService::class)->begin(
            'waiting-for-repair', 'Waiting for Repair', '8.8.4.4', 22, 'deploy', $this->publicKey(52),
        );
        $disable = $this->settings(false);
        $disable['revision'] = 1;
        $this->put('/admin/settings/reverse-ssh', $disable)->assertRedirect();
        self::assertSame('', file_get_contents($this->keyFile));
        $writer = new class(app(TargetTransportBinding::class)) extends SshManagedReverseAuthorizedKeys
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
        try {
            app(SshManagedReverseEnrollmentService::class)->claim(
                $waiting['enrollment']->id, $waiting['token'], $this->publicKey(62),
            );
            self::fail('A claim must not consume its token or implicitly repair a pending Enable.');
        } catch (\InvalidArgumentException) {
            self::assertSame('pending', $waiting['enrollment']->fresh()->state);
            self::assertNotNull($waiting['enrollment']->fresh()->token_hash);
        }
        $pendingTarget = $started['enrollment']->target->fresh();
        $pendingConfig = $pendingTarget->sshConfig;
        $credential = TargetCredential::query()->where('target_record_id', $pendingTarget->getKey())->sole();
        $pendingEpoch = $pendingTarget->transport_revision;
        $attempt = app(SshVerificationState::class)->begin($pendingTarget, $pendingConfig, $credential);
        app()->forgetInstance(SshManagedReverseAuthorizedKeys::class);
        $this->post('/admin/settings/reverse-ssh/repair', [
            'current_password' => 'StrongPassword!234',
        ])->assertRedirect();
        self::assertFalse(SshManagedReverseGateway::query()->sole()->publication_pending);
        self::assertTrue(SshManagedReverseGateway::active());
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
        self::assertSame($pendingEpoch + 1, $pendingTarget->fresh()->transport_revision);
        app(SshVerificationState::class)->failed($pendingTarget, $pendingConfig, $credential, $attempt, 'tcp_unreachable');
        self::assertNull($pendingTarget->fresh()->last_tested_at);
        try {
            app(SshVerificationState::class)->succeeded($pendingTarget, $pendingConfig, $credential, $attempt, '127.0.0.1');
            self::fail('A pending-publication snapshot must not survive the actual activation receipt.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('target_changed', $e->reason);
        }
    }
}
