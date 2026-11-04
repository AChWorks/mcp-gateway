<?php

namespace Tests\Feature\Targets;

use App\Application\Access\UserAccessManager;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetReconfiguration;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetIdentity;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

final class SshReverseRouteApprovalTest extends TestCase
{
    use RefreshDatabase;

    private const PORT = 62341;

    protected function setUp(): void
    {
        parent::setUp();
        $this->allow([
            'reverse-target' => ['port' => self::PORT, 'tunnel_identity' => 'fixture-reverse-one'],
            'second-target' => ['port' => self::PORT + 1, 'tunnel_identity' => 'fixture-reverse-two'],
        ]);
    }

    public function test_route_is_not_a_generic_ssrf_or_dns_bypass_and_operator_allowlist_must_be_unambiguous(): void
    {
        $policy = app(SshReverseRoutePolicy::class);
        self::assertNull($policy->approve('reverse-target', 'direct', null, null));
        $route = $policy->approve('reverse-target', 'reverse', (string) self::PORT, 'fixture-reverse-one');
        self::assertSame('reverse-target', $route->targetId);
        self::assertSame(self::PORT, $route->listenerPort);
        self::assertSame('fixture-reverse-one', $route->tunnelIdentity);

        foreach ([
            ['wrong-target', 'reverse', self::PORT, 'fixture-reverse-one'],
            ['reverse-target', 'reverse', self::PORT + 1, 'fixture-reverse-one'],
            ['reverse-target', 'reverse', self::PORT, 'other-identity'],
            ['reverse-target', 'reverse', 22, 'fixture-reverse-one'],
            ['reverse-target', 'reverse', 'http://127.0.0.1:62341', 'fixture-reverse-one'],
            ['reverse-target', 'direct', self::PORT, 'fixture-reverse-one'],
            ['reverse-target', 'proxy', self::PORT, 'fixture-reverse-one'],
        ] as [$target, $mode, $port, $identity]) {
            try {
                $policy->approve($target, $mode, $port, $identity);
                self::fail('Unapproved reverse route unexpectedly accepted');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame('reverse_route_not_approved', $exception->reason);
            }
        }
        $this->allow([
            'reverse-target' => ['port' => self::PORT, 'tunnel_identity' => 'fixture-reverse-one'],
            'second-target' => ['port' => self::PORT, 'tunnel_identity' => 'fixture-reverse-two'],
        ]);
        $this->expectException(SshTargetConnectionException::class);
        $policy->approve('reverse-target', 'reverse', self::PORT, 'fixture-reverse-one');
    }

    public function test_owner_and_password_are_required_for_reverse_registration_without_dialing_any_host(): void
    {
        $fields = $this->enrollment();
        $this->actingAs($this->user('administrator'))->post('/admin/targets', $fields)->assertForbidden();
        self::assertSame(0, Target::query()->count());

        $this->actingAs($this->user('owner'));
        $fields['current_password'] = 'wrong-password-do-not-log';
        $this->post('/admin/targets', $fields)->assertAdminRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=manual')
            ->assertSessionHasErrors('current_password');
        self::assertSame(0, Target::query()->count());
        $fields['current_password'] = 'StrongPassword!234';
        $this->post('/admin/targets', $fields)->assertAdminRedirect('/admin/targets/reverse-target');
        $target = Target::query()->sole();
        $config = SshTargetConfig::query()->sole();
        self::assertSame('reverse', $config->route_mode);
        self::assertSame(self::PORT, $config->reverse_listener_port);
        self::assertSame('fixture-reverse-one', $config->reverse_tunnel_identity);
        self::assertSame('2606:4700:4700::1111', $config->host);
        self::assertNull($config->observed_peer_ip);
        self::assertSame('disconnected', $target->connection_state->value);
        self::assertSame('password-secret-fixture', app(SshTargetVault::class)
            ->open($target, $config, TargetCredential::query()->sole())['secret']);
        $this->get('/admin/targets/reverse-target')->assertOk()
            ->assertSee('Owner-approved Reverse SSH')
            ->assertSee('127.0.0.1:'.self::PORT)
            ->assertSee('2606:4700:4700::1111')
            ->assertDontSee('password-secret-fixture');

        $metadata = app(SshTargetIdentity::class)->safeMetadata($target);
        self::assertSame('reverse', $metadata['route_mode'] ?? null);
        self::assertNotSame('127.0.0.1', $metadata['ip']);
    }

    public function test_missing_operator_approval_rejects_enrollment_before_writing_any_records_and_never_flashes_secrets(): void
    {
        $this->actingAs($this->user('owner'));
        $fields = $this->enrollment();
        $fields['current_password'] = 'StrongPassword!234';
        $this->allow([]);
        $failure = $this->post('/admin/targets', $fields)->assertAdminRedirect('/admin/targets/create?connector_type=ssh_direct&ssh_mode=manual')
            ->assertSessionHasErrors('ssh_reverse_port')
            ->assertSessionHas('diagnostic_code', 'reverse_route_not_approved');
        self::assertArrayNotHasKey('current_password', $failure->baseResponse->getSession()->getOldInput());
        self::assertArrayNotHasKey('ssh_password', $failure->baseResponse->getSession()->getOldInput());
        self::assertSame('reverse', $failure->baseResponse->getSession()->getOldInput()['ssh_route_mode']);
        self::assertSame(0, Target::query()->count());
        self::assertSame(0, TargetCredential::query()->count());
    }

    public function test_operator_revocation_stops_verification_commands_and_sftp_before_dialing_any_socket(): void
    {
        $owner = $this->user('owner');
        $this->actingAs($owner);
        $target = app(SshTargetRegistration::class)->register(
            'reverse-target', 'Reverse revoked', 'fixture.example.test', 22, 'deploy',
            $this->hostKey(), 'password', 'password-secret-fixture', null,
            null, 'reverse', self::PORT, 'fixture-reverse-one',
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        $this->allow([]);
        foreach ([
            'verification' => static fn () => app(SshTargetConnectionService::class)->test($target),
            'command' => static fn () => app(SshCommandRuntime::class)->run($owner, $target, 'printf must-not-run'),
            'sftp' => static fn () => app(SshFileRuntime::class)->stat($owner, $target, '/home/deploy'),
        ] as $path => $attempt) {
            // Verify failure marks Target health as Error; reset the local
            // synthetic precondition to independently test each call path.
            $target->refresh();
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
            $fresh = Target::query()->whereKey($target->getKey())->firstOrFail();
            self::assertSame(TargetConnectionState::Connected, $fresh->connection_state, 'health for '.$path);
            $cfg = SshTargetConfig::query()->sole();
            self::assertSame('password-secret-fixture', app(SshTargetVault::class)->open($fresh, $cfg, TargetCredential::query()->sole())['secret'], 'vault for '.$path);
            try {
                $attempt();
                self::fail('Revoked operator approval unexpectedly permitted SSH transport.');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame('reverse_route_not_approved', $exception->reason, $path);
            }
        }
        $config = SshTargetConfig::query()->sole();
        self::assertNull($config->observed_peer_ip);
        self::assertNull($config->observed_at);
    }

    public function test_owner_route_rotation_fences_credentials_verified_state_and_retained_job_binding(): void
    {
        $this->actingAs($this->user('owner'));
        $target = app(SshTargetRegistration::class)->register(
            'reverse-target', 'Fixture', '8.8.8.8', 22, 'deploy',
            $this->hostKey(), 'password', 'password-secret-fixture', null,
        );
        $original = SshTargetConfig::query()->sole();
        $originalCipher = TargetCredential::query()->sole()->encrypted_payload;
        $originalJobBinding = SshTargetBinding::hash($target, $original);
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $this->get('/admin/targets/reverse-target/edit')->assertOk();
        $revision = app(SshTargetReconfiguration::class)->revision($target);
        $payload = $this->reconfigure($revision);
        $this->put('/admin/targets/reverse-target/configuration', $payload)
            ->assertAdminRedirect('/admin/targets/reverse-target')->assertSessionHasNoErrors();

        $target->refresh();
        $config = SshTargetConfig::query()->sole();
        self::assertSame('reverse', $config->route_mode);
        self::assertSame('disconnected', $target->connection_state->value);
        self::assertNull($config->observed_peer_ip);
        self::assertNotSame($originalCipher, TargetCredential::query()->sole()->encrypted_payload);
        self::assertSame(1, $config->binding_revision);
        self::assertNotSame($originalJobBinding, SshTargetBinding::hash($target, $config));
        self::assertSame('password-secret-fixture', app(SshTargetVault::class)
            ->open($target, $config, TargetCredential::query()->sole())['secret']);

        $this->put('/admin/targets/reverse-target/configuration', $payload)
            ->assertSessionHasErrors('configuration_revision');
        $after = app(SshTargetReconfiguration::class)->revision($target);
        $back = $this->reconfigure($after);
        $back['ssh_route_mode'] = 'direct';
        $back['ssh_reverse_port'] = null;
        $back['ssh_tunnel_identity'] = null;
        $this->put('/admin/targets/reverse-target/configuration', $back)
            ->assertAdminRedirect('/admin/targets/reverse-target')->assertSessionHasNoErrors();
        $direct = SshTargetConfig::query()->sole();
        self::assertSame('direct', $direct->route_mode);
        self::assertNull($direct->reverse_listener_port);
        self::assertSame(2, $direct->binding_revision);
        self::assertNotSame($originalJobBinding, SshTargetBinding::hash($target, $direct),
            'A Direct->Reverse->Direct round trip must never reactivate old retained Jobs.');
        self::assertSame('password-secret-fixture', app(SshTargetVault::class)
            ->open($target, $direct, TargetCredential::query()->sole())['secret']);
    }

    /** @param array<string, mixed> $routes */
    private function allow(array $routes): void
    {
        config()->set('ssh.reverse_approved_routes', json_encode($routes, JSON_THROW_ON_ERROR));
    }

    /** @return array<string, string|int> */
    private function enrollment(): array
    {
        return [
            'connector_type' => 'ssh_direct',
            'target_id' => 'reverse-target',
            'display_name' => 'Reverse Fixture',
            'ssh_host' => '2606:4700:4700::1111',
            'ssh_port' => 22,
            'ssh_username' => 'deploy',
            'ssh_host_key' => $this->hostKey(),
            'ssh_auth_method' => 'password',
            'ssh_password' => 'password-secret-fixture',
            'ssh_trust_confirmed' => 'yes',
            'ssh_route_mode' => 'reverse',
            'ssh_reverse_port' => self::PORT,
            'ssh_tunnel_identity' => 'fixture-reverse-one',
        ];
    }

    /** @return array<string, string|int|null> */
    private function reconfigure(string $revision): array
    {
        return [
            'configuration_revision' => $revision,
            'ssh_host' => '8.8.8.8',
            'ssh_port' => 22,
            'ssh_username' => 'deploy',
            'ssh_host_key' => $this->hostKey(),
            'ssh_auth_method' => 'password',
            'ssh_trust_confirmed' => 'yes',
            'ssh_route_mode' => 'reverse',
            'ssh_reverse_port' => self::PORT,
            'ssh_tunnel_identity' => 'fixture-reverse-one',
            'current_password' => 'StrongPassword!234',
        ];
    }

    private function hostKey(): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32));
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
}
