<?php

namespace Tests\Feature\Targets;

use App\Application\Access\AccessControl;
use App\Application\Access\UserAccessManager;
use App\Application\Mcp\TargetMcpToolHandlers;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class SshTargetRegistrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_registers_out_of_band_pinned_password_target_without_network_or_secret_disclosure(): void
    {
        $this->actingAs($this->user('owner'));
        $fields = $this->fields();
        $this->post('/admin/targets', $fields)->assertRedirect('/admin/targets/ssh-alpha');
        $target = Target::query()->where('target_id', 'ssh-alpha')->sole();
        self::assertSame('ssh_direct', $target->connector_type);
        self::assertSame('disconnected', $target->connection_state->value);
        $config = SshTargetConfig::query()->sole();
        self::assertSame('2606:4700:4700::1111', $config->host);
        self::assertSame(2222, $config->port);
        self::assertSame('deploy', $config->username);
        self::assertNull($config->observed_peer_ip);
        $registrationEvent = DB::table('activity_events')->where('operation', 'ssh-target-register')->sole();
        self::assertSame('ssh_direct', $registrationEvent->connector_type_snapshot);
        self::assertSame($target->getKey(), $registrationEvent->target_record_id);
        self::assertSame('success', $registrationEvent->outcome);
        self::assertStringNotContainsString('password-secret-test', json_encode($registrationEvent, JSON_THROW_ON_ERROR));
        $credential = TargetCredential::query()->sole();
        self::assertNotSame('password-secret-test', $credential->encrypted_payload);
        self::assertStringNotContainsString('password-secret-test', $credential->encrypted_payload);
        self::assertSame(['secret' => 'password-secret-test', 'passphrase' => null],
            app(SshTargetVault::class)->open($target, $config, $credential));

        $this->get('/admin/targets/ssh-alpha')->assertOk()
            ->assertSee('deploy@[2606:4700:4700::1111]:2222')
            ->assertSee('IP not yet verified')
            ->assertDontSee('password-secret-test')
            ->assertDontSee($credential->encrypted_payload)
            ->assertDontSee($config->pinned_host_key);
        $this->get('/admin/targets')->assertOk()
            ->assertSee('deploy@[2606:4700:4700::1111]:2222')
            ->assertDontSee('password-secret-test');
    }

    public function test_registration_requires_independent_key_confirmation_and_never_flashes_secret(): void
    {
        $this->actingAs($this->user('owner'));
        $fields = $this->fields();
        unset($fields['ssh_trust_confirmed']);
        $this->post('/admin/targets', $fields)->assertSessionHasErrors('ssh_trust_confirmed');
        self::assertSame(0, Target::query()->count());
        $fields['ssh_trust_confirmed'] = 'yes';
        $fields['ssh_host_key'] = 'ssh-ed25519 malicious';
        $response = $this->post('/admin/targets', $fields)->assertSessionHasErrors('ssh_host');
        self::assertArrayNotHasKey('ssh_password', $response->baseResponse->getSession()->getOldInput());
        self::assertArrayNotHasKey('ssh_private_key', $response->baseResponse->getSession()->getOldInput());
        self::assertSame(0, Target::query()->count());

        $fields = $this->fields();
        $fields['target_id'] = '../oops';
        $this->post('/admin/targets', $fields)->assertSessionHasErrors('target_id');
        self::assertSame(0, Target::query()->count());
    }

    public function test_private_key_and_passphrase_are_write_only_and_vault_is_bound_to_exact_record_and_pin(): void
    {
        $target = app(SshTargetRegistration::class)->register(
            'alpha', 'Alpha', 'HOST.Example.test.', 22, 'deploy',
            $this->key(), 'private_key', 'PRIVATE KEY TEST VALUE', 'passphrase-test',
        );
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole();
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        self::assertSame('host.example.test', $config->host);
        self::assertNull($config->observed_peer_ip);
        self::assertStringNotContainsString('passphrase-test', $credential->encrypted_payload);
        self::assertStringNotContainsString('PRIVATE KEY TEST VALUE', $credential->encrypted_payload);
        self::assertSame(['secret' => 'PRIVATE KEY TEST VALUE', 'passphrase' => 'passphrase-test'],
            app(SshTargetVault::class)->open($target, $config, $credential));

        $other = app(SshTargetRegistration::class)->register(
            'beta', 'Beta', 'host.example.test', 22, 'deploy',
            $this->key(), 'private_key', 'OTHER TEST KEY', 'other-passphrase',
        );
        $otherConfig = SshTargetConfig::query()->where('target_record_id', $other->getKey())->sole();

        $this->expectException(RuntimeException::class);
        app(SshTargetVault::class)->open($other, $otherConfig, $credential);
    }

    public function test_unauthorized_request_cannot_consume_an_ssh_verification_attempt(): void
    {
        config()->set('ssh.verification.max_attempts_per_minute', 1);
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $target = app(SshTargetRegistration::class)->register(
            'guarded', 'Guarded', '127.0.0.1', 22, 'deploy',
            $this->key(), 'password', 'password-secret-test', null,
        );

        $this->actingAs($operator)->post('/admin/targets/guarded/test')->assertForbidden();

        $this->actingAs($owner)->post('/admin/targets/guarded/test')
            ->assertRedirect('/admin/targets/guarded')
            ->assertSessionHasErrors('target');
        self::assertSame('egress_denied', $target->refresh()->last_error_code);
        self::assertSame(1, DB::table('activity_events')
            ->where('operation', 'ssh-login-verify')
            ->where('error_code', 'egress_denied')
            ->count());
    }

    public function test_registered_unsafe_literal_is_never_contacted_and_gateway_denies_default_ssh_authority(): void
    {
        $owner = $this->user('owner');
        $target = app(SshTargetRegistration::class)->register(
            'unsafe', 'Unsafe', '127.0.0.1', 22, 'deploy',
            $this->key(), 'password', 'password-secret-test', null,
        );
        $operator = $this->user('operator');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);
        self::assertTrue(app(AccessControl::class)->allows($owner, GatewayPermission::SshCommandRun, $target));
        self::assertSame([
            'ssh.command.run' => true,
            'ssh.file.read' => true,
        ], app(AccessControl::class)->allowsTargetPermissions($owner, $target, [
            GatewayPermission::SshCommandRun, GatewayPermission::SshFileRead,
        ]));
        self::assertFalse(app(AccessControl::class)->allows($operator, GatewayPermission::SshCommandRun, $target));
        self::assertFalse(app(AccessControl::class)->allows($operator, GatewayPermission::SshFileRead, $target));
        self::assertFalse(app(AccessControl::class)->allows($operator, GatewayPermission::SshFileWrite, $target));

        $this->actingAs($owner)->post('/admin/targets/unsafe/test')
            ->assertRedirect('/admin/targets/unsafe')
            ->assertSessionHasErrors('target');
        $target->refresh();
        self::assertSame('egress_denied', $target->last_error_code);
        self::assertNull(SshTargetConfig::query()->sole()->observed_peer_ip);
        $this->post('/admin/targets/unsafe/disconnect')->assertRedirect('/admin/targets/unsafe');
        self::assertSame(0, TargetCredential::query()->count());
        self::assertSame('disconnected', $target->refresh()->connection_state->value);
        self::assertSame('failure', DB::table('activity_events')->where('operation', 'ssh-login-verify')->sole()->outcome);
        self::assertSame('egress_denied', DB::table('activity_events')->where('operation', 'ssh-login-verify')->sole()->error_code);
        self::assertSame('success', DB::table('activity_events')->where('operation', 'ssh-credential-disconnect')->sole()->outcome);
    }

    public function test_mcp_ssh_ip_inventory_and_context_are_target_scoped_and_never_include_secrets(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $hidden = app(SshTargetRegistration::class)->register(
            'ssh-hidden', 'Hidden', '8.8.8.8', 22, 'root', $this->key(),
            'password', 'hidden-secret', null,
        );
        $visible = app(SshTargetRegistration::class)->register(
            'ssh-visible', 'Visible', '8.8.8.8', 2222, 'deploy', $this->key(),
            'password', 'visible-secret', null,
        );
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $visible->getKey(),
            'allowed' => true,
        ]);

        $handlers = app(TargetMcpToolHandlers::class);
        $ownerList = $handlers->targetsList($owner, search: '8.8.8.8');
        self::assertCount(2, $ownerList['targets']);
        self::assertSame('root@8.8.8.8:22', $ownerList['targets'][0]['ssh']['destination_label']);
        self::assertSame('deploy@8.8.8.8:2222', $ownerList['targets'][1]['ssh']['destination_label']);
        self::assertSame('registered_unverified', $ownerList['targets'][0]['ssh']['ip_status']);
        self::assertSame(1, count($handlers->targetsList($operator, search: '8.8.8.8')['targets']));
        self::assertSame('ssh-visible', $handlers->targetsList($operator, search: '8.8.8.8')['targets'][0]['target_id']);
        self::assertCount(1, $handlers->targetsList($owner, search: '8.8.8.8:2222')['targets']);
        self::assertSame('ssh-visible', $handlers->targetsList($owner, search: 'deploy@8.8.8.8:2222')['targets'][0]['target_id']);
        self::assertSame([], $handlers->targetsList($operator, search: '8.8.8.8:22')['targets']);
        self::assertSame($handlers->targetContext($operator, 'does-not-exist'),
            $handlers->targetContext($operator, 'ssh-hidden'));
        $context = $handlers->targetContext($operator, 'ssh-visible');
        self::assertSame('deploy@8.8.8.8:2222', $context['target']['ssh']['destination_label']);
        self::assertStringNotContainsString('visible-secret', json_encode($context, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString($this->key(), json_encode($context, JSON_THROW_ON_ERROR));

        $this->actingAs($operator)->get('/admin/targets/ssh-hidden')->assertForbidden();
        $this->get('/admin/targets/ssh-visible')->assertOk()->assertSee('deploy@8.8.8.8:2222');
    }

    private function fields(): array
    {
        return [
            'connector_type' => 'ssh_direct',
            'target_id' => 'ssh-alpha',
            'display_name' => 'Alpha',
            'ssh_host' => '[2606:4700:4700::1111]',
            'ssh_port' => '2222',
            'ssh_username' => 'deploy',
            'ssh_host_key' => $this->key(),
            'ssh_auth_method' => 'password',
            'ssh_password' => 'password-secret-test',
            'ssh_trust_confirmed' => 'yes',
        ];
    }

    private function key(): string
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
