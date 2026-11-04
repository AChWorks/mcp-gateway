<?php

namespace Tests\Feature\Admin;

use App\Application\Access\UserAccessManager;
use App\Application\Targets\ConnectionRelayAdministration;
use App\Application\Targets\ConnectionRelayTargetBinding;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\TargetConnectorFailure;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostReadiness;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshDirectTargetAdapter;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Http\OutboundRequestException;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ConnectionRelayAdminTest extends TestCase
{
    use RefreshDatabase;

    private const PASSWORD = 'StrongPassword!234';

    public function test_owner_registers_disabled_relay_but_missing_host_attestation_fails_closed(): void
    {
        $this->actingAs($this->user('owner'));

        $this->get('/admin/settings/connection-relays')
            ->assertOk()->assertSee('Connection Relays')->assertSee('Register disabled Relay');

        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(),
            'current_password' => self::PASSWORD,
        ])->assertAdminRedirect('/admin/settings/connection-relays')->assertSessionHasNoErrors();

        $relay = ConnectionRelay::query()->sole();
        self::assertFalse($relay->enabled);
        $this->post('/admin/settings/connection-relays/'.$relay->id.'/toggle', [
            'relay_revision' => 1, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay');
        self::assertFalse($relay->fresh()->enabled);
        self::assertSame(0, DB::table('targets')->whereNotNull('relay_record_id')->count());

        $this->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()->assertDontSee('value="iran-1"', false);
    }

    public function test_failed_ssh_enrollment_keeps_explicit_relay_selection_for_safe_retry(): void
    {
        $this->readyRelay();
        $this->actingAs($this->user('owner'));

        $this->post('/admin/targets', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'relay-validation-error',
            'display_name' => 'Relayed SSH',
            'connection_relay_id' => 'iran-1',
        ])->assertSessionHasErrors('ssh_host')
            ->assertSessionHas('_old_input.connection_relay_id', 'iran-1');
    }

    public function test_only_owner_can_manage_relay_or_attach_target_to_it(): void
    {
        $this->actingAs($this->user('operator'));
        $this->get('/admin/settings/connection-relays')->assertForbidden();
        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(), 'current_password' => self::PASSWORD,
        ])->assertForbidden();
    }

    public function test_attested_relay_can_be_selected_once_for_many_targets_with_stable_ssh_secret_and_job_fencing(): void
    {
        $relay = $this->readyRelay();
        $this->actingAs($this->user('owner'));
        $this->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()->assertSee('value="iran-1"', false);

        $target = app(SshTargetRegistration::class)->register(
            'relay-target-one', 'Relayed SSH', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole();
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        self::assertSame(1, $target->relay_binding_revision);
        self::assertSame((string) $relay->getKey(), $target->getAttribute('relay_record_id'));
        self::assertSame('ssh-secret', app(SshTargetVault::class)->open($target, $config, $credential)['secret']);
        self::assertSame(46081, app(ConnectionRelayRoutes::class)->sshRouteForTarget($target)?->loopbackPort);

        $oldHash = SshTargetBinding::hash($target, $config);
        $bindings = app(ConnectionRelayTargetBinding::class);
        self::assertTrue($bindings->change($target, $bindings->revision($target), null));
        $target->refresh();
        self::assertSame(2, $target->relay_binding_revision);
        self::assertNull($target->getAttribute('relay_record_id'));
        self::assertNotSame($oldHash, SshTargetBinding::hash($target, $config));
        self::assertSame('ssh-secret', app(SshTargetVault::class)->open($target, $config, $credential->fresh())['secret']);

        self::assertTrue($bindings->change($target, $bindings->revision($target), 'iran-1'));
        $target->refresh();
        self::assertSame(3, $target->relay_binding_revision);
        self::assertNotSame($oldHash, SshTargetBinding::hash($target, $config));
        self::assertSame('ssh-secret', app(SshTargetVault::class)->open($target, $config, $credential->fresh())['secret']);

        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        try {
            $bindings->change($target, $bindings->revision($target), null);
            self::fail('Connected Target changed routes without disconnecting.');
        } catch (TargetConnectorFailure) {
            self::assertNotNull($target->fresh()->getAttribute('relay_record_id'));
        }

        $target->forceFill(['connection_state' => TargetConnectionState::Disconnected])->save();
        app(ConnectionRelayAdministration::class)->disable($relay, 1);
        $target->refresh();
        self::assertSame(4, $target->relay_binding_revision);
        self::assertSame('error', $target->connection_state->value);
        self::assertSame('relay_disabled', $target->last_error_code);
        self::assertNotSame($oldHash, SshTargetBinding::hash($target, $config));
        self::assertSame('ssh-secret', app(SshTargetVault::class)->open($target, $config, $credential->fresh())['secret']);

        try {
            app(ConnectionRelayRoutes::class)->sshRouteForTarget($target);
            self::fail('Disabled Relay was used or silently switched to Direct.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('relay_unavailable', $exception->reason);
        }
    }

    public function test_relay_attestation_cannot_be_forged_by_a_normal_php_user(): void
    {
        $relay = ConnectionRelay::query()->create($this->relayFields());
        DB::table('connection_relays')->where('id', $relay->id)->update(['enabled' => true]);
        $relay->refresh();
        self::assertFalse(app(ConnectionRelayHostReadiness::class)->ready($relay));
        self::assertNotSame('', $relay->hostFingerprint());
    }

    public function test_stale_route_epoch_fails_before_a_reused_wordpress_request(): void
    {
        $relay = $this->readyRelay();
        $target = app(SshTargetRegistration::class)->register(
            'relay-route-epoch', 'Route epoch', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $routes = app(ConnectionRelayRoutes::class);
        $original = $routes->httpRouteAtEpoch((string) $target->getKey(), 1);
        self::assertSame(46081, $original?->loopbackPort);

        app(ConnectionRelayAdministration::class)->disable($relay, 1);
        try {
            $routes->httpRouteAtEpoch((string) $target->getKey(), 1, $original, true);
            self::fail('An outdated route revision reached the transport.');
        } catch (OutboundRequestException $exception) {
            self::assertTrue($exception->preDispatch);
            self::assertSame('network_failure', $exception->reason);
        }
    }

    public function test_disable_advances_security_generation_and_rejects_old_enable_and_double_disable(): void
    {
        $relay = $this->readyRelay();
        $this->actingAs($this->user('owner'));
        $oldFingerprint = $relay->hostFingerprint();
        $url = '/admin/settings/connection-relays/'.$relay->getKey().'/toggle';

        $this->post($url, [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $relay->refresh();
        self::assertFalse($relay->enabled);
        self::assertSame(2, $relay->configuration_revision);
        self::assertSame(2, $relay->lifecycle_revision);
        self::assertNotSame($oldFingerprint, $relay->hostFingerprint());

        $this->post($url, [
            'relay_revision' => 1, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_revision');
        self::assertFalse($relay->fresh()->enabled);

        // This successful enable uses a fake readiness fixture only; the real
        // privileged verifier must issue evidence against the new generation.
        $this->post($url, [
            'relay_revision' => 2, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $relay->refresh();
        self::assertTrue($relay->enabled);
        self::assertSame(3, $relay->lifecycle_revision);
        self::assertSame(2, $relay->configuration_revision);
        // Stale Enable AND a Disable issued before this latest Enable must
        // both be rejected even though the host attestation did not rotate.
        $this->post($url, [
            'relay_revision' => 2, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_revision');
        $this->post($url, [
            'relay_revision' => 2, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_revision');
        self::assertTrue($relay->fresh()->enabled);

        $this->post($url, [
            'relay_revision' => 3, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $relay->refresh();
        self::assertSame(3, $relay->configuration_revision);
        self::assertSame(4, $relay->lifecycle_revision);
        self::assertFalse(app(ConnectionRelayAdministration::class)->disable($relay, 4));
        self::assertSame(4, $relay->fresh()->lifecycle_revision);
        $this->post($url, [
            'relay_revision' => 3, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_revision');
    }

    public function test_double_disable_does_not_reseal_credentials_or_advance_job_epoch(): void
    {
        $relay = $this->readyRelay();
        $target = app(SshTargetRegistration::class)->register(
            'relay-double-disable', 'Relay second disable', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $first = app(ConnectionRelayAdministration::class)->disable($relay, 1);
        self::assertTrue($first);
        $epoch = $target->fresh()->relay_binding_revision;
        $encrypted = TargetCredential::query()->where('target_record_id', $target->getKey())
            ->sole()->encrypted_payload;
        self::assertFalse(app(ConnectionRelayAdministration::class)->disable($relay, 2));
        self::assertSame($epoch, $target->fresh()->relay_binding_revision);
        self::assertSame($encrypted, TargetCredential::query()
            ->where('target_record_id', $target->getKey())->sole()->encrypted_payload);
    }

    public function test_connect_reconnect_and_verify_do_not_claim_tunnel_peer_ip(): void
    {
        $this->readyRelay();
        $this->app->instance(SshTargetConnectionService::class, new class
        {
            public function test(Target $target): void {}
        });

        $direct = app(SshTargetRegistration::class)->register(
            'message-direct', 'Direct', '1.1.1.1', 22, 'deploy',
            $this->publicKey(), 'password', 'ssh-secret', null,
        );
        $relay = app(SshTargetRegistration::class)->register(
            'message-relay', 'Relay', '1.1.1.1', 22, 'deploy',
            $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $reverse = app(SshTargetRegistration::class)->register(
            'message-reverse', 'Reverse', '1.1.1.1', 22, 'deploy',
            $this->publicKey(), 'password', 'ssh-secret', null,
        );
        DB::table('ssh_direct_target_configs')->where('target_record_id', $reverse->getKey())
            ->update(['route_mode' => 'reverse', 'reverse_listener_port' => 42050, 'reverse_tunnel_identity' => 'fixture-only']);

        $adapter = app(SshDirectTargetAdapter::class);
        foreach ([$direct, $relay, $reverse] as $target) {
            foreach (['connect', 'reconnect', 'test'] as $action) {
                $message = $adapter->{$action}($target)->statusMessage;
                self::assertNotNull($message);
                self::assertStringContainsString('key and login', $message);
                if ($target->getKey() === $direct->getKey()) {
                    self::assertStringContainsString('Direct SSH TCP peer', $message);
                    self::assertStringNotContainsString('remote Target IP was not independently observed', $message);
                } else {
                    self::assertStringContainsString('The observed TCP peer is local', $message);
                    self::assertStringContainsString('remote Target IP was not independently observed', $message);
                }
            }
        }
    }

    public function test_target_route_requires_password_and_blocks_stale_revision(): void
    {
        $relay = $this->readyRelay();
        $this->actingAs($this->user('owner'));
        $target = app(SshTargetRegistration::class)->register(
            'relay-config-ssh', 'Relayed SSH', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
        );
        $revision = app(ConnectionRelayTargetBinding::class)->revision($target);
        $url = '/admin/targets/relay-config-ssh/relay-route';

        $this->put($url, [
            'route_revision' => $revision, 'connection_relay_id' => 'iran-1',
        ])->assertSessionHasErrors('current_password');
        self::assertNull($target->fresh()->getAttribute('relay_record_id'));

        $this->put($url, [
            'route_revision' => $revision, 'connection_relay_id' => 'iran-1',
            'current_password' => self::PASSWORD,
        ])->assertAdminRedirect('/admin/targets/relay-config-ssh/edit')->assertSessionHasNoErrors();
        self::assertSame((string) $relay->id, (string) $target->fresh()->getAttribute('relay_record_id'));

        $this->put($url, [
            'route_revision' => $revision, 'connection_relay_id' => '',
            'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('route_revision');
        self::assertSame(1, $target->fresh()->relay_binding_revision);
    }

    private function readyRelay(): ConnectionRelay
    {
        $relay = ConnectionRelay::query()->create($this->relayFields());
        DB::table('connection_relays')->where('id', $relay->id)->update(['enabled' => true]);
        $relay->refresh();
        $this->app->instance(ConnectionRelayHostReadiness::class, new class extends ConnectionRelayHostReadiness
        {
            public function ready(ConnectionRelay $relay): bool
            {
                return true; // Fixture only. No production attestation.
            }
        });

        return $relay;
    }

    /** @return array<string,mixed> */
    private function relayFields(): array
    {
        return [
            'relay_id' => 'iran-1',
            'display_name' => 'Iran shared relay',
            'control_host' => '193.111.235.101',
            'control_port' => 22,
            'control_user' => 'mcp-relay',
            'control_host_key' => $this->publicKey(),
            'local_socks_port' => 46081,
        ];
    }

    private function publicKey(): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('a', 32));
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => ucfirst($role),
            'email' => Str::random(14).'@example.test',
            'password' => self::PASSWORD,
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ], []);
    }
}
