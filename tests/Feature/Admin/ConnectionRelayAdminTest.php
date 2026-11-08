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
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostService;
use App\Infrastructure\Connectors\Relay\ConnectionRelayOnboarding;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshDirectTargetAdapter;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Http\OutboundRequestException;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use phpseclib4\Crypt\EC;
use Symfony\Component\Process\Process;
use Tests\TestCase;

final class ConnectionRelayAdminTest extends TestCase
{
    use RefreshDatabase;

    private const PASSWORD = 'StrongPassword!234';

    public function test_owner_can_add_enable_and_view_native_ssh_commands_without_host_manifests(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(), 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $relay = ConnectionRelay::query()->sole();
        self::assertFalse($relay->enabled);
        self::assertNotEmpty($relay->login_private_key_encrypted);
        self::assertNotEmpty($relay->login_public_key);
        self::assertStringStartsWith('-----BEGIN OPENSSH PRIVATE KEY-----',
            app(ConnectionRelayOnboarding::class)->privateKey($relay));

        $this->get('/admin/settings/connection-relays')->assertOk()
            ->assertSee('Two-command Relay setup')
            ->assertSee('On the intermediary Relay server')
            ->assertSee('On the Gateway server')
            ->assertSee('gateway:relay-install')
            ->assertSee('Test local Relay connection')
            ->assertDontSee('BEGIN OPENSSH PRIVATE KEY')
            ->assertDontSee($relay->login_private_key_encrypted)
            ->assertDontSee('nftables')
            ->assertDontSee('setup-gateway');
        $unit = app(ConnectionRelayHostService::class)->unitText($relay);
        self::assertStringContainsString('ssh -N -T -D 127.0.0.1:46081', $unit);
        self::assertStringContainsString('StrictHostKeyChecking=yes', $unit);
        self::assertStringContainsString('Restart=always', $unit);
        self::assertStringContainsString('WantedBy=multi-user.target', $unit);

        $this->post('/admin/settings/connection-relays/'.$relay->getKey().'/toggle', [
            'relay_revision' => 1, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        self::assertTrue($relay->fresh()->enabled);
        $this->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()->assertSee('value="iran-1"', false);
    }

    public function test_legacy_relay_can_prepare_two_commands_only_with_owner_reauthentication(): void
    {
        $relay = $this->readyRelay();
        self::assertNull($relay->login_public_key);
        $owner = $this->user('owner');
        $this->actingAs($owner);
        $route = '/admin/settings/connection-relays/'.$relay->getKey().'/prepare';

        $this->post($route, ['relay_revision' => 1, 'current_password' => 'wrong'])
            ->assertSessionHasErrors('current_password');
        self::assertNull($relay->fresh()->login_public_key);
        $this->post($route, ['relay_revision' => 999, 'current_password' => self::PASSWORD])
            ->assertSessionHasErrors('relay_revision');
        self::assertNull($relay->fresh()->login_public_key);
        $this->get('/admin/settings/connection-relays')->assertOk()
            ->assertSee('Prepare the two complete setup commands');
        $this->post($route, ['relay_revision' => 1, 'current_password' => self::PASSWORD])
            ->assertSessionHasNoErrors();
        self::assertNotNull($relay->fresh()->login_public_key);
        $first = $relay->fresh()->login_public_key;
        $this->post($route, ['relay_revision' => 1, 'current_password' => self::PASSWORD])
            ->assertSessionHasNoErrors();
        self::assertSame($first, $relay->fresh()->login_public_key, 'Repeat setup must not rotate the key.');
        $this->get('/admin/settings/connection-relays')->assertOk()
            ->assertSee('gateway:relay-install')->assertDontSee('BEGIN OPENSSH PRIVATE KEY');
    }

    public function test_generated_full_relay_command_preserves_all_existing_authorized_keys_entries(): void
    {
        $root = sys_get_temp_dir().'/gateway-relay-command-'.bin2hex(random_bytes(8));
        $home = $root.'/home';
        $bin = $root.'/bin';
        self::assertTrue(mkdir($root, 0700));
        self::assertTrue(mkdir($home, 0700));
        self::assertTrue(mkdir($bin, 0700));
        try {
            // Run the exact generated sh -c payload, replacing only sudo and
            // privileged OS helpers with fixture-scoped equivalents. The real
            // authorized_keys file of this host is never opened or modified.
            file_put_contents($bin.'/getent', <<<'SH'
#!/bin/sh
[ "$1" = passwd ] && [ "$2" = fixture-relay ] || exit 1
printf 'fixture-relay:x:9999:9999::%s:/bin/sh\n' "$RELAY_TEST_HOME"
SH
            );
            file_put_contents($bin.'/install', <<<'SH'
#!/bin/sh
for item do destination="$item"; done
mkdir -p "$destination" && chmod 700 "$destination"
SH
            );
            file_put_contents($bin.'/chown', "#!/bin/sh\nexit 0\n");
            foreach (['getent', 'install', 'chown'] as $helper) {
                chmod($bin.'/'.$helper, 0755);
            }
            $key = EC::createKey('Ed25519')->getPublicKey()->toString('OpenSSH');
            $parts = preg_split('/\s+/', trim($key));
            self::assertIsArray($parts);
            $key = $parts[0].' '.$parts[1];
            $relay = new ConnectionRelay([
                'relay_id' => 'fixture-relay', 'control_user' => 'fixture-relay',
                'control_host' => 'relay.example.test', 'control_port' => 22,
                'local_socks_port' => 46081, 'control_host_key' => $key,
            ]);
            $relay->login_public_key = $key;
            $command = app(ConnectionRelayOnboarding::class)->commands($relay)['relay'];
            self::assertStringStartsWith('sudo sh -c ', $command);
            self::assertStringNotContainsString('PRIVATE KEY', $command);
            $authorized = $home.'/.ssh/authorized_keys';
            $previous = 'ssh-ed25519 AAAA-existing-key another-user';
            foreach ([
                'empty' => ['', $key."\n"],
                'terminated' => [$previous."\n", $previous."\n".$key."\n"],
                'unterminated' => [$previous, $previous."\n".$key."\n"],
                'identical' => [$previous."\n".$key."\n", $previous."\n".$key."\n"],
            ] as $case => [$original, $expected]) {
                if (! is_dir($home.'/.ssh')) {
                    mkdir($home.'/.ssh', 0700);
                }
                file_put_contents($authorized, $original);
                for ($repeat = 0; $repeat < 2; $repeat++) {
                    $process = Process::fromShellCommandline(substr($command, strlen('sudo ')), null, [
                        'PATH' => $bin.':'.getenv('PATH'),
                        'RELAY_TEST_HOME' => $home,
                    ]);
                    $process->mustRun();
                    self::assertSame($expected, file_get_contents($authorized),
                        $case.' iteration '.$repeat.' must preserve unrelated bytes and append exactly once.');
                }
            }
        } finally {
            File::deleteDirectory($root);
        }
    }

    public function test_failed_relay_edit_expands_only_its_disclosure(): void
    {
        $relay = $this->readyRelay();
        $this->actingAs($this->user('owner'));
        $base = '/admin/settings/connection-relays/'.$relay->getKey();
        $this->post($base.'/toggle', [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $result = $this->from('/admin/settings/connection-relays')->put($base, [
            ...$this->relayFields(), 'relay_revision' => 2, 'current_password' => self::PASSWORD,
            'control_host_key' => 'invalid server public host key',
            'edit_relay_id' => $relay->getKey(), 'relay_action' => 'edit',
            'relay_action_id' => $relay->getKey(),
        ])->assertSessionHasErrors('control_host_key');

        $location = $result->headers->get('Location');
        $html = $this->get($location ?? '/admin/settings/connection-relays')->assertOk()->getContent();

        self::assertMatchesRegularExpression(
            '/<details class="target-help-details"\s+open\s*>\s*<summary>Edit Relay connection<\/summary>/',
            $html,
        );
        self::assertMatchesRegularExpression(
            '/<details class="target-help-details"\s*>\s*<summary>Delete Relay<\/summary>/',
            $html,
        );
    }

    public function test_failed_rename_and_delete_open_only_the_submitting_relay_panel(): void
    {
        $relay = $this->readyRelay();
        $this->actingAs($this->user('owner'));
        $base = '/admin/settings/connection-relays/'.$relay->getKey();
        $index = '/admin/settings/connection-relays';
        $this->post($base.'/toggle', [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();

        foreach ([
            ['rename', 'put', $base.'/name', [
                'display_name' => '', 'relay_revision' => 2, 'current_password' => self::PASSWORD,
            ], 'display_name'],
            ['delete', 'delete', $base, [
                'relay_revision' => 2, 'confirm_relay_id' => 'incorrect',
                'current_password' => self::PASSWORD,
            ], 'confirm_relay_id'],
        ] as [$action, $method, $url, $fields, $errorKey]) {
            $response = $this->from($index)->$method($url, [
                ...$fields, 'relay_action' => $action,
                'relay_action_id' => $relay->getKey(),
            ])->assertSessionHasErrors($errorKey);
            $html = $this->get((string) $response->headers->get('Location'))->assertOk()->getContent();
            foreach (['rename' => 'Rename Relay', 'edit' => 'Edit Relay connection', 'delete' => 'Delete Relay'] as $candidate => $summary) {
                $opening = $candidate === $action ? '\s+open' : '';
                self::assertMatchesRegularExpression(
                    '/<details class="target-help-details"'.$opening.'\s*>\s*<summary>'
                        .preg_quote($summary, '/').'<\/summary>/',
                    $html,
                    $action.' error must reveal its own panel, not '.$candidate,
                );
            }
        }
    }

    public function test_disabled_relay_remains_selected_on_failure_and_never_rebinds_to_direct(): void
    {
        $relay = $this->readyRelay();
        $target = app(SshTargetRegistration::class)->register(
            'relay-offline-route', 'Offline relay', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        self::assertSame(46081, app(ConnectionRelayRoutes::class)->sshRouteForTarget($target)?->loopbackPort);
        $this->actingAs($this->user('owner'));
        $this->post('/admin/settings/connection-relays/'.$relay->getKey().'/toggle', [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $target->refresh();
        self::assertSame((string) $relay->getKey(), (string) $target->getAttribute('relay_record_id'));
        try {
            app(ConnectionRelayRoutes::class)->sshRouteForTarget($target);
            self::fail('Disabled Relay unexpectedly became Direct.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('relay_unavailable', $exception->reason);
        }
        $this->post('/admin/settings/connection-relays/'.$relay->getKey().'/toggle', [
            'relay_revision' => 2, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        self::assertSame(46081, app(ConnectionRelayRoutes::class)->sshRouteForTarget($target->fresh())?->loopbackPort);
    }

    public function test_disabled_relay_connection_can_be_edited_with_assigned_targets_and_retested(): void
    {
        $relay = $this->readyRelay();
        $target = app(SshTargetRegistration::class)->register(
            'relay-edit-bound', 'Assigned SSH', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->getKey();
        $payload = [
            ...$this->relayFields(),
            'control_host' => 'new-relay.example.test',
            'local_socks_port' => 46091,
            'relay_revision' => 1, 'current_password' => self::PASSWORD,
        ];
        $this->put($url, $payload)->assertSessionHasErrors('relay');
        $this->post($url.'/toggle', [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $this->put($url, [...$payload, 'relay_revision' => 2])
            ->assertSessionHasNoErrors();
        $relay->refresh();
        self::assertSame('new-relay.example.test', $relay->control_host);
        self::assertSame(46091, $relay->local_socks_port);
        self::assertSame((string) $relay->getKey(), (string) $target->fresh()->getAttribute('relay_record_id'));
        $this->post($url.'/toggle', [
            'relay_revision' => 3, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        self::assertSame(46091, app(ConnectionRelayRoutes::class)->sshRouteForTarget($target->fresh())?->loopbackPort);
    }

    public function test_delete_does_not_depend_on_privileged_receipts_or_intermediary_reachability(): void
    {
        $relay = $this->readyRelay();
        $target = app(SshTargetRegistration::class)->register(
            'relay-delete-bound', 'Assigned SSH', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->getKey();
        $form = ['relay_revision' => 1, 'confirm_relay_id' => 'iran-1', 'current_password' => self::PASSWORD];
        $this->delete($url, $form)->assertSessionHasErrors('relay');
        $this->post($url.'/toggle', [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $this->delete($url, [...$form, 'relay_revision' => 2])->assertSessionHasErrors('relay');
        $bindings = app(ConnectionRelayTargetBinding::class);
        $target->refresh();
        self::assertTrue($bindings->change($target, $bindings->revision($target), null));

        $this->delete($url, [...$form, 'relay_revision' => 1])->assertSessionHasErrors('relay_revision');
        $this->delete($url, [...$form, 'relay_revision' => 2, 'confirm_relay_id' => 'wrong'])
            ->assertSessionHasErrors('confirm_relay_id');
        $this->delete($url, [...$form, 'relay_revision' => 2, 'current_password' => 'wrong'])
            ->assertSessionHasErrors('current_password');
        $this->delete($url, [...$form, 'relay_revision' => 2])
            ->assertSessionHasNoErrors();
        self::assertNull(ConnectionRelay::query()->find($relay->getKey()));
        self::assertNull($target->fresh()->getAttribute('relay_record_id'));
    }

    public function test_disable_and_reenable_use_normal_revision_without_host_lease(): void
    {
        $relay = $this->readyRelay();
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->getKey().'/toggle';
        $this->post($url, [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        self::assertFalse($relay->fresh()->enabled);
        self::assertSame(2, $relay->fresh()->lifecycle_revision);
        $this->post($url, [
            'relay_revision' => 1, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_revision');
        $this->post($url, [
            'relay_revision' => 2, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        self::assertTrue($relay->fresh()->enabled);
        self::assertSame(3, $relay->fresh()->lifecycle_revision);
    }

    public function test_saturated_target_binding_blocks_reenable_without_changing_relay_state(): void
    {
        $relay = $this->readyRelay();
        $target = app(SshTargetRegistration::class)->register(
            'relay-saturated-binding', 'Saturated binding', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole();
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $vault = app(SshTargetVault::class);
        $material = $vault->open($target, $config, $credential);

        // Start just below saturation with a valid credential, so Disable
        // reaches the maximum normally rather than failing credential resealing.
        $target->setRawAttributes([
            ...$target->getAttributes(), 'relay_binding_revision' => 4294967294,
        ], true);
        $credential->forceFill(['encrypted_payload' => $vault->seal(
            $target, $config, $material['secret'], $material['passphrase'],
        )])->save();
        DB::table('targets')->where('id', $target->getKey())
            ->update(['relay_binding_revision' => 4294967294]);
        $target->refresh();
        $beforeDisableHash = SshTargetBinding::hash($target, $config);

        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->getKey().'/toggle';
        $this->post($url, [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();

        $target->refresh();
        self::assertSame(4294967295, $target->relay_binding_revision);
        self::assertNotSame($beforeDisableHash, SshTargetBinding::hash($target, $config));
        self::assertSame('ssh-secret', $vault->open($target, $config, $credential->fresh())['secret']);
        self::assertFalse($relay->fresh()->enabled);
        self::assertSame(2, $relay->fresh()->lifecycle_revision);

        $this->post($url, [
            'relay_revision' => 2, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay');

        self::assertFalse($relay->fresh()->enabled);
        self::assertSame(2, $relay->fresh()->lifecycle_revision);
        self::assertSame(4294967295, $target->fresh()->relay_binding_revision);
        self::assertSame('relay_disabled', $target->fresh()->last_error_code);
        self::assertNull(app(ConnectionRelayRoutes::class)->selectable()->first());
    }

    public function test_non_owner_cannot_rename_or_delete_relays(): void
    {
        $relay = ConnectionRelay::query()->create($this->relayFields());
        $this->actingAs($this->user('operator'));
        $this->put('/admin/settings/connection-relays/'.$relay->id.'/name', [
            'display_name' => 'Not authorized',
            'relay_revision' => 1,
            'current_password' => self::PASSWORD,
        ])->assertForbidden();
        $this->delete('/admin/settings/connection-relays/'.$relay->id, [
            'relay_revision' => 1,
            'confirm_relay_id' => 'iran-1',
            'current_password' => self::PASSWORD,
        ])->assertForbidden();
        self::assertSame('Iran shared relay', $relay->fresh()->display_name);
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

    public function test_relay_create_and_edit_validation_report_the_actual_invalid_field(): void
    {
        $this->actingAs($this->user('owner'));
        $invalid = [
            'control_host' => 'invalid host.example',
            'control_user' => 'invalid user',
            'control_port' => 70000,
            'control_host_key' => 'not a public host key',
        ];

        foreach ($invalid as $field => $value) {
            $this->post('/admin/settings/connection-relays', [
                ...$this->relayFields(), $field => $value,
                'current_password' => self::PASSWORD,
            ])->assertSessionHasErrors($field)
                ->assertSessionDoesntHaveErrors(array_values(array_diff(array_keys($invalid), [$field])))
                ->assertSessionHas('_old_input.'.$field, $value)
                ->assertSessionMissing('_old_input.current_password');
            self::assertSame(0, ConnectionRelay::query()->count(), 'Invalid Relay metadata must never persist.');
        }

        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(), 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $relay = ConnectionRelay::query()->sole();
        $before = $relay->only(['control_host', 'control_user', 'control_host_key']);

        foreach ($invalid as $field => $value) {
            $this->put('/admin/settings/connection-relays/'.$relay->getKey(), [
                ...$this->relayFields(), $field => $value,
                'relay_revision' => $relay->lifecycle_revision,
                'edit_relay_id' => (string) $relay->getKey(),
                'current_password' => self::PASSWORD,
            ])->assertSessionHasErrors($field)
                ->assertSessionDoesntHaveErrors(array_values(array_diff(array_keys($invalid), [$field])))
                ->assertSessionHas('_old_input.'.$field, $value)
                ->assertSessionMissing('_old_input.current_password');
            self::assertSame($before, $relay->fresh()->only(array_keys($before)), 'Invalid edit must not rotate persisted Relay identity.');
        }
    }

    public function test_relay_create_and_edit_reject_duplicate_id_and_listener_port_on_the_correct_field(): void
    {
        $this->actingAs($this->user('owner'));
        $one = ConnectionRelay::query()->create($this->relayFields());
        $other = ConnectionRelay::query()->create([
            ...$this->relayFields(),
            'relay_id' => 'iran-2',
            'local_socks_port' => 46082,
        ]);
        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(), 'local_socks_port' => 46083,
            'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_id');
        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(), 'relay_id' => 'iran-3',
            'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('local_socks_port');

        $url = '/admin/settings/connection-relays/'.$other->getKey();
        $this->put($url, [
            ...$this->relayFields(), 'local_socks_port' => 46082,
            'relay_revision' => 1, 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_id');
        $this->put($url, [
            ...$this->relayFields(), 'relay_id' => 'iran-2',
            'relay_revision' => 1, 'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('local_socks_port');
        self::assertSame('iran-2', $other->fresh()->relay_id);
        self::assertSame(46082, $other->fresh()->local_socks_port);
        self::assertSame('iran-1', $one->fresh()->relay_id);
    }

    public function test_only_owner_can_manage_relay_or_attach_target_to_it(): void
    {
        $this->actingAs($this->user('operator'));
        $this->get('/admin/settings/connection-relays')->assertForbidden();
        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(), 'current_password' => self::PASSWORD,
        ])->assertForbidden();
    }

    public function test_enabled_relay_can_be_reused_with_stable_ssh_credentials(): void
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
        DB::table('connection_relays')->where('id', $relay->getKey())->update(['enabled' => true]);

        return $relay->fresh();
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
