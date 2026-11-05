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
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostOperatorPlan;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostReadiness;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRetirementEvidence;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshDirectTargetAdapter;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Http\OutboundRequestException;
use App\Models\User;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;
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

    public function test_admin_status_distinguishes_draft_ready_enabled_degraded_and_needs_setup(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/settings/connection-relays', [
            ...$this->relayFields(), 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();

        $relay = ConnectionRelay::query()->sole();
        $path = '/admin/settings/connection-relays';
        $this->get($path)->assertOk()
            ->assertSee('Draft — host unverified')
            ->assertSee('Do not assume host resources are absent.');

        $readiness = new class extends ConnectionRelayHostReadiness
        {
            public bool $isReady = false;

            public function ready(ConnectionRelay $relay): bool
            {
                return $this->isReady;
            }
        };
        $this->app->instance(ConnectionRelayHostReadiness::class, $readiness);
        $readiness->isReady = true;
        $this->get($path)->assertOk()->assertSee('Ready — host evidence current');

        $this->post($path.'/'.$relay->id.'/toggle', [
            'relay_revision' => 1, 'enable' => '1', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $this->get($path)->assertOk()->assertSee('Enabled — host evidence current');

        $readiness->isReady = false;
        $this->get($path)->assertOk()
            ->assertSee('Degraded — routing blocked')
            ->assertSee('Bound Target operations fail closed')
            ->assertSee('disable this Relay now')
            ->assertSee('Gateway Repair is not available yet')
            ->assertSee('a permanently fenced record must never be reprovisioned');

        $this->post($path.'/'.$relay->id.'/toggle', [
            'relay_revision' => 2, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $this->get($path)->assertOk()
            ->assertSee('Needs setup or re-verification')
            ->assertSee('No supported Gateway Setup/Update/Repair or trusted attestation issuance is available yet')
            ->assertSee('a separately approved host procedure and independent readiness proof')
            ->assertSee('Bound Targets never fall back to Direct');
    }

    public function test_owner_can_manage_multiple_relays_and_rename_an_active_relay_without_rekeying_targets(): void
    {
        $first = $this->readyRelay();
        $second = ConnectionRelay::query()->create([
            ...$this->relayFields(),
            'relay_id' => 'iran-2',
            'display_name' => 'Secondary route',
            'local_socks_port' => 46082,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'relay-rename-active', 'SSH relay', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $oldEpoch = $target->relay_binding_revision;
        $fingerprint = $first->hostFingerprint();
        $this->actingAs($this->user('owner'));
        $this->get('/admin/settings/connection-relays')
            ->assertOk()
            ->assertSee('Iran shared relay')
            ->assertSee('Secondary route')
            ->assertSee('Rename Relay')
            ->assertSee('Retire and remove Relay')
            ->assertSee('Add Relay');

        $url = '/admin/settings/connection-relays/'.$first->getKey().'/name';
        $this->put($url, [
            'display_name' => 'Iran primary link',
            'relay_revision' => $first->lifecycle_revision,
            'current_password' => self::PASSWORD,
        ])->assertAdminRedirect('/admin/settings/connection-relays')->assertSessionHasNoErrors();

        $first->refresh();
        self::assertSame('Iran primary link', $first->display_name);
        self::assertTrue($first->enabled);
        self::assertSame(1, $first->configuration_revision);
        self::assertSame(2, $first->lifecycle_revision);
        self::assertSame($fingerprint, $first->hostFingerprint());
        self::assertSame($oldEpoch, $target->fresh()->relay_binding_revision);
        self::assertSame($first->id, $target->fresh()->relay_record_id);
        self::assertSame('Secondary route', $second->fresh()->display_name);

        $this->put($url, [
            'display_name' => 'Stale rename',
            'relay_revision' => 1,
            'current_password' => self::PASSWORD,
        ])->assertSessionHasErrors('relay_revision');
        self::assertSame('Iran primary link', $first->fresh()->display_name);

        $this->put($url, [
            'display_name' => 'Iran primary link',
            'relay_revision' => 2,
            'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        self::assertSame(2, $first->fresh()->lifecycle_revision);
    }

    public function test_delete_requires_local_cleanup_proof_owner_confirmation_and_explicit_target_detach(): void
    {
        $relay = $this->readyRelay();
        $target = app(SshTargetRegistration::class)->register(
            'relay-delete-bound', 'SSH relay', '1.1.1.1', 22,
            'deploy', $this->publicKey(), 'password', 'ssh-secret', null,
            connectionRelayId: 'iran-1',
        );
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->id;
        $fields = [
            'confirm_relay_id' => 'iran-1',
            'confirm_gateway_cleanup' => '1',
            'current_password' => self::PASSWORD,
        ];

        $this->delete($url, [...$fields, 'relay_revision' => 1])
            ->assertSessionHasErrors('relay');
        self::assertNotNull($relay->fresh());

        $this->post($url.'/toggle', [
            'relay_revision' => 1, 'enable' => '0', 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        $this->delete($url, [...$fields, 'relay_revision' => 2])
            ->assertSessionHasErrors('relay');
        self::assertNotNull($target->fresh()->relay_record_id);

        $bindings = app(ConnectionRelayTargetBinding::class);
        $target->refresh();
        $afterDisableEpoch = $target->relay_binding_revision;
        self::assertTrue($bindings->change($target, $bindings->revision($target), null));
        self::assertNull($target->fresh()->relay_record_id);
        self::assertGreaterThan($afterDisableEpoch, $target->fresh()->relay_binding_revision);

        $this->delete($url, [...$fields, 'relay_revision' => 1])
            ->assertSessionHasErrors('relay_revision');
        $this->delete($url, [...$fields, 'relay_revision' => 2, 'confirm_relay_id' => 'iran-2'])
            ->assertSessionHasErrors('confirm_relay_id');
        $this->delete($url, [...$fields, 'relay_revision' => 2, 'current_password' => 'bad password'])
            ->assertSessionHasErrors('current_password');
        $this->delete($url, [...$fields, 'relay_revision' => 2, 'confirm_gateway_cleanup' => ''])
            ->assertSessionHasErrors('confirm_gateway_cleanup');
        self::assertNotNull($relay->fresh());

        // Owner confirmation alone does not prove privileged host cleanup.
        $this->delete($url, [...$fields, 'relay_revision' => 2])
            ->assertSessionHasErrors('relay');
        self::assertNotNull($relay->fresh());

        // A real deployment requires fresh root-owned evidence ONLY for
        // Gateway-host cleanup. This fake is local-only and creates no files;
        // there is intentionally no Iran-host check or network requirement.
        $this->app->instance(ConnectionRelayRetirementEvidence::class, new class extends ConnectionRelayRetirementEvidence
        {
            public function verifiedForDeletion(ConnectionRelay $relay): bool
            {
                return true;
            }
        });
        $this->delete($url, [...$fields, 'relay_revision' => 2, 'confirm_gateway_cleanup' => ''])
            ->assertSessionHasErrors('confirm_gateway_cleanup');
        $this->delete($url, [...$fields, 'relay_revision' => 2])
            ->assertAdminRedirect('/admin/settings/connection-relays')->assertSessionHasNoErrors();
        self::assertNull(ConnectionRelay::query()->find($relay->getKey()));
        self::assertNull($target->fresh()->relay_record_id);
        self::assertSame(0, DB::table('targets')->whereNotNull('relay_record_id')->count());
    }

    public function test_new_host_claim_invalidates_old_retirement_proof_and_preserves_registration(): void
    {
        $relay = ConnectionRelay::query()->create($this->relayFields());
        $relay->refresh();
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->getKey();
        $form = [
            'relay_revision' => 1,
            'confirm_relay_id' => $relay->relay_id,
            'confirm_gateway_cleanup' => '1',
            'current_password' => self::PASSWORD,
        ];
        $directory = sys_get_temp_dir().'/relay-delete-test-'.bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        try {
            $evidence = new class($directory) extends ConnectionRelayRetirementEvidence
            {
                public ?\Closure $afterDeletionVerified = null;

                public function __construct(private readonly string $directory) {}

                public function verifiedForDeletion(ConnectionRelay $relay): bool
                {
                    $valid = parent::verifiedForDeletion($relay);
                    if ($valid && $this->afterDeletionVerified) {
                        ($this->afterDeletionVerified)($relay);
                    }

                    return $valid;
                }

                protected function evidenceDirectory(): string
                {
                    return $this->directory;
                }

                protected function trusted(string $path, bool $directory): bool
                {
                    if ($directory && $path !== $this->directory) {
                        return true;
                    }

                    return ! is_link($path) && ($directory ? is_dir($path) : is_file($path));
                }
            };
            $this->app->instance(ConnectionRelayRetirementEvidence::class, $evidence);
            $generation = str_repeat('b', 64);
            $state = [
                'version' => 1,
                'relay_record_id' => $relay->getKey(),
                'relay_id' => $relay->relay_id,
                'host_generation' => $generation,
                'state' => 'retired',
            ];
            $now = time();
            $boot = trim((string) file_get_contents('/proc/sys/kernel/random/boot_id'));
            $uptime = (int) floor((float) explode(' ', trim((string) file_get_contents('/proc/uptime')))[0]);
            $proof = [
                'relay_record_id' => $relay->getKey(),
                'relay_id' => $relay->relay_id,
                'host_fingerprint' => $relay->hostFingerprint(),
                'configuration_revision' => (int) $relay->configuration_revision,
                'host_generation' => $generation,
                'verified_boot_id' => $boot,
                'verified_at_unix' => $now,
                'verified_at_boot_seconds' => $uptime,
                'expires_at_unix' => $now + 600,
                'gateway_cleanup_verified' => true,
            ];
            $receipt = $directory.'/'.$relay->relay_id.'.retired.json';
            $stateFile = $directory.'/'.$relay->relay_id.'.generation.json';
            $claimFile = $directory.'/'.$relay->relay_id.'.managed.json';
            file_put_contents($receipt, json_encode($proof, JSON_THROW_ON_ERROR));
            file_put_contents($stateFile, json_encode($state, JSON_THROW_ON_ERROR));
            self::assertTrue($evidence->verified($relay));

            // A new host claim appears without any DB revision change.
            file_put_contents($claimFile, '{"version":2}');
            $this->delete($url, $form)->assertSessionHasErrors('relay');
            self::assertNotNull(ConnectionRelay::query()->find($relay->getKey()));
            unlink($claimFile);

            // Setup generation invalidation defeats a stale receipt even
            // before new resources have been installed.
            $state['state'] = 'provisioning';
            $state['host_generation'] = str_repeat('c', 64);
            file_put_contents($stateFile, json_encode($state, JSON_THROW_ON_ERROR));
            $this->delete($url, $form)->assertSessionHasErrors('relay');
            self::assertNotNull(ConnectionRelay::query()->find($relay->getKey()));

            // Only a new correct, root-analogous retirement proof unlocks
            // the previously blocked Owner action.
            $state['state'] = 'retired';
            $state['host_generation'] = str_repeat('d', 64);
            $proof['host_generation'] = $state['host_generation'];
            file_put_contents($stateFile, json_encode($state, JSON_THROW_ON_ERROR));
            file_put_contents($receipt, json_encode($proof, JSON_THROW_ON_ERROR));
            self::assertTrue($evidence->verified($relay));
            // Exact old race: a valid retirement receipt alone no longer
            // authorizes Delete, even with no active host claims.
            self::assertFalse($evidence->verifiedForDeletion($relay));
            $this->delete($url, $form)->assertSessionHasErrors('relay');
            self::assertNotNull(ConnectionRelay::query()->find($relay->getKey()));

            $fenceDirectory = $directory.'/.fences';
            mkdir($fenceDirectory, 0755);
            $fence = [
                'version' => 1,
                'relay_record_id' => $relay->getKey(),
                'relay_id' => $relay->relay_id,
                'host_fingerprint' => $relay->hostFingerprint(),
                'configuration_revision' => (int) $relay->configuration_revision,
                'host_generation' => $state['host_generation'],
                'intent' => 'delete',
            ];
            file_put_contents($fenceDirectory.'/'.$relay->getKey().'.json', json_encode($fence, JSON_THROW_ON_ERROR));
            self::assertTrue($evidence->verifiedForDeletion($relay));
            self::assertFalse($evidence->verifiedForRotation($relay));

            // Controlled cross-language concurrency injection. Run the
            // actual Python prepare_setup() AFTER PHP has verified the exact
            // fence, but BEFORE the controller commits the DB DELETE.
            // It must refuse without rotating the generation; otherwise the
            // callback fails the request and the DB row cannot be removed.
            $evidence->afterDeletionVerified = static function (ConnectionRelay $current) use ($directory, $stateFile): void {
                $python = <<<'PYTHON'
import os
import pathlib
import sys
sys.path.insert(0, sys.argv[1])
import test_connection_relay_gateway_host as fixtures
class FixtureLayout(fixtures.mod.Layout):
    @property
    def evidence_dir(self):
        return self.root
relay = fixtures.mod.Relay(sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6]), int(sys.argv[7]))
layout = FixtureLayout(pathlib.Path(sys.argv[2]), os.geteuid())
operator = fixtures.mod.Retirement(relay, layout, fixtures.FakeHost(relay))
try:
    operator.prepare_setup()
except fixtures.mod.Refusal as error:
    if 'permanently fenced' not in str(error):
        raise
    print('SETUP BLOCKED AFTER PHP VERIFIED')
else:
    raise SystemExit('UNSAFE: host Setup began after an irreversible delete fence')
PYTHON;
                $before = file_get_contents($stateFile);
                $probe = new Process([
                    '/usr/bin/python3', '-c', $python, base_path('tests/Support'),
                    $directory, $current->relay_id, (string) $current->getKey(),
                    $current->hostFingerprint(), (string) $current->configuration_revision,
                    (string) $current->local_socks_port,
                ], base_path());
                $probe->run();
                self::assertTrue($probe->isSuccessful(), $probe->getErrorOutput().' '.$probe->getOutput());
                self::assertStringContainsString('SETUP BLOCKED AFTER PHP VERIFIED', $probe->getOutput());
                self::assertSame($before, file_get_contents($stateFile), 'Blocked Setup must not rotate generation.');
            };
            $this->delete($url, $form)
                ->assertSessionHasNoErrors()
                ->assertAdminRedirect('/admin/settings/connection-relays');
            self::assertNull(ConnectionRelay::query()->find($relay->getKey()));
        } finally {
            // This exact disposable fixture includes the helper's private
            // test-only lock, not a production /run path.
            (new Filesystem)->deleteDirectory($directory);
        }
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

    public function test_operator_commands_are_relay_specific_release_pinned_and_fail_closed_on_stale_source(): void
    {
        $relay = ConnectionRelay::query()->create($this->relayFields());
        $relay->refresh(); // Database defaults own configuration_revision.
        $commands = app(ConnectionRelayHostOperatorPlan::class)->commands($relay);
        self::assertIsArray($commands);
        self::assertSame(hash_file('sha256', base_path('resources/host/connection-relay-gateway.py')), $commands['sha256']);
        foreach (['preflight', 'retire'] as $action) {
            self::assertStringContainsString('/usr/bin/sudo /usr/bin/sha256sum --check --status', $commands[$action]);
            self::assertStringContainsString('/usr/bin/sudo /usr/local/sbin/mcp-gateway-relay '.$action, $commands[$action]);
            self::assertStringContainsString($relay->relay_id, $commands[$action]);
            self::assertStringContainsString($relay->getKey(), $commands[$action]);
            self::assertStringContainsString($relay->hostFingerprint(), $commands[$action]);
            self::assertStringNotContainsString('ssh ', $commands[$action]);
        }
        self::assertStringContainsString('/usr/bin/sudo /usr/bin/bash -c', $commands['bootstrap']);
        self::assertStringContainsString('sha256sum --check --status', $commands['bootstrap']);
        self::assertStringContainsString('ln --', $commands['bootstrap']);
        self::assertStringContainsString('Untrusted host tool directory', $commands['bootstrap']);
        self::assertStringContainsString('Unknown or outdated installed host tool', $commands['bootstrap']);
        self::assertStringContainsString(
            '/usr/bin/sudo /usr/local/sbin/mcp-gateway-relay prepare-setup',
            $commands['prepare_setup'],
        );
        self::assertStringContainsString('if sealed=$(', $commands['cleanup']);
        self::assertStringNotContainsString('/etc/mcp-gateway/connection-relays/.fences/'.$relay->getKey().'.json', $commands['cleanup']);
        self::assertStringContainsString('if sealed=$(', $commands['cleanup_for_rotation']);
        self::assertStringContainsString('/usr/bin/sudo /usr/local/sbin/mcp-gateway-relay retire', $commands['cleanup']);
        self::assertStringContainsString('/usr/bin/sudo /usr/local/sbin/mcp-gateway-relay seal-delete', $commands['cleanup']);
        self::assertStringContainsString('/usr/bin/sudo /usr/local/sbin/mcp-gateway-relay seal-rotate', $commands['cleanup_for_rotation']);
        self::assertStringContainsString('/usr/bin/sudo /usr/local/sbin/mcp-gateway-relay seal-delete', $commands['seal_delete']);
        self::assertStringContainsString('/usr/bin/sudo /usr/local/sbin/mcp-gateway-relay seal-rotate', $commands['seal_rotate']);
        self::assertStringContainsString($commands['sha256'], $commands['bootstrap']);

        config()->set('connection_relays.gateway_retirement_helper_sha256', str_repeat('0', 64));
        self::assertNull(app(ConnectionRelayHostOperatorPlan::class)->commands($relay));
    }

    public function test_cleanup_sequence_retires_old_rotation_fence_but_only_renews_exact_current_fence(): void
    {
        $dir = sys_get_temp_dir().'/relay-operator-shell-'.bin2hex(random_bytes(8));
        mkdir($dir, 0700);
        try {
            $state = escapeshellarg($dir.'/fence');
            $seal = 'test "$(cat '.$state.' 2>/dev/null)" = current && printf "SEALED\n"';
            $retire = 'printf "RETIRED\n" && printf current > '.$state;
            $sequence = new \ReflectionMethod(ConnectionRelayHostOperatorPlan::class, 'cleanupSequence');
            $command = $sequence->invoke(null, $seal, $retire);
            self::assertIsString($command);
            $run = static function (string $shell): Process {
                $process = new Process(['/usr/bin/bash', '-c', $shell]);
                $process->run();

                return $process;
            };
            // On first use, Seal cannot verify retirement; fall back to
            // exact local retirement and then seal the current revision.
            $first = $run($command);
            self::assertTrue($first->isSuccessful(), $first->getErrorOutput());
            self::assertSame("RETIRED\nSEALED\n", $first->getOutput());
            // Replaying an already sealed operation renews the proof only.
            $again = $run($command);
            self::assertTrue($again->isSuccessful());
            self::assertSame("SEALED\n", $again->getOutput());
            // A prior rotation fence exists, but it is NOT a current Seal.
            file_put_contents($dir.'/fence', 'older-rotation');
            $later = $run($command);
            self::assertTrue($later->isSuccessful());
            self::assertSame("RETIRED\nSEALED\n", $later->getOutput());
            // No successful Seal or retirement can report cleanup success.
            file_put_contents($dir.'/fence', 'older-rotation');
            $blocked = $run($sequence->invoke(null, $seal, 'false'));
            self::assertFalse($blocked->isSuccessful());
        } finally {
            @unlink($dir.'/fence');
            rmdir($dir);
        }
    }

    public function test_disable_operator_plan_targets_the_exact_previous_owned_revision_and_current_seal(): void
    {
        $relay = $this->readyRelay();
        $original = $relay->hostFingerprint();
        self::assertTrue(app(ConnectionRelayAdministration::class)->disable($relay, 1));
        $relay->refresh();
        self::assertSame(2, $relay->configuration_revision);
        self::assertSame($original, $relay->hostFingerprint(1));
        self::assertNotSame($original, $relay->hostFingerprint());
        $commands = app(ConnectionRelayHostOperatorPlan::class)->commands($relay);
        self::assertIsArray($commands);
        // The cleanup command may inspect N or N+1 owned host claims; the
        // permanent root fence is issued only for the new DB revision N+1.
        self::assertStringContainsString('--revision 2 --local-port 46081 --prior-fingerprint '."'".$original."'", $commands['retire']);
        self::assertStringContainsString('--revision 2 --local-port 46081', $commands['seal_delete']);
        self::assertStringNotContainsString('--prior-fingerprint', $commands['seal_delete']);
        self::assertStringNotContainsString('--prior-fingerprint', $commands['seal_rotate']);
        self::assertStringNotContainsString('--prior-fingerprint', $commands['prepare_setup']);
        self::assertStringContainsString($relay->hostFingerprint(), $commands['cleanup']);
        self::assertStringContainsString($original, $commands['cleanup']);
        self::assertStringContainsString('--prior-fingerprint', $commands['preflight']);
    }

    public function test_edit_display_name_only_never_rotates_attestation_or_requires_host_command(): void
    {
        $relay = ConnectionRelay::query()->create($this->relayFields());
        $relay->refresh();
        $fingerprint = $relay->hostFingerprint();
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->getKey();
        $this->put($url, [
            ...$this->relayFields(), 'display_name' => 'Renamed within Edit form',
            'relay_revision' => 1, 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();

        $relay->refresh();
        self::assertSame('Renamed within Edit form', $relay->display_name);
        self::assertSame(1, $relay->configuration_revision);
        self::assertSame(2, $relay->lifecycle_revision);
        self::assertSame($fingerprint, $relay->hostFingerprint());

        $this->put($url, [
            ...$this->relayFields(), 'display_name' => 'Renamed within Edit form',
            'relay_revision' => 2, 'current_password' => self::PASSWORD,
        ])->assertSessionHasNoErrors();
        self::assertSame(2, $relay->fresh()->lifecycle_revision);
    }

    public function test_sensitive_edit_requires_retirement_and_internal_id_is_permanent(): void
    {
        $relay = ConnectionRelay::query()->create($this->relayFields());
        $this->actingAs($this->user('owner'));
        $url = '/admin/settings/connection-relays/'.$relay->getKey();
        $new = [...$this->relayFields(), 'control_host' => '198.51.100.99'];
        $form = [...$new, 'relay_revision' => 1, 'current_password' => self::PASSWORD];

        $this->put($url, $form)->assertSessionHasErrors('relay');
        self::assertSame('193.111.235.101', $relay->fresh()->control_host);
        self::assertSame(1, $relay->fresh()->configuration_revision);

        $this->put($url, [...$form, 'relay_id' => 'changed-relay-id'])
            ->assertSessionHasErrors('relay_id');
        self::assertSame('iran-1', $relay->fresh()->relay_id);

        // Only a separately privileged local helper can create real
        // retirement proof. This test-only fake performs no actual setup.
        $this->app->instance(ConnectionRelayRetirementEvidence::class, new class extends ConnectionRelayRetirementEvidence
        {
            public function verifiedForRotation(ConnectionRelay $relay): bool
            {
                return true;
            }
        });
        $oldFingerprint = $relay->hostFingerprint();
        $this->put($url, $form)->assertSessionHasNoErrors()
            ->assertAdminRedirect('/admin/settings/connection-relays');
        $relay->refresh();
        self::assertSame('198.51.100.99', $relay->control_host);
        self::assertSame(2, $relay->configuration_revision);
        self::assertSame(2, $relay->lifecycle_revision);
        self::assertNotSame($oldFingerprint, $relay->hostFingerprint());
        self::assertFalse($relay->enabled);

        $this->put($url, $form)->assertSessionHasErrors('relay');
        self::assertSame(2, $relay->fresh()->configuration_revision);
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
