<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\ConnectionRelayAdministration;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetReconfiguration;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\SftpAdmissionProbe;
use Tests\TestCase;

/** A disposable real OpenSSH fixture with a linger-enabled systemd user. */
final class SshJobFixtureTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        if (getenv('SSH_JOB_FIXTURE_ENABLED') !== '1') {
            $this->markTestSkipped('Disposable systemd-user SSH fixture is not configured.');
        }
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return ['127.0.0.1'];
            }
        });
    }

    /** @return array<string, array{bool}> */
    public static function supersededJobScriptCases(): array
    {
        return ['inline script' => [false], 'streamed script' => [true]];
    }

    #[DataProvider('supersededJobScriptCases')]
    public function test_job_refuses_script_publication_after_credential_rotation_and_reverification(bool $streamed): void
    {
        $owner = User::query()->create([
            'name' => 'Job binding fixture',
            'email' => 'job-binding-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $register = static function (string $id): Target {
            $target = app(SshTargetRegistration::class)->register(
                $id, 'Disposable Job binding fixture', 'fixture.example.test',
                (int) getenv('SSH_JOB_FIXTURE_PORT'), (string) getenv('SSH_JOB_FIXTURE_USER'),
                trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY'))),
                'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
                getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
            );
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

            return $target;
        };
        $target = $register('job-binding-fixture');
        $proofTarget = $register('job-binding-proof');
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->firstOrFail();
        $binding = SshTargetBinding::hash($target, $config);
        $requestId = (string) Str::uuid();
        $marker = '/home/'.getenv('SSH_JOB_FIXTURE_USER').'/unlaunched-'.bin2hex(random_bytes(9));
        $script = 'printf should-never-run > '.escapeshellarg($marker)."\n"
            .($streamed ? '# '.str_repeat('x', 20000)."\n" : '');
        DB::table('operational_settings')->where('id', 1)->update(['ssh_job_max_script_kib' => 64]);

        $fileChecks = 0;
        $changed = false;
        $disconnected = false;
        $reverified = false;
        /** @var bool $finished Read by the retained event listener after this operation returns. */
        $finished = false;
        $verifiedIp = null;
        $zeroProof = null;
        /** @var array<string,mixed>|null $payloadProof Populated by a later query-event callback. */
        $payloadProof = null;
        $directory = '';
        $findStage = '';
        DB::listen(function (QueryExecuted $query) use (
            &$fileChecks, &$changed, &$disconnected, &$reverified, &$finished,
            &$verifiedIp, &$zeroProof, &$payloadProof, &$directory, &$findStage,
            $owner, $target, $proofTarget, $config, $credential, $requestId,
        ): void {
            if ($finished || ! SftpAdmissionProbe::readsCredential($query, (string) $credential->getKey())) {
                return;
            }
            if ($reverified) {
                $payloadProof = app(SshCommandRuntime::class)->run(
                    $owner, $proofTarget, $findStage." -printf '%s\\n'",
                );

                return;
            }
            if ($changed || ++$fileChecks !== SftpAdmissionProbe::PRE_PAYLOAD_FENCE) {
                return;
            }
            $changed = true;
            $id = DB::table('ssh_command_jobs')->where('request_id', $requestId)->value('id');
            self::assertIsString($id);
            $directory = '/var/tmp/.mcp-gateway-job-'.$id;
            $findStage = 'find '.escapeshellarg($directory)
                ." -type f \\( -name payload -o -name '.gateway-stream-*.tmp' \\)";
            $zeroProof = app(SshCommandRuntime::class)->run(
                $owner, $proofTarget, $findStage." -printf '%s %m\\n'",
            );

            // Reseal the SAME valid key under the SAME endpoint/config.
            // expectedTargetBinding alone cannot detect this invalidation.
            $reconfiguration = app(SshTargetReconfiguration::class);
            $reconfiguration->update($target, [
                'configuration_revision' => $reconfiguration->revision($target),
                'ssh_host' => $config->host, 'ssh_port' => $config->port,
                'ssh_username' => $config->username, 'ssh_host_key' => $config->pinned_host_key,
                'ssh_auth_method' => 'private_key', 'ssh_trust_confirmed' => 'yes',
                'ssh_private_key' => (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
                'ssh_passphrase' => getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
            ]);
            $disconnected = $target->fresh()->getAttribute('connection_state') === TargetConnectionState::Disconnected;
            $verifiedIp = app(SshTargetConnectionService::class)->test($target->fresh());
            $reverified = $target->fresh()->getAttribute('connection_state') === TargetConnectionState::Connected;
        });

        try {
            $denied = app(SshJobMcpToolHandlers::class)->start(
                $owner, $target->target_id, hash('sha256', 'job-binding-fixture'), $requestId, $script, 60,
            );
        } finally {
            $finished = true;
        }
        self::assertTrue($changed, json_encode($denied));
        self::assertSame(SftpAdmissionProbe::PRE_PAYLOAD_FENCE, $fileChecks);
        self::assertTrue($disconnected);
        self::assertSame('127.0.0.1', $verifiedIp);
        self::assertTrue($reverified);
        self::assertIsArray($zeroProof);
        self::assertSame(0, $zeroProof['exit_code'], json_encode($zeroProof));
        self::assertSame("0 600\n", $zeroProof['stdout']);
        self::assertIsArray($payloadProof);
        self::assertSame(0, $payloadProof['exit_code'], json_encode($payloadProof));
        self::assertSame(strlen($script)."\n", $payloadProof['stdout'],
            'The complete private script reaches the final publication check.');
        self::assertSame($binding, SshTargetBinding::hash($target->fresh(), $config->fresh()));
        self::assertNotSame($credential->encrypted_payload, $credential->fresh()->encrypted_payload);
        self::assertFalse($denied['ok']);
        self::assertSame('target_changed', $denied['error']['code']);
        self::assertSame('failed', $denied['result']['status']);
        self::assertTrue($denied['result']['complete']);
        self::assertFalse($denied['result']['launch_admitted']);
        self::assertSame('pre_launch_failed', $denied['result']['terminal_reason']);
        self::assertFalse($denied['result']['retry_safe']);
        $id = $denied['result']['job_id'];
        self::assertSame('/var/tmp/.mcp-gateway-job-'.$id, $directory);
        self::assertSame('failed', DB::table('ssh_command_jobs')->where('id', $id)->value('status'));

        // Inspect the original endpoint independently: no published script,
        // wrapper, detached systemd unit or script effect, and no staging
        // residue. The preparing Job directory itself is an allowed effect.
        $proof = app(SshCommandRuntime::class)->run(
            $owner, $proofTarget,
            'test ! -e '.escapeshellarg($marker)
                .' && test "$(XDG_RUNTIME_DIR=/run/user/$(id -u)'
                .' DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus'
                .' systemctl --user show -p LoadState --value '.escapeshellarg('mgw-'.strtolower($id).'.service')
                .')" = not-found && find '.escapeshellarg($directory).' -mindepth 1 -print',
        );
        self::assertSame(0, $proof['exit_code'], json_encode($proof));
        self::assertSame($directory.'/.job-identity'."\n", $proof['stdout'], 'Only the private artifact witness may remain.');
        $cleanup = app(SshCommandRuntime::class)->run($owner, $proofTarget,
            'rm -- '.escapeshellarg($directory.'/.job-identity').' && rmdir -- '.escapeshellarg($directory));
        self::assertSame(0, $cleanup['exit_code'], json_encode($cleanup));
    }

    public function test_real_host_without_linger_refuses_detached_execution_before_script_staging(): void
    {
        if (getenv('SSH_JOB_FIXTURE_NO_LINGER') !== '1') {
            $this->markTestSkipped('Requires the same SSH fixture with linger deliberately disabled.');
        }

        $owner = User::query()->create([
            'name' => 'No-linger fixture',
            'email' => 'no-linger-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'no-linger-fixture', 'No linger', 'fixture.example.test',
            (int) getenv('SSH_JOB_FIXTURE_PORT'), (string) getenv('SSH_JOB_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY'))),
            'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
            getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        $started = app(SshJobMcpToolHandlers::class)->start(
            $owner, $target->target_id, hash('sha256', 'no-linger-client'),
            (string) Str::uuid(), 'sleep 19; echo must-not-run', 60,
        );
        self::assertFalse($started['ok']);
        self::assertSame('job_unsupported', $started['error']['code']);
        self::assertSame('unsupported', $started['result']['status']);
        self::assertSame('host_unsupported', $started['result']['terminal_reason']);
        self::assertFalse($started['result']['launch_admitted']);
        $evidence = json_decode(Crypt::decryptString(
            DB::table('ssh_command_jobs')->where('id', $started['result']['job_id'])->value('launch_observation_ciphertext'),
        ), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('completed', $evidence['status']);
        self::assertSame(0, $evidence['exit_code']);
        self::assertSame('job_unsupported', $evidence['error_code']);
        self::assertArrayNotHasKey('provider_cause', $evidence['diagnostics']);
        $directory = '/var/tmp/.mcp-gateway-job-'.$started['result']['job_id'];

        $probe = app(SshCommandMcpToolHandlers::class)->run(
            $owner, $target->target_id, 'test ! -e '.escapeshellarg($directory),
        );
        self::assertTrue($probe['ok'], json_encode($probe));
        self::assertSame(0, $probe['result']['exit_code']);
    }

    public function test_job_can_write_large_regular_files_while_capturing_bounded_stdout_and_stderr(): void
    {
        $owner = User::query()->create([
            'name' => 'Output-bound fixture',
            'email' => 'output-fixture-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'output-bound-fixture', 'Disposable output-bound SSH Job', 'fixture.example.test',
            (int) getenv('SSH_JOB_FIXTURE_PORT'), (string) getenv('SSH_JOB_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY'))),
            'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
            getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $client = hash('sha256', 'job-file-limit-fixture-client');

        $settings = app(OperationalSettings::class);
        $settings->save($owner, ['ssh_job_output_window_kib' => 512], $settings->state()['version']);

        // The former systemd-wide LimitFSIZE=1MiB terminated innocent package
        // extraction/writes. The temporary file is deliberately >1MiB, and
        // the script cleans only its own randomly named harmless fixture.
        $script = <<<'SH'
set -eu
fixture="$(mktemp /tmp/ssh-job-large-write-XXXXXXXX)"
trap 'rm -f -- "$fixture"' EXIT
head -c 3145728 /dev/zero > "$fixture"
test "$(wc -c < "$fixture")" -eq 3145728
head -c 1114112 /dev/zero
head -c 1114112 /dev/zero >&2
SH;

        $jobs = app(SshJobMcpToolHandlers::class);
        $start = $jobs->start(
            $owner, $target->target_id, $client, (string) Str::uuid(), $script, 60,
        );
        self::assertTrue($start['ok'], json_encode($start));
        $id = $start['result']['job_id'];

        $status = null;
        for ($i = 0; $i < 40; $i++) {
            $status = $jobs->status($owner, $target->target_id, $client, $id);
            if (($status['result']['status'] ?? null) === 'completed'
                && ($status['result']['exit_code'] ?? null) === 0) {
                break;
            }
            sleep(2);
        }
        self::assertSame('completed', $status['result']['status'] ?? null, json_encode($status));
        self::assertSame(0, $status['result']['exit_code'] ?? null, json_encode($status));

        foreach (['stdout', 'stderr'] as $stream) {
            $digest = hash_init('sha256');
            foreach ([0, 524288] as $offset) {
                $output = $jobs->output($owner, $target->target_id, $client, $id, $stream, $offset, 524288);
                self::assertTrue($output['ok'], $output['error']['code'] ?? '');
                self::assertSame(1048576, $output['result']['size']);
                self::assertSame(524288, $output['result']['length']);
                $bytes = base64_decode($output['result']['data'], true);
                self::assertSame(str_repeat("\0", 524288), $bytes);
                hash_update($digest, $bytes);
                self::assertSame($offset === 524288, $output['result']['end_of_file']);
                self::assertSame($offset === 524288 ? true : null, $output['result']['truncated']);
            }
            self::assertSame(hash('sha256', str_repeat("\0", 1048576)), hash_final($digest));
            $tail = $jobs->output($owner, $target->target_id, $client, $id, $stream, 1048570, 16);
            self::assertTrue($tail['ok'], $tail['error']['code'] ?? '');
            self::assertSame(6, $tail['result']['length']);
            self::assertSame(str_repeat("\0", 6), base64_decode($tail['result']['data'], true));
            self::assertTrue($tail['result']['end_of_file']);
            self::assertTrue($tail['result']['truncated']);
        }

        $directory = '/var/tmp/.mcp-gateway-job-'.$id;
        $unexpected = $directory.'/.unexpected-retention-witness';
        $injected = app(SshCommandRuntime::class)->run(
            $owner, $target,
            'test "$(cat -- '.escapeshellarg($directory.'/exit-code').')" = 0'
                .' && printf "retain" > '.escapeshellarg($unexpected),
        );
        self::assertSame(0, $injected['exit_code'], json_encode($injected));

        DB::table('ssh_command_jobs')->where('id', $id)->update(['expires_at' => now()->subMinute()]);
        self::assertSame(0, app(SshJobCoordinator::class)->prune(),
            'An unexpected file must block cleanup before any stdout/stderr/exit-code unlink.');
        self::assertSame(1, DB::table('ssh_command_jobs')->where('id', $id)->count());
        $preserved = app(SshCommandRuntime::class)->run(
            $owner, $target,
            'test -s '.escapeshellarg($directory.'/stdout')
                .' && test -s '.escapeshellarg($directory.'/stderr')
                .' && test "$(cat -- '.escapeshellarg($directory.'/exit-code').')" = 0'
                .' && test -f '.escapeshellarg($unexpected),
        );
        self::assertSame(0, $preserved['exit_code'], json_encode($preserved));

        $removed = app(SshCommandRuntime::class)->run(
            $owner, $target, 'rm -f -- '.escapeshellarg($unexpected),
        );
        self::assertSame(0, $removed['exit_code'], json_encode($removed));
        self::assertSame(1, app(SshJobCoordinator::class)->prune(),
            'The same Job must be safely prunable after the unexpected entry is removed.');
        self::assertSame(0, DB::table('ssh_command_jobs')->where('id', $id)->count());
    }

    public function test_client_initiated_reverse_route_retained_job_stays_bound_and_completes(): void
    {
        $forwardPort = (int) getenv('SSH_FIXTURE_REVERSE_PORT');
        self::assertSame(46250, $forwardPort, 'Disposable reverse listener required.');

        config()->set('ssh.reverse_approved_routes', json_encode([
            'reverse-job-fixture' => ['port' => $forwardPort, 'tunnel_identity' => 'job-test-forward'],
        ], JSON_THROW_ON_ERROR));

        $owner = User::query()->create([
            'name' => 'Reverse SSH Job fixture',
            'email' => 'reverse-job-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'reverse-job-fixture', 'Reverse SSH Job fixture', 'fixture.example.test',
            (int) getenv('SSH_FIXTURE_PORT_MODERN'), (string) getenv('SSH_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_FIXTURE_ED25519_HOST_PUB'))),
            'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
            getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
            null, 'reverse', $forwardPort, 'job-test-forward',
        );
        // Use actual transport login, not merely a fake Connected flag.
        app(SshTargetConnectionService::class)->test($target);
        $target->refresh();
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);

        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole();
        self::assertNull($config->observed_peer_ip);
        self::assertNotNull($config->observed_at);
        $expectedBinding = SshTargetBinding::hash($target, $config);
        $client = hash('sha256', 'reverse-job-only-fixture-client');
        $requestId = (string) Str::uuid();
        $tools = app(SshJobMcpToolHandlers::class);
        $start = $tools->start(
            $owner, $target->target_id, $client, $requestId,
            'printf reverse_retained_job_ok', 60,
        );
        self::assertTrue($start['ok'], json_encode($start));
        $id = $start['result']['job_id'];
        self::assertSame($expectedBinding, DB::table('ssh_command_jobs')->where('id', $id)->value('target_binding_hash'));
        $otherRequest = (string) Str::uuid();
        $active = $tools->start($owner, $target->target_id, $client, $otherRequest, 'sleep 90', 120);
        self::assertTrue($active['ok'], json_encode($active));
        $activeId = $active['result']['job_id'];
        $firstPage = $tools->list($owner, $target->target_id, $client, limit: 1);
        self::assertSame($activeId, $firstPage['result']['jobs'][0]['job_id']);
        $cursor = $firstPage['result']['next_cursor'];
        self::assertIsString($cursor);

        // Switch only the path, using the real reconfiguration and pinned
        // login. No old route/grant is reused for these fresh follow-ups.
        $reconfiguration = app(SshTargetReconfiguration::class);
        $reconfiguration->update($target, [
            'configuration_revision' => $reconfiguration->revision($target),
            'ssh_host' => $config->host, 'ssh_port' => $config->port,
            'ssh_username' => $config->username, 'ssh_host_key' => $config->pinned_host_key,
            'ssh_auth_method' => 'private_key', 'ssh_trust_confirmed' => 'yes',
            'ssh_route_mode' => 'direct',
        ]);
        $target->refresh();
        // Route-only changes preserve the credential/connection lifecycle
        // but invalidate the previous path's verification observation.
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        self::assertNull($target->last_tested_at);
        self::assertSame('direct', $target->transportKind());
        self::assertNotSame($expectedBinding, SshTargetBinding::hash($target, $config->fresh()));
        self::assertSame($id, $tools->list($owner, $target->target_id, $client, cursor: $cursor, limit: 1)['result']['jobs'][0]['job_id']);
        self::assertSame($id, $tools->start($owner, $target->target_id, $client, $requestId, 'printf reverse_retained_job_ok', 60)['result']['job_id']);
        app(SshTargetConnectionService::class)->test($target);
        $target->refresh();
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        self::assertNotSame($expectedBinding, SshTargetBinding::hash($target, $config->fresh()));

        $stop = $tools->cancel($owner, $target->target_id, $client, $activeId);
        self::assertSame('canceled', $stop['result']['status'] ?? null, json_encode($stop));
        self::assertTrue($stop['result']['remote_observed']);
        $status = null;
        for ($attempt = 0; $attempt < 30; $attempt++) {
            $status = $tools->status($owner, $target->target_id, $client, $id);
            if (($status['result']['status'] ?? null) === 'completed'
                && ($status['result']['exit_code'] ?? null) === 0) {
                break;
            }
            sleep(2);
        }
        self::assertSame('completed', $status['result']['status'] ?? null, json_encode($status));
        self::assertSame(0, $status['result']['exit_code'] ?? null, json_encode($status));
        $output = $tools->output($owner, $target->target_id, $client, $id, 'stdout', 0, 16384);
        self::assertTrue($output['ok'], json_encode($output));
        self::assertSame('reverse_retained_job_ok', base64_decode((string) $output['result']['data'], true));
        self::assertSame($expectedBinding, DB::table('ssh_command_jobs')->where('id', $id)->value('target_binding_hash'));

        // Refuse output on a fresh route if the private original artifact
        // witness is not present. Restore the exact fixture witness after.
        $marker = '/var/tmp/.mcp-gateway-job-'.$id.'/.job-identity';
        $runtime = app(SshCommandRuntime::class);
        $hide = $runtime->run($owner, $target, 'mv -- '.escapeshellarg($marker).' '.escapeshellarg($marker.'.fixture'));
        self::assertSame(0, $hide['exit_code']);
        try {
            $denied = $tools->output($owner, $target->target_id, $client, $id, 'stdout');
            self::assertFalse($denied['ok'], json_encode($denied));
            self::assertSame('job_identity_unverified', $denied['error']['code']);
            self::assertArrayNotHasKey('result', $denied);
        } finally {
            $restore = $runtime->run($owner, $target, 'mv -- '.escapeshellarg($marker.'.fixture').' '.escapeshellarg($marker));
            self::assertSame(0, $restore['exit_code']);
        }
        $discovered = $tools->list($owner, $target->target_id, $client);
        self::assertTrue($discovered['ok'], json_encode($discovered));
        self::assertCount(2, $discovered['result']['jobs']);
        DB::table('ssh_command_jobs')->whereIn('id', [$id, $activeId])->update(['expires_at' => now()->subMinute()]);
        self::assertSame(2, app(SshJobCoordinator::class)->prune());
    }

    public function test_real_relay_large_retained_job_recovers_without_relaunch(): void
    {
        // The existing ssh-fixture.sh owns independently pinned native
        // OpenSSH control/Target daemons and the live loopback SOCKS listener.
        // Only its deterministic loopback address policy is substituted.
        self::assertSame(46251, (int) getenv('SSH_FIXTURE_RELAY_SOCKS_PORT'));
        $account = (string) getenv('SSH_JOB_FIXTURE_USER');
        self::assertMatchesRegularExpression('/^mcpfx[0-9]+$/D', $account);
        $owner = User::query()->create([
            'name' => 'Disposable retained Relay Job',
            'email' => 'relay-job-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $relay = ConnectionRelay::query()->create([
            'relay_id' => 'retained-job-relay', 'display_name' => 'Disposable native Relay',
            'control_host' => 'fixture-relay.example.test',
            'control_port' => (int) getenv('SSH_FIXTURE_RELAY_CONTROL_PORT'),
            'control_user' => $account,
            'control_host_key' => trim((string) file_get_contents((string) getenv('SSH_FIXTURE_REVERSE_CONTROL_HOST_PUB'))),
            'local_socks_port' => (int) getenv('SSH_FIXTURE_RELAY_SOCKS_PORT'),
        ]);
        $relay->refresh();
        $admin = app(ConnectionRelayAdministration::class);
        self::assertTrue($admin->setEnabled($relay, $relay->lifecycle_revision, true));
        $pin = trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY')));
        self::assertNotSame($relay->control_host_key, $pin);
        $register = static function (string $id, ?string $relayId) use ($account, $pin): Target {
            $target = app(SshTargetRegistration::class)->register(
                $id, 'Disposable retained Job fixture', 'fixture.example.test',
                (int) getenv('SSH_JOB_FIXTURE_PORT'), $account, $pin,
                'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
                getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
                connectionRelayId: $relayId,
            );
            app(SshTargetConnectionService::class)->test($target);

            return $target->fresh();
        };
        $target = $register('relay-retained-job', $relay->relay_id);
        $direct = $register('relay-job-direct-control', null);
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        self::assertSame('relay', $target->transportKind());
        self::assertSame($relay->id, $target->relay_record_id);
        self::assertSame(TargetConnectionState::Connected, $direct->connection_state);
        self::assertSame('direct', $direct->transportKind());

        $settings = app(OperationalSettings::class);
        $settings->save($owner, ['ssh_job_max_script_kib' => 512], $settings->state()['version']);
        self::assertSame(524288, $settings->sshJobLimits()['max_script_bytes']);
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole();
        $binding = SshTargetBinding::hash($target, $config);
        $client = hash('sha256', 'relay-retained-job-fixture');
        $request = (string) Str::uuid();
        $effect = '/home/'.$account.'/relay-job-'.$request;
        $tail = "\n".'set -eu; printf "once\\n" >> '.escapeshellarg($effect)
            .'; printf relay-job-stdout; printf relay-job-stderr >&2; exit 0';
        $script = '# '.str_repeat('x', 524288 - 2 - strlen($tail)).$tail;
        $digest = hash('sha256', $script);
        $jobs = app(SshJobMcpToolHandlers::class);
        $commands = app(SshCommandMcpToolHandlers::class);
        $started = $jobs->start($owner, $target->target_id, $client, $request, $script, 60);
        self::assertTrue($started['ok'], json_encode($started));
        self::assertTrue($started['result']['launch_admitted']);
        $id = $started['result']['job_id'];
        $row = static fn () => DB::table('ssh_command_jobs')->where('id', $id);
        $directory = '/var/tmp/.mcp-gateway-job-'.$id;
        self::assertSame($binding, $row()->value('target_binding_hash'));
        self::assertSame(hash_hmac('sha256', $script, (string) config('app.key')), $row()->value('script_digest'));

        $status = null;
        for ($attempt = 0; $attempt < 30; $attempt++) {
            $status = $jobs->status($owner, $target->target_id, $client, $id);
            if (($status['result']['complete'] ?? false) === true) {
                break;
            }
            sleep(1);
        }
        self::assertSame('completed', $status['result']['status'] ?? null, json_encode($status));
        self::assertSame(0, $status['result']['exit_code'] ?? null);
        self::assertSame('script_exit', $status['result']['terminal_reason'] ?? null);
        $assertOutput = static function () use ($jobs, $owner, $target, $client, $id): void {
            foreach (['stdout' => 'relay-job-stdout', 'stderr' => 'relay-job-stderr'] as $stream => $expected) {
                $output = $jobs->output($owner, $target->target_id, $client, $id, $stream);
                self::assertTrue($output['ok'], json_encode($output));
                self::assertSame($expected, base64_decode($output['result']['data'], true));
                self::assertTrue($output['result']['end_of_file']);
                self::assertFalse($output['result']['truncated']);
            }
        };
        $assertOutput();

        // An independent direct control sees the complete actual script
        // bytes and exactly one execution marker. The retained row alone
        // would not prove either fact.
        $verifyStored = static function () use ($commands, $owner, $direct, $directory, $effect, $digest): void {
            $proof = $commands->run($owner, $direct->target_id,
                'test "$(wc -c < '.escapeshellarg($directory.'/script.sh').')" -eq 524288'
                .' && test "$(sha256sum -- '.escapeshellarg($directory.'/script.sh').' | cut -d " " -f 1)" = '.escapeshellarg($digest)
                .' && cat -- '.escapeshellarg($effect));
            self::assertTrue($proof['ok'], json_encode($proof));
            self::assertSame(0, $proof['result']['exit_code']);
            self::assertSame("once\n", $proof['result']['stdout']);
        };
        $verifyStored();
        $history = (array) $row()->sole();
        $ciphertext = TargetCredential::query()->where('target_record_id', $target->getKey())->sole()->encrypted_payload;

        // The actual native SOCKS listener stays up. This isolates the
        // administrative availability fence from a TCP failure. Direct
        // remains available, but remote retained reads must not fall back.
        self::assertTrue($admin->setEnabled($relay->fresh(), $relay->fresh()->lifecycle_revision, false));
        try {
            $target->refresh();
            self::assertSame('relay', $target->transportKind());
            self::assertSame($relay->id, $target->relay_record_id);
            $local = $jobs->status($owner, $target->target_id, $client, $id);
            self::assertTrue($local['ok']);
            self::assertSame('completed', $local['result']['status']);
            self::assertSame(0, $local['result']['exit_code']);
            self::assertFalse($local['result']['remote_observed']);
            $denied = $jobs->output($owner, $target->target_id, $client, $id);
            self::assertFalse($denied['ok'], json_encode($denied));
            self::assertSame('relay_unavailable', $denied['error']['code']);
            $duplicate = $jobs->start($owner, $target->target_id, $client, $request, $script, 60);
            self::assertTrue($duplicate['ok']);
            self::assertSame($id, $duplicate['result']['job_id']);
            self::assertSame($history, (array) $row()->sole());
            $verifyStored();
        } finally {
            self::assertTrue($admin->setEnabled($relay->fresh(), $relay->fresh()->lifecycle_revision, true));
        }
        app(SshTargetConnectionService::class)->test($target->fresh());
        $target->refresh();
        self::assertSame('relay', $target->transportKind());
        self::assertNotSame($binding, SshTargetBinding::hash($target, $config->fresh()));
        self::assertSame($ciphertext, TargetCredential::query()->where('target_record_id', $target->getKey())->sole()->encrypted_payload);
        $assertOutput();
        $duplicate = $jobs->start($owner, $target->target_id, $client, $request, $script, 60);
        self::assertTrue($duplicate['ok']);
        self::assertSame($id, $duplicate['result']['job_id']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
        self::assertSame($history, (array) $row()->sole());
        $verifyStored();

        // Expire only this completed disposable row; use actual product
        // pruning over the current selected route and independently verify
        // that neither the owned spool nor the test marker remains.
        $row()->update(['expires_at' => now()->subMinute()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, $row()->count());
        $cleanup = $commands->run($owner, $direct->target_id,
            'test ! -e '.escapeshellarg($directory).' && rm -- '.escapeshellarg($effect)
            .' && test ! -e '.escapeshellarg($effect));
        self::assertTrue($cleanup['ok'], json_encode($cleanup));
        self::assertSame(0, $cleanup['result']['exit_code']);
        fwrite(STDOUT, 'PASS: retained native Relay Job '.json_encode([
            'script_bytes' => strlen($script), 'script_sha256' => $digest,
            'exit_code' => 0, 'stdout' => 'relay-job-stdout', 'stderr' => 'relay-job-stderr',
            'exact_stored_script' => true, 'single_execution_marker' => true,
            'disabled_remote_read' => 'relay_unavailable', 'direct_control_available' => true,
            'same_job_after_restore' => true, 'immutable_history' => true, 'cleanup_confirmed' => true,
        ], JSON_THROW_ON_ERROR)."\n");
    }

    public function test_retained_job_sftp_reads_recheck_command_scope_on_every_native_session(): void
    {
        $actor = User::query()->create([
            'name' => 'Retained read scope fixture',
            'email' => 'retained-scope-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'operator',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'retained-read-fixture', 'Disposable retained read fixture', 'fixture.example.test',
            (int) getenv('SSH_JOB_FIXTURE_PORT'), (string) getenv('SSH_JOB_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY'))),
            'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
            getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
        );
        app(SshTargetConnectionService::class)->test($target);
        $target->refresh();
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        $client = hash('sha256', 'retained-read-scope');
        $tools = app(SshJobMcpToolHandlers::class);
        $request = (string) Str::uuid();
        $script = 'head -c 1114112 /dev/zero';
        $start = $tools->start($actor, $target->target_id, $client, $request, $script, 60);
        self::assertTrue($start['ok'], json_encode($start));
        $id = $start['result']['job_id'];
        // Use a fresh builder: SQLite limited updates mutate the selected
        // columns to rowid, so reusing a builder after value()/update()
        // can read rowid instead of the requested journal field.
        $row = static fn () => DB::table('ssh_command_jobs')->where('id', $id);
        $binding = $row()->value('target_binding_hash');
        for ($i = 0; $i < 10; $i++) {
            $status = $tools->status($actor, $target->target_id, $client, $id);
            if (($status['result']['status'] ?? null) === 'completed') {
                break;
            }
            sleep(1);
        }
        self::assertSame('completed', $status['result']['status'] ?? null, json_encode($status));
        $directory = '/var/tmp/.mcp-gateway-job-'.$id;
        $grant = static fn (GatewayPermission $permission) => DB::table('user_target_permission_denials')
            ->where('user_id', $actor->getKey())->where('target_record_id', $target->getKey())
            ->where('permission', $permission->value);
        $deny = static function (GatewayPermission $permission) use ($actor, $target): void {
            DB::table('user_target_permission_denials')->insert([
                'user_id' => $actor->getKey(), 'target_record_id' => $target->getKey(),
                'permission' => $permission->value, 'created_at' => now(), 'updated_at' => now(),
            ]);
        };
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $credentialId = (string) $credential->getKey();
        $fence = 0;
        $reads = 0;
        DB::listen(static function (QueryExecuted $event) use (&$fence, &$reads, &$credentialId, $deny): void {
            if ($fence > 0 && SftpAdmissionProbe::readsCredential($event, $credentialId) && ++$reads === $fence) {
                // This listener is at the real native admission's credential
                // read, BEFORE its current combined permission decision.
                $deny(GatewayPermission::SshCommandRun);
            }
        });
        $atFence = static function (int $boundary, callable $operation) use (&$fence, &$reads): array {
            $reads = 0;
            $fence = $boundary;
            try {
                $response = $operation();
                self::assertSame($boundary, $reads, json_encode($response));
                self::assertFalse($response['ok'], json_encode($response));
                self::assertSame('forbidden', $response['error']['code']);

                return $response;
            } finally {
                $fence = 0;
            }
        };
        $output = static fn () => $tools->output($actor, $target->target_id, $client, $id, 'stdout', 1048570, 16);
        $positive = $output();
        self::assertTrue($positive['ok'], json_encode($positive));
        self::assertTrue($positive['result']['truncated']);

        // Original binding: pre-login, before the actual payload get, and
        // the next session's pre-login for the separate truncation marker.
        foreach ([1, 3, 5] as $boundary) {
            try {
                $rejected = $atFence($boundary, $output);
                self::assertArrayNotHasKey('result', $rejected);
                self::assertTrue(app(AccessControl::class)->allows($actor, GatewayPermission::SshFileRead, $target));
                self::assertFalse(app(AccessControl::class)->allows($actor, GatewayPermission::SshCommandRun, $target));
                if ($boundary === 1) {
                    // Independent ordinary SFTP scope must remain usable.
                    $plain = app(SshFileRuntime::class)->read($actor, $target, $directory.'/stdout', 0, 1);
                    self::assertSame(base64_encode("\0"), $plain['data']);
                }
            } finally {
                $grant(GatewayPermission::SshCommandRun)->delete();
            }
        }

        // Simulate a remote-completed Job whose last local status response
        // was lost. Its actual exit marker exists on the disposable host.
        self::assertSame(1, $row()->update(['status' => 'running', 'exit_code' => null, 'terminal_reason' => null]));
        self::assertNull($row()->value('exit_code'));
        foreach (['status', 'cancel'] as $operation) {
            try {
                $rejected = $atFence(3, static fn () => $tools->{$operation}($actor, $target->target_id, $client, $id));
                self::assertFalse($rejected['result']['remote_observed']);
                self::assertNull($row()->value('exit_code'));
                self::assertSame($operation === 'cancel' ? 'cancel_requested' : 'running', $row()->value('status'));
            } finally {
                $grant(GatewayPermission::SshCommandRun)->delete();
            }
        }
        self::assertSame('completed', $tools->status($actor, $target->target_id, $client, $id)['result']['status']);

        // Reconfigure an alias, not the peer/account. Reverify using the
        // real transport. The retained Job now needs the artifact witness.
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole();
        $reconfigure = app(SshTargetReconfiguration::class);
        $reconfigure->update($target, [
            'configuration_revision' => $reconfigure->revision($target),
            'ssh_host' => 'fixture-rebound.example.test', 'ssh_port' => $config->port,
            'ssh_username' => $config->username, 'ssh_host_key' => $config->pinned_host_key,
            'ssh_auth_method' => 'private_key', 'ssh_trust_confirmed' => 'yes',
            'ssh_route_mode' => 'direct',
        ]);
        app(SshTargetConnectionService::class)->test($target->fresh());
        $target->refresh();
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        self::assertNotSame($binding, SshTargetBinding::hash($target, $config->fresh()));
        $credentialId = (string) TargetCredential::query()->where('target_record_id', $target->getKey())->sole()->getKey();
        // Pre-login, post-login, directory/marker metadata, witness bytes,
        // then post-witness authority before the requested file's metadata.
        foreach ([5, 6, 7] as $boundary) {
            try {
                $rejected = $atFence($boundary, $output);
                self::assertArrayNotHasKey('result', $rejected);
            } finally {
                $grant(GatewayPermission::SshCommandRun)->delete();
            }
        }
        $positive = $output();
        self::assertTrue($positive['ok'], json_encode($positive));
        self::assertSame(base64_encode(str_repeat("\0", 6)), $positive['result']['data']);
        self::assertTrue($positive['result']['truncated']);
        self::assertSame(1, $row()->update(['status' => 'running', 'exit_code' => null, 'terminal_reason' => null]));
        self::assertNull($row()->value('exit_code'));
        try {
            $rejected = $atFence(6, static fn () => $tools->status($actor, $target->target_id, $client, $id));
            self::assertFalse($rejected['result']['remote_observed']);
            self::assertNull($row()->value('exit_code'));
        } finally {
            $grant(GatewayPermission::SshCommandRun)->delete();
        }
        self::assertSame('completed', $tools->status($actor, $target->target_id, $client, $id)['result']['status']);

        // Optional SFTP rights do not become mandatory for command-only
        // status or local history. Nor can retained reads borrow write scope.
        $active = $tools->start($actor, $target->target_id, $client, (string) Str::uuid(), 'sleep 30', 60);
        self::assertTrue($active['ok'], json_encode($active));
        $activeId = $active['result']['job_id'];
        $deny(GatewayPermission::SshFileRead);
        $deny(GatewayPermission::SshFileWrite);
        try {
            $status = $tools->status($actor, $target->target_id, $client, $activeId);
            self::assertTrue($status['ok'], json_encode($status));
            self::assertSame('running', $status['result']['status']);
            self::assertTrue($status['result']['remote_observed']);
            self::assertCount(2, $tools->list($actor, $target->target_id, $client)['result']['jobs']);
            self::assertSame($id, $tools->start($actor, $target->target_id, $client, $request, $script, 60)['result']['job_id']);
        } finally {
            $grant(GatewayPermission::SshFileRead)->delete();
            $grant(GatewayPermission::SshFileWrite)->delete();
        }
        $stop = $tools->cancel($actor, $target->target_id, $client, $activeId);
        self::assertSame('canceled', $stop['result']['status'], json_encode($stop));
        DB::table('ssh_command_jobs')->whereIn('id', [$id, $activeId])->update(['expires_at' => now()->subMinute()]);
        self::assertSame(2, app(SshJobCoordinator::class)->prune());
    }

    public function test_real_job_probe_preserves_native_connection_and_admission_failures(): void
    {
        $actor = User::query()->create([
            'name' => 'Native probe failure fixture',
            'email' => 'probe-failure-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'operator',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $pin = trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY')));
        $wrongPin = trim((string) file_get_contents((string) getenv('SSH_FIXTURE_WRONG_ED25519_HOST_PUB')));
        self::assertNotSame($pin, $wrongPin);
        $key = (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY'));
        $passphrase = getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null;
        $client = hash('sha256', 'native-probe-failure');
        $ids = [];
        foreach ([
            'host_key_mismatch' => 'pin', 'authentication_failed' => 'auth',
            'dispatch_lease_expired' => 'lease', 'forbidden' => 'grant',
        ] as $code => $kind) {
            $target = app(SshTargetRegistration::class)->register(
                'probe-failure-'.$kind, 'Disposable probe failure', 'fixture.example.test',
                (int) getenv('SSH_JOB_FIXTURE_PORT'), (string) getenv('SSH_JOB_FIXTURE_USER'),
                $kind === 'pin' ? $wrongPin : $pin,
                $kind === 'auth' ? 'password' : 'private_key',
                $kind === 'auth' ? 'invalid-fixture-password' : $key,
                $kind === 'auth' ? null : $passphrase,
            );
            // Model a previously connected Target whose next native probe
            // now encounters the actual pinned-login/admission failure.
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
            $request = (string) Str::uuid();
            $dialed = false;
            $onDial = static function () use (&$dialed, $kind, $actor, $target, $request): void {
                $dialed = true;
                if ($kind === 'lease') {
                    $row = DB::table('ssh_command_jobs')->where('request_id', $request);
                    self::assertSame('preparing', $row->value('status'));
                    $row->update(['preparing_expires_at' => now()->subSecond()]);
                } elseif ($kind === 'grant') {
                    DB::table('user_target_permission_denials')->insert([
                        'user_id' => $actor->getKey(), 'target_record_id' => $target->getKey(),
                        'permission' => GatewayPermission::SshCommandRun->value,
                        'created_at' => now(), 'updated_at' => now(),
                    ]);
                }
            };
            $this->app->instance(SshDialAddressPolicy::class, new class($onDial) implements SshDialAddressPolicy
            {
                public function __construct(private readonly \Closure $onDial) {}

                public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
                {
                    ($this->onDial)();

                    return ['127.0.0.1'];
                }
            });
            $jobs = app(SshJobMcpToolHandlers::class);
            try {
                $response = $jobs->start($actor, $target->target_id, $client, $request, 'printf must-not-launch', 60);
                self::assertTrue($dialed);
                self::assertFalse($response['ok'], json_encode($response));
                self::assertSame($code, $response['error']['code'], json_encode($response));
                self::assertSame('failed', $response['result']['status']);
                self::assertSame('pre_dispatch_failed', $response['result']['terminal_reason']);
                self::assertFalse($response['result']['launch_admitted']);
                $id = $response['result']['job_id'];
                $ids[] = $id;
                $row = DB::table('ssh_command_jobs')->where('id', $id)->sole();
                self::assertNull($row->unit_mode);
                $evidence = json_decode(Crypt::decryptString($row->launch_observation_ciphertext), true, flags: JSON_THROW_ON_ERROR);
                self::assertSame($code, $evidence['error_code']);
                self::assertSame('probe', $evidence['stage']);
                self::assertSame(in_array($kind, ['pin', 'auth'], true) ? 'gateway_transport' : 'gateway_admission', $evidence['diagnostics']['failure_origin']);
                self::assertFalse($evidence['diagnostics']['job_launch_admitted']);
            } finally {
                DB::table('user_target_permission_denials')
                    ->where('user_id', $actor->getKey())->where('target_record_id', $target->getKey())
                    ->where('permission', GatewayPermission::SshCommandRun->value)->delete();
            }
            $dialed = false;
            $same = $jobs->start($actor, $target->target_id, $client, $request, 'printf must-not-launch', 60);
            self::assertFalse($dialed, 'Exact failed request recovery must never probe again.');
            self::assertSame($id, $same['result']['job_id']);
            self::assertSame($code, $same['error']['code']);
        }
        // The final Target has correct fixture credentials and its command
        // grant is restored. Prove there was no staging directory for any
        // of the failed preparations, using a normal authorized command.
        $this->app->instance(SshDialAddressPolicy::class, new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return ['127.0.0.1'];
            }
        });
        $proof = app(SshCommandRuntime::class)->run($actor, $target, implode(' && ', array_map(
            static fn (string $id): string => 'test ! -e '.escapeshellarg('/var/tmp/.mcp-gateway-job-'.$id),
            $ids,
        )));
        self::assertSame(0, $proof['exit_code'], json_encode($proof));
        DB::table('ssh_command_jobs')->whereIn('id', $ids)->update(['expires_at' => now()->subMinute()]);
        self::assertSame(count($ids), app(SshJobCoordinator::class)->prune());
    }

    public function test_final_launch_lease_expiry_after_reservation_fences_real_systemd_exec(): void
    {
        $owner = User::query()->create([
            'name' => 'Final launch lease fixture', 'email' => 'final-lease-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'owner', 'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'job-final-lease-fixture', 'Disposable final launch lease fixture', 'fixture.example.test',
            (int) getenv('SSH_JOB_FIXTURE_PORT'), (string) getenv('SSH_JOB_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY'))),
            'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
            getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
        );
        app(SshTargetConnectionService::class)->test($target);
        $target->refresh();
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        $requestId = (string) Str::uuid();
        $expired = false;
        $expire = static function () use (&$expired, $requestId): void {
            if ($expired) {
                return;
            }
            foreach (debug_backtrace() as $frame) {
                if (($frame['class'] ?? '') === SshCommandRuntime::class && ($frame['function'] ?? '') === 'run'
                    && str_contains((string) ($frame['args'][2] ?? ''), '--unit=')) {
                    $row = DB::table('ssh_command_jobs')->where('request_id', $requestId)->sole();
                    self::assertSame('launch_unknown', $row->status);
                    self::assertFalse((bool) $row->launch_admitted);
                    self::assertTrue(now()->lt($row->admission_expires_at));
                    DB::table('ssh_command_jobs')->where('id', $row->id)->update(['admission_expires_at' => now()->subSecond()]);
                    $expired = true;

                    return;
                }
            }
        };
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class($expire) implements SshDialAddressPolicy
        {
            public function __construct(private readonly \Closure $expire) {}

            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                ($this->expire)();

                return ['127.0.0.1'];
            }
        });
        $marker = '/home/'.getenv('SSH_JOB_FIXTURE_USER').'/lease-fenced-'.bin2hex(random_bytes(8));
        $result = app(SshJobMcpToolHandlers::class)->start($owner, $target->target_id, hash('sha256', 'final-lease'), $requestId,
            'printf must-not-run > '.escapeshellarg($marker), 60);
        self::assertTrue($expired, json_encode($result));
        self::assertFalse($result['ok'], json_encode($result));
        self::assertSame('dispatch_lease_expired', $result['error']['code']);
        self::assertFalse($result['result']['launch_admitted']);
        self::assertSame('failed', $result['result']['status']);
        $id = $result['result']['job_id'];
        $proof = app(SshCommandRuntime::class)->run($owner, $target,
            'test ! -e '.escapeshellarg($marker)
                .' && test "$(XDG_RUNTIME_DIR=/run/user/$(id -u) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus'
                .' systemctl --user show -p LoadState --value '.escapeshellarg('mgw-'.strtolower($id).'.service').')" = not-found');
        self::assertSame(0, $proof['exit_code'], json_encode($proof));
        DB::table('ssh_command_jobs')->where('id', $id)->update(['expires_at' => now()->subMinute()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());
    }

    public function test_job_longer_than_http_budget_has_bounded_output_durable_exit_and_verified_cancel(): void
    {
        $owner = User::query()->create([
            'name' => 'Job fixture',
            'email' => 'job-fixture-'.bin2hex(random_bytes(5)).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'job-fixture', 'Disposable SSH job', 'fixture.example.test',
            (int) getenv('SSH_JOB_FIXTURE_PORT'), (string) getenv('SSH_JOB_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_HOST_KEY'))),
            'private_key', (string) file_get_contents((string) getenv('SSH_JOB_FIXTURE_PRIVATE_KEY')),
            getenv('SSH_JOB_FIXTURE_PASSPHRASE') ?: null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $client = hash('sha256', 'separate-fixture-client');
        $tools = app(SshJobMcpToolHandlers::class);
        $requestId = (string) Str::uuid();
        // Exercise the actual verified streaming publish, not just a larger
        // input schema. The exact 512 KiB last executable lines are AFTER byte 16384, so
        // truncation/partial upload cannot accidentally pass this test.
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_job_max_script_kib' => 512,
        ]);
        $tail = 'sleep 19; printf "%020000d" 7; printf "err-job" >&2; exit 7';
        $header = 'set -eu'.chr(10);
        $script = $header.'# '.str_repeat('x', 524288 - strlen($header) - 3 - strlen($tail))
            .chr(10).$tail;
        self::assertSame(524288, strlen($script));
        $start = $tools->start($owner, $target->target_id, $client, $requestId, $script, 60);
        self::assertTrue($start['ok'], json_encode($start));
        self::assertSame('running', $start['result']['status']);
        $id = $start['result']['job_id'];

        // Re-resolve a fresh facade after a simulated client disconnect.
        // No process/job handles are held in Gateway PHP memory.
        unset($tools);
        $resumed = app(SshJobMcpToolHandlers::class);
        $status = null;
        // Real CI can finish the systemd unit before a later rate-limited
        // SFTP exit-marker read. Poll with a sensible remote-SSH interval,
        // and require the exact script exit code, not merely a generic
        // systemd failure status with nullable exit evidence.
        for ($n = 0; $n < 40; $n++) {
            $status = $resumed->status($owner, $target->target_id, $client, $id);
            if (($status['result']['status'] ?? '') === 'failed'
                && ($status['result']['exit_code'] ?? null) === 7) {
                break;
            }
            sleep(3);
        }
        self::assertSame('failed', $status['result']['status'] ?? null, json_encode($status));
        self::assertSame(7, $status['result']['exit_code'] ?? null, json_encode($status));

        $a = $resumed->output($owner, $target->target_id, $client, $id, 'stdout', 0, 16384);
        $b = $resumed->output($owner, $target->target_id, $client, $id, 'stdout', 16384, 16384);
        self::assertTrue($a['ok'], json_encode($a));
        self::assertTrue($b['ok'], json_encode($b));
        self::assertSame(16384, $a['result']['length']);
        self::assertSame(3616, $b['result']['length']);
        self::assertTrue($b['result']['end_of_file']);
        // The same exact exit code can be recovered either from the
        // wrapper's durable exit-code file (capture readers were waited)
        // or directly from systemd (no independent capture proof). Only
        // the first route licenses truncated=false for a short spool.
        $terminalReason = DB::table('ssh_command_jobs')->where('id', $id)->value('terminal_reason');
        if ($terminalReason === 'script_exit') {
            self::assertFalse($b['result']['truncated']);
        } else {
            self::assertSame('systemd_exit-code', $terminalReason);
            self::assertNull($b['result']['truncated']);
        }
        self::assertSame(str_pad('7', 20000, '0', STR_PAD_LEFT),
            base64_decode($a['result']['data'], true).base64_decode($b['result']['data'], true));
        $err = $resumed->output($owner, $target->target_id, $client, $id, 'stderr');
        self::assertSame('err-job', base64_decode($err['result']['data'], true));

        $duplicate = $resumed->start($owner, $target->target_id, $client, $requestId, $script, 60);
        self::assertSame($id, $duplicate['result']['job_id']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());

        $cancel = $resumed->start($owner, $target->target_id, $client, (string) Str::uuid(),
            'printf "partial-before-cancel"; sleep 120; printf "unexpected"; exit 0', 180);
        self::assertTrue($cancel['ok'], json_encode($cancel));
        $cancelId = $cancel['result']['job_id'];
        sleep(1);
        $stop = $resumed->cancel($owner, $target->target_id, $client, $cancelId);
        self::assertSame('canceled', $stop['result']['status'] ?? null, json_encode($stop));
        self::assertTrue($stop['result']['complete']);
        // The terminated script emitted a prefix, but systemd may kill the
        // FIFO reader before it flushes even a byte. Either an empty stored
        // spool or a short prefix is valid; neither proves complete capture.
        $partial = $resumed->output($owner, $target->target_id, $client, $cancelId);
        self::assertTrue($partial['ok'], json_encode($partial));
        self::assertTrue($partial['result']['available']);
        $stored = base64_decode($partial['result']['data'], true);
        self::assertIsString($stored);
        self::assertTrue(str_starts_with('partial-before-cancel', $stored));
        self::assertSame(strlen($stored), $partial['result']['size']);
        self::assertLessThan(1048576, $partial['result']['size']);
        self::assertTrue($partial['result']['end_of_file']);
        self::assertNull($partial['result']['truncated']);

        DB::table('ssh_command_jobs')->whereIn('id', [$id, $cancelId])
            ->update(['expires_at' => now()->subMinute()]);
        self::assertSame(2, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, DB::table('ssh_command_jobs')->count());
    }
}
