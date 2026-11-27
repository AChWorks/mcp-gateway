<?php

namespace Tests\Feature\Targets;

use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Tests\TestCase;

/** Actual OpenSSH fixture, loopback-only policy explicitly injected in CI. */
final class SshCommandFixtureTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        if (getenv('SSH_FIXTURE_ENABLED') !== '1') {
            $this->markTestSkipped('Disposable OpenSSH fixture is not configured.');
        }
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return ['127.0.0.1'];
            }
        });
    }

    public function test_password_command_reports_separate_stdout_stderr_exit_and_verified_peer(): void
    {
        $target = $this->target('password');
        $command = "printf 'normal-out'; printf 'normal-err' >&2; exit 7";
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id, $command);
        self::assertTrue($result['ok'], json_encode($result));
        $data = $result['result'];
        self::assertSame('completed', $data['status']);
        self::assertSame('127.0.0.1', $data['connected_ip']);
        self::assertSame('normal-out', $data['stdout']);
        self::assertSame('normal-err', $data['stderr']);
        self::assertSame('utf-8', $data['stdout_encoding']);
        self::assertSame(7, $data['exit_code']);
        self::assertTrue($data['complete']);
        self::assertFalse($data['truncated']);
        self::assertFalse($data['continuation_available']);
        self::assertStringNotContainsString($command, json_encode(
            DB::table('activity_events')->where('operation', 'ssh-command-run')->get(), JSON_THROW_ON_ERROR,
        ));
    }

    public function test_encrypted_private_key_command_and_binary_stdout_are_preserved(): void
    {
        $target = $this->target('private_key');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id, "printf '\\377\\000'");
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('base64', $result['result']['stdout_encoding']);
        self::assertSame('/wA=', $result['result']['stdout']);
        self::assertSame(2, $result['result']['stdout_bytes']);
        self::assertSame(0, $result['result']['exit_code']);
    }

    public function test_owner_512_kib_stdout_and_stderr_windows_preserve_real_remote_exit(): void
    {
        $target = $this->target('password');
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_command_stdout_kib' => 512,
            'ssh_command_stderr_kib' => 512,
        ]);
        $this->app->forgetInstance(OperationalSettings::class);
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id,
            "head -c 524289 /dev/zero | tr '\\000' x; head -c 524288 /dev/zero | tr '\\000' e >&2; exit 7");
        self::assertTrue($result['ok'], $result['error']['code'] ?? '');
        $data = $result['result'];
        self::assertSame('completed', $data['status']);
        self::assertSame(str_repeat('x', 524288), $data['stdout']);
        self::assertSame(str_repeat('e', 524288), $data['stderr']);
        self::assertSame(524289, $data['stdout_total_bytes']);
        self::assertSame(524288, $data['stderr_total_bytes']);
        self::assertTrue($data['stdout_truncated']);
        self::assertFalse($data['stderr_truncated']);
        self::assertSame(7, $data['exit_code']);
    }

    public function test_output_flood_drains_safely_and_retains_proven_remote_exit(): void
    {
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id,
            "head -c 32768 /dev/zero | tr '\\000' x");
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('completed', $result['result']['status']);
        self::assertSame(16384, $result['result']['stdout_bytes']);
        self::assertSame(32768, $result['result']['stdout_total_bytes']);
        self::assertTrue($result['result']['stdout_truncated']);
        self::assertFalse($result['result']['stderr_truncated']);
        self::assertTrue($result['result']['truncated']);
        self::assertTrue($result['result']['complete']);
        self::assertSame(0, $result['result']['exit_code']);
        self::assertFalse($result['result']['continuation_available']);
    }

    public function test_stderr_flood_is_bounded_independently_from_stdout(): void
    {
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id,
            "head -c 16384 /dev/zero | tr '\\000' e >&2");
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame(8192, $result['result']['stderr_bytes']);
        self::assertSame(16384, $result['result']['stderr_total_bytes']);
        self::assertTrue($result['result']['stderr_truncated']);
        self::assertFalse($result['result']['stdout_truncated']);
        self::assertTrue($result['result']['truncated']);
        self::assertSame(0, $result['result']['exit_code']);
    }

    // PHP memory_get_peak_usage(true) is the high-water mark for the ENTIRE
    // PHPUnit process, not the SSH operation. An earlier unrelated test can
    // permanently consume the 128-MiB budget before this fixture starts.
    // Isolate only this resource assertion with a fresh PHP process, retaining
    // the exact 128-MiB bound and all real SSH stream/exit/byte assertions.
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function test_multi_megabyte_outputs_are_drained_without_stderr_heap_growth(): void
    {
        $baselineCurrent = memory_get_usage(true);
        $baselinePeak = memory_get_peak_usage(true);
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id,
            "head -c 2097152 /dev/zero | tr '\\000' s; head -c 2097152 /dev/zero | tr '\\000' e >&2; exit 7");
        self::assertTrue($result['ok'], json_encode($result));
        $data = $result['result'];
        self::assertSame('completed', $data['status']);
        self::assertSame(7, $data['exit_code']);
        self::assertSame(2097152, $data['stdout_total_bytes']);
        self::assertSame(2097152, $data['stderr_total_bytes']);
        self::assertSame(16384, $data['stdout_bytes']);
        self::assertSame(8192, $data['stderr_bytes']);
        self::assertTrue($data['stdout_truncated']);
        self::assertTrue($data['stderr_truncated']);
        self::assertLessThan(128 * 1024 * 1024, memory_get_peak_usage(true), sprintf(
            'Isolated SSH stream peak memory in bytes: before_current=%d, before_peak=%d, after_current=%d, after_peak=%d.',
            $baselineCurrent, $baselinePeak, memory_get_usage(true), memory_get_peak_usage(true),
        ));
    }

    public function test_timeout_is_unknown_and_command_is_not_retried(): void
    {
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id, 'sleep 3', 1);
        self::assertFalse($result['ok']);
        self::assertSame('outcome_unknown', $result['error']['code']);
        self::assertFalse($result['result']['complete']);
        self::assertNull($result['result']['exit_code']);
    }

    public function test_continuous_stream_obeys_wall_clock_deadline_and_does_not_retry(): void
    {
        $target = $this->target('password');
        $started = hrtime(true);
        // A saturated output stream supplies already-ready packets, unlike
        // a paced loop whose socket blocking would consume vendor timeout.
        // Cap the remote generator at 5 seconds so the old buggy behavior
        // fails decisively rather than hanging the disposable fixture.
        $result = app(SshCommandMcpToolHandlers::class)->run(
            $this->owner(), $target->target_id, 'timeout 5 yes tick; exit 7', 1,
        );
        $elapsedSeconds = (hrtime(true) - $started) / 1_000_000_000;

        self::assertFalse($result['ok'], json_encode($result));
        self::assertSame('outcome_unknown', $result['error']['code']);
        self::assertSame('outcome_unknown', $result['result']['status']);
        self::assertFalse($result['result']['complete']);
        self::assertNull($result['result']['exit_code']);
        self::assertGreaterThan(16384, $result['result']['stdout_total_bytes']);
        self::assertTrue($result['result']['stdout_truncated']);
        self::assertLessThan(4.5, $elapsedSeconds, 'Continuous output must not restart the actual deadline.');
        self::assertSame(1, DB::table('activity_events')->where('operation', 'ssh-command-run')->count());
    }

    public function test_disposable_real_ssh_command_runs_longer_than_previous_30_second_ceiling(): void
    {
        $target = $this->target('password');
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_command_timeout_seconds' => 45,
        ]);
        $result = app(SshCommandMcpToolHandlers::class)->run(
            $this->owner(), $target->target_id, 'sleep 35; printf "after35"; exit 7', 45,
        );
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('completed', $result['result']['status']);
        self::assertSame('after35', $result['result']['stdout']);
        self::assertSame(7, $result['result']['exit_code']);
        self::assertTrue($result['result']['complete']);
    }

    public function test_opt_in_disposable_extended_timeout_acceptance_over_90_or_near_360_seconds(): void
    {
        $seconds = (int) getenv('SSH_COMMAND_EXTENDED_FIXTURE_SECONDS');
        if (! in_array($seconds, [95, 350], true)) {
            $this->markTestSkipped('Set SSH_COMMAND_EXTENDED_FIXTURE_SECONDS=95 or 350 on disposable OpenSSH fixture.');
        }

        $target = $this->target('password');
        $selectedTimeout = $seconds === 350 ? 360 : 120;
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_command_timeout_seconds' => $selectedTimeout,
        ]);
        $result = app(SshCommandMcpToolHandlers::class)->run(
            $this->owner(), $target->target_id, 'sleep '.$seconds.'; printf "long-ok"', $selectedTimeout,
        );
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('completed', $result['result']['status']);
        self::assertSame('long-ok', $result['result']['stdout']);
        self::assertSame(0, $result['result']['exit_code']);
    }

    public function test_staged_512_kib_script_uses_exact_bytes_and_native_output_without_systemd(): void
    {
        $target = $this->target('password');
        $owner = $this->owner();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_command_max_kib' => 512, 'ssh_command_timeout_seconds' => 30,
        ]);
        $this->app->forgetInstance(OperationalSettings::class);
        $tail = "\nprintf 'staged-tail'; printf 'staged-error' >&2; exit 7";
        $script = '# '.str_repeat('x', 524288 - 2 - strlen($tail)).$tail;
        $result = app(SshCommandMcpToolHandlers::class)->runScript($owner, $target->target_id, $script, '/bin/sh', 30);
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame(524288, $result['result']['script_bytes']);
        self::assertTrue($result['result']['script_staging_verified']);
        self::assertTrue($result['result']['script_launch_attempted']);
        self::assertSame('staged-tail', $result['result']['stdout']);
        self::assertSame('staged-error', $result['result']['stderr']);
        self::assertSame(7, $result['result']['exit_code']);
        self::assertTrue($result['result']['temporary_cleanup_confirmed'], json_encode($result));
        self::assertArrayNotHasKey('script_staging_path', $result['result']);
        self::assertSame(0, DB::table('ssh_command_jobs')->count());
        self::assertSame(1, DB::table('activity_events')->where('operation', 'ssh-script-run')->count());
        self::assertStringNotContainsString('staged-tail', json_encode(DB::table('activity_events')->where('operation', 'ssh-script-run')->get(), JSON_THROW_ON_ERROR));
    }

    public function test_command_only_host_keeps_native_exec_and_refuses_script_before_launch(): void
    {
        $target = $this->target('password', (int) $this->env('SSH_FIXTURE_PORT_NO_SFTP'));
        $owner = $this->owner();
        $handler = app(SshCommandMcpToolHandlers::class);
        $ordinary = $handler->run($owner, $target->target_id, 'printf native-ok');
        self::assertTrue($ordinary['ok'], json_encode($ordinary));
        self::assertSame('native-ok', $ordinary['result']['stdout']);
        $staged = $handler->runScript($owner, $target->target_id, 'printf should-not-run', '/bin/sh');
        self::assertFalse($staged['ok'], json_encode($staged));
        self::assertSame('failed', $staged['result']['status']);
        self::assertSame('upload', $staged['result']['script_stage']);
        self::assertFalse($staged['result']['script_launch_attempted']);
        self::assertFalse($staged['result']['script_staging_verified']);
        self::assertTrue($staged['result']['temporary_cleanup_confirmed'], json_encode($staged));
        self::assertSame('native-ok', $handler->run($owner, $target->target_id, 'printf native-ok')['result']['stdout']);
    }

    public function test_staged_control_failures_are_available_through_correlated_diagnostics(): void
    {
        $target = $this->target('password');
        $owner = $this->owner();
        $handler = app(SshCommandMcpToolHandlers::class);
        $diagnostics = app(OperationDiagnosticsMcpToolHandlers::class);
        $missing = $handler->runScript($owner, $target->target_id, 'printf not-executed', '/nonexistent-mcp-fixture-interpreter');
        self::assertFalse($missing['ok']);
        self::assertFalse($missing['result']['script_launch_attempted']);
        $event = $diagnostics->read($owner, $missing['error']['diagnostic_reference'])['events'][0]['diagnostics'];
        self::assertSame('interpreter_unavailable', $event['script_control_failure']);
        self::assertIsInt($event['remote_exit_code']);

        $script = 'touch "$(dirname "$0")/extra"; printf "private-fixture-stdout"; printf "private-fixture-stderr" >&2; exit 7';
        $path = null;
        try {
            $completed = $handler->runScript($owner, $target->target_id, $script, '/bin/sh');
            self::assertTrue($completed['ok'], json_encode($completed));
            $result = $completed['result'];
            $path = $result['script_staging_path'] ?? null;
            self::assertSame('completed', $result['status']);
            self::assertSame(7, $result['exit_code']);
            self::assertSame('private-fixture-stdout', $result['stdout']);
            self::assertSame('private-fixture-stderr', $result['stderr']);
            self::assertFalse($result['temporary_cleanup_confirmed']);
            self::assertIsString($path);
            $activity = $diagnostics->read($owner, $completed['diagnostic_reference'])['events'][0];
            self::assertSame('success', $activity['outcome']);
            self::assertSame('script_cleanup_unconfirmed', $activity['error_code']);
            $event = $activity['diagnostics'];
            self::assertSame($path, $event['script_staging_path']);
            $cleanup = $event['script_cleanup_diagnostics'];
            self::assertSame('directory_remove_failed', $cleanup['script_control_failure']);
            self::assertIsInt($cleanup['remote_exit_code']);
            self::assertStringContainsString('Directory not empty', $cleanup['source_error_message']);
            self::assertStringNotContainsString('private-fixture-stdout', json_encode($event, JSON_THROW_ON_ERROR));
            self::assertStringNotContainsString('private-fixture-stderr', json_encode($event, JSON_THROW_ON_ERROR));
        } finally {
            if (is_string($path) && preg_match('~\A/var/tmp/\.mcp-gateway-script-[a-f0-9]{32}\z~D', $path) === 1) {
                $cleanup = $handler->run($owner, $target->target_id, 'rm -f -- '.$path.'/extra && rmdir -- '.$path);
                self::assertSame(0, $cleanup['result']['exit_code'] ?? null, 'Dispose only this test-owned residue.');
            }
        }
    }

    public function test_staged_launch_and_cleanup_stop_when_actual_target_is_paused_after_upload(): void
    {
        $target = $this->target('password');
        $owner = $this->owner();
        $policy = new class((string) $target->getKey()) implements SshDialAddressPolicy
        {
            public int $dials = 0;

            public function __construct(private readonly string $targetId) {}

            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                if (++$this->dials === 3) {
                    // First dial prepares, second verifies SFTP upload,
                    // third reaches the launch connection. Revoke the real
                    // current Target authority before its credential login.
                    Target::query()->whereKey($this->targetId)->update(['operations_paused' => true]);
                }

                return ['127.0.0.1'];
            }
        };
        $this->app->instance(SshDialAddressPolicy::class, $policy);
        $handler = app(SshCommandMcpToolHandlers::class);
        $path = null;
        try {
            $result = $handler->runScript($owner, $target->target_id, 'printf must-not-run', '/bin/sh');
            self::assertFalse($result['ok'], json_encode($result));
            $data = $result['result'];
            $path = $data['script_staging_path'] ?? null;
            self::assertSame('target_paused', $result['error']['code']);
            self::assertTrue($data['script_staging_verified']);
            self::assertFalse($data['script_launch_attempted']);
            self::assertFalse($data['temporary_cleanup_confirmed']);
            self::assertSame('target_paused', $data['script_cleanup_error_code']);
            self::assertIsString($path);
            self::assertSame(4, $policy->dials);
            self::assertTrue((bool) $target->fresh()->operations_paused);
        } finally {
            $target->forceFill(['operations_paused' => false])->save();
            if (is_string($path) && preg_match('~\A/var/tmp/\.mcp-gateway-script-[a-f0-9]{32}\z~D', $path) === 1) {
                // The test owns this exact artifact, and the original
                // Target authority is restored solely for fixture cleanup.
                $cleanup = $handler->run($owner, $target->target_id,
                    'test -f '.$path.'/script && test -f '.$path.'/identity && rm -f -- '.$path.'/script '.$path.'/identity && rmdir -- '.$path);
                self::assertSame(0, $cleanup['result']['exit_code'] ?? null);
            }
        }
    }

    private function target(string $method, ?int $port = null): Target
    {
        $secret = $method === 'password'
            ? $this->env('SSH_FIXTURE_PASSWORD')
            : (string) file_get_contents($this->env('SSH_FIXTURE_RSA_LOGIN_KEY'));

        $target = app(SshTargetRegistration::class)->register(
            'ssh-command-'.str_replace('_', '-', $method), 'Command fixture', 'fixture.example.test',
            $port ?? (int) $this->env('SSH_FIXTURE_PORT_MODERN'), $this->env('SSH_FIXTURE_USER'),
            trim((string) file_get_contents($this->env('SSH_FIXTURE_ED25519_HOST_PUB'))),
            $method, $secret, $method === 'password' ? null : $this->env('SSH_FIXTURE_KEY_PASSPHRASE'),
        );
        // These transport fixtures exercise the command/SFTP data plane.
        // A verified connection is a required test precondition; the real
        // host-key-pinned verify workflow is exercised separately and in
        // installed-mixed E2E. Never relax the production runtime gate.
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target;
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'SSH fixture owner',
            'email' => 'fixture-'.uniqid('', true).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }

    private function env(string $name): string
    {
        $value = getenv($name);
        self::assertIsString($value, 'Missing SSH fixture variable '.$name);
        self::assertNotSame('', $value);

        return $value;
    }
}
