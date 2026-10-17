<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
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
            $output = $jobs->output($owner, $target->target_id, $client, $id, $stream, 1048570, 16);
            self::assertTrue($output['ok'], json_encode($output));
            self::assertSame(1048576, $output['result']['size']);
            self::assertSame(6, $output['result']['length']);
            self::assertSame(str_repeat("\0", 6), base64_decode($output['result']['data'], true));
            self::assertTrue($output['result']['end_of_file']);
            self::assertTrue($output['result']['truncated']);
        }

        DB::table('ssh_command_jobs')->where('id', $id)->update(['expires_at' => now()->subMinute()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, DB::table('ssh_command_jobs')->where('id', $id)->count());
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
        // input schema. Last executable lines occur AFTER byte 16384, so
        // truncation/partial upload cannot accidentally pass this test.
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_job_max_script_kib' => 32,
        ]);
        $script = str_repeat('# streamed-fixture-padding-'.str_repeat('x', 48).chr(10), 300)
            .'sleep 19; printf "%020000d" 7; printf "err-job" >&2; exit 7';
        self::assertGreaterThan(16384, strlen($script));
        self::assertLessThanOrEqual(32768, strlen($script));
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
