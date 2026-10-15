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
        $script = 'sleep 19; printf "%020000d" 7; printf "err-job" >&2; exit 7';
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
        self::assertSame(str_pad('7', 20000, '0', STR_PAD_LEFT),
            base64_decode($a['result']['data'], true).base64_decode($b['result']['data'], true));
        $err = $resumed->output($owner, $target->target_id, $client, $id, 'stderr');
        self::assertSame('err-job', base64_decode($err['result']['data'], true));

        $duplicate = $resumed->start($owner, $target->target_id, $client, $requestId, $script, 60);
        self::assertSame($id, $duplicate['result']['job_id']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());

        $cancel = $resumed->start($owner, $target->target_id, $client, (string) Str::uuid(),
            'sleep 120; printf "unexpected"; exit 0', 180);
        self::assertTrue($cancel['ok'], json_encode($cancel));
        $cancelId = $cancel['result']['job_id'];
        sleep(1);
        $stop = $resumed->cancel($owner, $target->target_id, $client, $cancelId);
        self::assertSame('canceled', $stop['result']['status'] ?? null, json_encode($stop));
        self::assertTrue($stop['result']['complete']);

        DB::table('ssh_command_jobs')->whereIn('id', [$id, $cancelId])
            ->update(['expires_at' => now()->subMinute()]);
        self::assertSame(2, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, DB::table('ssh_command_jobs')->count());
    }
}
