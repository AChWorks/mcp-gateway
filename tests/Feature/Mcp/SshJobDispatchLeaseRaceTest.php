<?php

namespace Tests\Feature\Mcp;

use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

/** Independent MariaDB process/transaction race at an old lease expiry. */
#[Group('database-concurrency')]
final class SshJobDispatchLeaseRaceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB is required for an independent-process lease race.');
        }
        $db = (string) DB::connection()->getDatabaseName();
        if (! app()->environment('testing')
            || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', $db) !== 1) {
            throw new RuntimeException('Dispatch race fixture refuses non-test MariaDB.');
        }
        Artisan::call('migrate:fresh', ['--force' => true]);
    }

    public function test_renewal_and_new_admission_cannot_both_own_the_one_slot_at_expiry(): void
    {
        $user = User::query()->create([
            'name' => 'Dispatch renewal expiry race',
            'email' => 'dispatch-renewal@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner', 'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $hostKey = 'ssh-ed25519 '.base64_encode(
            pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32),
        );
        $target = app(SshTargetRegistration::class)->register(
            'ssh-lease-expiry-race', 'Dispatch lease boundary',
            'fixture.example.test', 22, 'fixture-user', $hostKey,
            'password', 'only-test-credential', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_job_max_active_per_user' => 1,
            'ssh_job_preparing_grace_seconds' => 30,
            'ssh_job_reconcile_grace_seconds' => 60,
        ]);

        $jobId = (string) Str::ulid();
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
        $expires = now()->addSeconds(4)->toDateTimeString();
        DB::table('ssh_command_jobs')->insert([
            'id' => $jobId,
            'target_record_id' => $target->getKey(), 'user_id' => $user->getKey(),
            'original_user_id' => $user->getKey(),
            'client_identity_hash' => hash('sha256', 'original-dispatch-client'),
            'request_id' => (string) Str::uuid(),
            'script_digest' => hash('sha256', 'original-script'),
            'target_binding_hash' => SshTargetBinding::hash($target, $config),
            'status' => 'launch_unknown', 'unit_mode' => 'user',
            'runtime_seconds' => 16, 'reconcile_grace_seconds' => 60,
            'admission_expires_at' => $expires,
            'expires_at' => now()->addHour(),
            'created_at' => now(), 'updated_at' => now(),
        ]);

        $directory = storage_path('framework/testing/ssh-dispatch-race-'.bin2hex(random_bytes(8)));
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Failed to create private race barriers.');
        }
        $workers = [];
        try {
            foreach (['renew', 'start'] as $name) {
                $pipes = [];
                $process = proc_open([
                    PHP_BINARY, base_path('tests/Support/ssh_job_dispatch_race.php'),
                    $directory, $name, (string) $user->getKey(),
                    $target->target_id, $jobId, $expires,
                ], [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ], $pipes, base_path());
                if (! is_resource($process)) {
                    throw new RuntimeException('Failed to spawn dispatch worker.');
                }
                $workers[$name] = ['process' => $process, 'pipes' => $pipes];
            }
            $this->waitUntil(static fn (): bool => is_file($directory.'/ready-renew')
                && is_file($directory.'/ready-start'));
            // Worker renew holds both the principal and Job locks while
            // the original expiry boundary elapses (DB query event barrier).
            $this->waitUntil(static fn (): bool => is_file($directory.'/renew-job-locked'));
            $expiry = Carbon::parse($expires);
            $deadline = microtime(true) + 7;
            while (now()->lessThanOrEqualTo($expiry)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Original lease expiry was never observed.');
                }
                usleep(10000);
            }

            // New admission starts from a genuinely independent connection.
            // A currently-correct renew holds the User row and therefore
            // serializes B; an old Job-only renew did not hold this lock.
            touch($directory.'/go-start');
            $this->waitUntil(static fn (): bool => is_file($directory.'/start-entered'));
            // B has a bounded scheduling opportunity at the old expiry.
            // The ordering itself is controlled by the real DB locks above.
            usleep(250000);
            touch($directory.'/release-renew');
            $this->waitUntil(static fn (): bool => is_file($directory.'/result-renew')
                && is_file($directory.'/result-start'));

            $renew = json_decode((string) file_get_contents($directory.'/result-renew'),
                true, flags: JSON_THROW_ON_ERROR);
            $fresh = json_decode((string) file_get_contents($directory.'/result-start'),
                true, flags: JSON_THROW_ON_ERROR);
            self::assertTrue($renew['renewed'] ?? false);
            self::assertSame('rate_limited', $fresh['error']['code'] ?? null);
            self::assertSame(1, DB::table('ssh_command_jobs')->count());
            foreach ($workers as &$worker) {
                $stderr = stream_get_contents($worker['pipes'][2]);
                fclose($worker['pipes'][1]);
                fclose($worker['pipes'][2]);
                $worker['pipes'] = [];
                $exit = proc_close($worker['process']);
                $worker['process'] = null;
                self::assertSame(0, $exit, (string) $stderr);
            }
            unset($worker);
        } finally {
            touch($directory.'/go-start');
            touch($directory.'/release-renew');
            foreach ($workers as $worker) {
                if (is_resource($worker['process'])) {
                    proc_terminate($worker['process']);
                    proc_close($worker['process']);
                }
                foreach ($worker['pipes'] as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
            }
            foreach (glob($directory.'/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($directory);
        }
    }

    private function waitUntil(callable $ready): void
    {
        $deadline = microtime(true) + 12;
        while (! $ready()) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Timed out waiting for independent dispatch workers.');
            }
            usleep(10000);
        }
    }
}
