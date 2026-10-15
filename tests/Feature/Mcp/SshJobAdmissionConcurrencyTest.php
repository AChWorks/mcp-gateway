<?php

namespace Tests\Feature\Mcp;

use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

/**
 * Real independent PHP processes/connections against disposable MariaDB.
 * No real SSH, external request, production Target or remote side effect.
 */
#[Group('database-concurrency')]
final class SshJobAdmissionConcurrencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB is required for independent Job admission locking.');
        }
        $db = (string) DB::connection()->getDatabaseName();
        if (! app()->environment('testing')
            || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', $db) !== 1) {
            throw new RuntimeException('SSH concurrency fixture refuses non-test MariaDB.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
    }

    public function test_two_simultaneous_independent_starts_cannot_both_pass_a_limit_of_one(): void
    {
        $user = User::query()->create([
            'name' => 'SSH Job concurrency',
            'email' => 'ssh-job-concurrency@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner', 'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $hostKey = 'ssh-ed25519 '.base64_encode(
            pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32),
        );
        $target = app(SshTargetRegistration::class)->register(
            'ssh-job-admission-race', 'SSH admission test',
            'fixture.example.test', 22, 'fixture-user', $hostKey,
            'password', 'only-test-credential', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_job_max_active_per_user' => 1,
            'ssh_job_preparing_grace_seconds' => 30,
            'ssh_job_reconcile_grace_seconds' => 60,
        ]);

        $directory = storage_path('framework/testing/ssh-job-admission-'.bin2hex(random_bytes(8)));
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create private process barrier.');
        }
        $workers = [];
        try {
            foreach (['a', 'b'] as $name) {
                $pipes = [];
                $process = proc_open([
                    PHP_BINARY, base_path('tests/Support/ssh_job_concurrent_start.php'),
                    $directory, $name, (string) $user->getKey(),
                ], [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ], $pipes, base_path());
                if (! is_resource($process)) {
                    throw new RuntimeException('Failed to open independent admission worker.');
                }
                $workers[$name] = ['process' => $process, 'pipes' => $pipes];
            }

            $this->waitUntil(static fn (): bool => is_file($directory.'/ready-a') && is_file($directory.'/ready-b'));
            touch($directory.'/go');
            // One worker must be parked *after its successful committed DB
            // insert* but BEFORE any remote side effect. The second must
            // return rate_limited without entering that probe.
            $this->waitUntil(static fn (): bool => is_file($directory.'/probe-a') || is_file($directory.'/probe-b'));
            $winner = is_file($directory.'/probe-a') ? 'a' : 'b';
            $loser = $winner === 'a' ? 'b' : 'a';
            $this->waitUntil(static fn (): bool => is_file($directory.'/result-'.$loser));
            self::assertFileDoesNotExist($directory.'/probe-'.$loser);
            $blocked = json_decode((string) file_get_contents($directory.'/result-'.$loser),
                true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('rate_limited', $blocked['error']['code'] ?? null);
            self::assertSame(1, DB::table('ssh_command_jobs')->count());
            self::assertSame('preparing',
                DB::table('ssh_command_jobs')->value('status'));

            touch($directory.'/release');
            $this->waitUntil(static fn (): bool => is_file($directory.'/result-'.$winner));
            $accepted = json_decode((string) file_get_contents($directory.'/result-'.$winner),
                true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('unsupported', $accepted['result']['status'] ?? null);
            self::assertSame(1, DB::table('ssh_command_jobs')->count());
            self::assertSame('unsupported',
                DB::table('ssh_command_jobs')->value('status'));
            foreach ($workers as &$worker) {
                $stdout = stream_get_contents($worker['pipes'][1]);
                $stderr = stream_get_contents($worker['pipes'][2]);
                fclose($worker['pipes'][1]);
                fclose($worker['pipes'][2]);
                $worker['pipes'] = [];
                $exit = proc_close($worker['process']);
                $worker['process'] = null;
                self::assertSame(0, $exit, trim((string) $stderr).substr((string) $stdout, 0, 120));
            }
            unset($worker);
        } finally {
            touch($directory.'/release');
            touch($directory.'/go');
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

    public function test_older_populated_journal_migrates_on_mariadb_without_rebinding_original_host(): void
    {
        $user = User::query()->create([
            'name' => 'SSH Job migration',
            'email' => 'ssh-job-migration@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner', 'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $hostKey = 'ssh-ed25519 '.base64_encode(
            pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32),
        );
        $target = app(SshTargetRegistration::class)->register(
            'ssh-job-migrate-rc1', 'Old prerelease Journal',
            'original.example.test', 22, 'original-user', $hostKey,
            'password', 'test-only-password', null,
        );
        $config = SshTargetConfig::query()
            ->where('target_record_id', $target->getKey())->firstOrFail();
        $binding = hash('sha256', implode("\0", [
            (string) $target->getKey(), (string) $target->target_id,
            (string) $config->host, (string) $config->port,
            (string) $config->username, (string) $config->auth_method,
            (string) $config->pinned_host_key,
        ]));
        $lifecycle = require database_path('migrations/2026_10_15_020000_add_ssh_job_lifecycle_policy.php');
        $snapshot = require database_path('migrations/2026_10_15_030000_snapshot_ssh_job_admission_policy.php');

        // On a *disposable test database*, first re-create an unpublished
        // RC1-era Job schema, populate a matching and a rebound identity,
        // and migrate both forwards across real MariaDB DDL.
        $snapshot->down();
        $lifecycle->down();
        $oldLease = now()->subMinutes(10)->toDateTimeString();
        $ids = [(string) Str::ulid(), (string) Str::ulid()];
        foreach ($ids as $i => $id) {
            DB::table('ssh_command_jobs')->insert([
                'id' => $id,
                'target_record_id' => $target->getKey(),
                'user_id' => $user->getKey(),
                'client_identity_hash' => hash('sha256', 'rc1-client-'.$i),
                'request_id' => (string) Str::uuid(),
                'script_digest' => hash('sha256', 'rc1-script-'.$i),
                'target_binding_hash' => $i === 0 ? $binding : hash('sha256', 'pre-rotation-binding'),
                'unit_mode' => 'user',
                'status' => 'launch_unknown',
                'runtime_seconds' => 300,
                'expires_at' => now()->addHour(),
                'created_at' => now()->subHour(),
                'updated_at' => now()->subHour(),
            ]);
        }
        $lifecycle->up();
        // Existing RC2 lease can never be reduced by a later policy backfill.
        DB::table('ssh_command_jobs')->where('id', $ids[0])
            ->update(['admission_expires_at' => now()->addDay()]);
        $futureLease = (string) DB::table('ssh_command_jobs')
            ->where('id', $ids[0])->value('admission_expires_at');
        $snapshot->up();

        $matched = DB::table('ssh_command_jobs')->where('id', $ids[0])->first();
        $rebound = DB::table('ssh_command_jobs')->where('id', $ids[1])->first();
        self::assertSame('original.example.test', $matched->original_host);
        self::assertSame('original-user', $matched->original_os_username);
        self::assertNull($rebound->original_host);
        self::assertNull($rebound->original_os_username);
        self::assertSame(3600, (int) $matched->reconcile_grace_seconds);
        self::assertSame(3600, (int) $rebound->reconcile_grace_seconds);
        self::assertNotNull($matched->preparing_expires_at);
        self::assertNotNull($rebound->preparing_expires_at);
        self::assertSame($futureLease, $matched->admission_expires_at);
        self::assertGreaterThan($oldLease, $rebound->admission_expires_at);
        self::assertSame('launch_unknown', $rebound->status);
        self::assertSame('launch_unknown', $matched->status);
    }

    private function waitUntil(callable $ready): void
    {
        $deadline = microtime(true) + 12;
        while (! $ready()) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Timed out waiting for independent SSH admission workers.');
            }
            usleep(10000);
        }
    }
}
