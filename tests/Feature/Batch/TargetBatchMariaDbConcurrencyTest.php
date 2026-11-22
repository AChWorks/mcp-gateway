<?php

namespace Tests\Feature\Batch;

use App\Application\Batch\BatchProviderResolver;
use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchCoordinator;
use App\Application\Batch\TargetBatchOperationProvider;
use App\Application\Batch\TargetBatchWorker;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Models\User;
use Closure;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

/** Independent PHP workers and real MariaDB row/unique locks, no remote I/O. */
final class RaceTestBatchProvider implements TargetBatchOperationProvider
{
    public static ?string $lateResultBarrier = null;

    public function key(): string
    {
        return 'ssh.command.run';
    }

    public function connectorType(): string
    {
        return 'ssh_direct';
    }

    public function permission(): GatewayPermission
    {
        return GatewayPermission::SshCommandRun;
    }

    public function isEffectful(): bool
    {
        return true;
    }

    public function validArguments(array $arguments): bool
    {
        return $arguments === ['command' => 'fixture-read', 'timeout_seconds' => 10];
    }

    public function remoteTimeoutSeconds(array $arguments): int
    {
        return 10;
    }

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess): array
    {
        if (! $beforeRemoteEffect()) {
            return ['ok' => false, 'status' => 'blocked', 'error_code' => 'authorization_revoked'];
        }
        DB::table('batch_fixture_effects')->insert([
            'target_id' => $target->target_id, 'pid' => getmypid(), 'created_at' => now(),
        ]);
        if (self::$lateResultBarrier !== null) {
            // Remote effect happened; the original worker now holds a delayed
            // successful response while an independent process reconciles.
            touch(self::$lateResultBarrier.'-dispatched');
            $deadline = microtime(true) + 12;
            while (! is_file(self::$lateResultBarrier.'-release') && microtime(true) < $deadline) {
                usleep(10000);
            }
            if (! is_file(self::$lateResultBarrier.'-release')) {
                throw new RuntimeException('Late-result fixture synchronization timed out.');
            }
        }
        // Keep the claim visibly in-flight while the sibling worker enters.
        usleep(30000);

        return ['ok' => true, 'status' => 'completed', 'result' => ['target_id' => $target->target_id]];
    }
}

final class RaceTestBatchResolver implements BatchProviderResolver
{
    public function find(string $key): ?TargetBatchOperationProvider
    {
        return $key === 'ssh.command.run' ? new RaceTestBatchProvider : null;
    }
}

#[Group('database-concurrency')]
final class TargetBatchMariaDbConcurrencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true) || ! function_exists('pcntl_fork')) {
            $this->markTestSkipped('Requires real isolated MariaDB and pcntl on CLI.');
        }
        $database = (string) DB::connection()->getDatabaseName();
        if (! app()->environment('testing')
            || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', $database) !== 1) {
            throw new RuntimeException('Batch concurrency fixture refuses non-test databases.');
        }
        Artisan::call('migrate:fresh', ['--force' => true]);
        Schema::create('batch_fixture_effects', static function (Blueprint $table): void {
            $table->string('target_id', 64)->primary();
            $table->unsignedBigInteger('pid');
            $table->timestamp('created_at');
        });
        $this->app->bind(BatchProviderResolver::class, RaceTestBatchResolver::class);
        config()->set('batch.max_parallelism', 6);
        config()->set('batch.global_active', 6);
        config()->set('batch.user_active', 6);
    }

    public function test_original_worker_late_success_after_second_process_reconciliation_keeps_journal_and_activity_unknown(): void
    {
        $user = User::query()->create([
            'name' => 'Late Worker User', 'email' => 'batch-late-worker@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $hostKey = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(70), 32));
        $target = app(SshTargetRegistration::class)->register(
            'late-race-host', 'Late Race', 'late-race.example.test', 22,
            'worker', $hostKey, 'password', 'test-only', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $request = Request::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $core = app(TargetBatchCoordinator::class);
        $args = ['command' => 'fixture-read', 'timeout_seconds' => 10];
        $preview = $core->preview($user, $origin, 'ssh.command.run', [$target->target_id], $args);
        $id = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run',
            [$target->target_id], $args, $preview['preview_token'])['batch_id'];

        $barrier = storage_path('framework/testing/batch-late-'.bin2hex(random_bytes(8)));
        RaceTestBatchProvider::$lateResultBarrier = $barrier;
        $pid = pcntl_fork();
        if ($pid === -1) {
            throw new RuntimeException('Could not fork late-result Worker A.');
        }
        if ($pid === 0) {
            try {
                DB::disconnect();
                DB::reconnect();
                $worked = app(TargetBatchWorker::class)->workOnce();
                file_put_contents($barrier.'-result', json_encode($worked, JSON_THROW_ON_ERROR));
                DB::disconnect();
                exit(0);
            } catch (\Throwable $exception) {
                file_put_contents($barrier.'-error', $exception::class.' '.$exception->getMessage());
                exit(3);
            }
        }
        try {
            DB::disconnect();
            DB::reconnect();
            $deadline = microtime(true) + 12;
            while (! is_file($barrier.'-dispatched') && microtime(true) < $deadline) {
                usleep(10000);
            }
            self::assertFileExists($barrier.'-dispatched');
            DB::table('target_batch_items')->where('batch_id', $id)->update([
                'lease_expires_at' => now()->subMinute(),
            ]);
            // Worker B sees the expired committed claim and reconciles without
            // dispatching a second remote operation.
            self::assertNull(app(TargetBatchWorker::class)->workOnce());
            self::assertSame('outcome_unknown', DB::table('target_batch_items')->where('batch_id', $id)->value('status'));
            touch($barrier.'-release');
            $status = 0;
            self::assertSame($pid, pcntl_waitpid($pid, $status));
            self::assertSame(0, pcntl_wexitstatus($status), (string) @file_get_contents($barrier.'-error'));
            DB::disconnect();
            DB::reconnect();
            $worked = json_decode((string) file_get_contents($barrier.'-result'), true, 512, JSON_THROW_ON_ERROR);
            self::assertSame('outcome_unknown', $worked['status']);
            self::assertSame('dispatch_lease_expired', $worked['error_code']);
            self::assertSame('outcome_unknown', DB::table('target_batches')->where('id', $id)->value('status'));
            self::assertSame(1, DB::table('batch_fixture_effects')->where('target_id', $target->target_id)->count());
            self::assertSame(0, DB::table('activity_events')->where('operation', 'like', 'target-batch%')
                ->where('outcome', 'success')->count());
            $event = DB::table('activity_events')->where('correlation_id', $worked['diagnostic_reference'])->first();
            self::assertNotNull($event);
            self::assertSame('unknown', $event->outcome);
            self::assertSame('late_result_ignored', $event->error_code);
            self::assertSame('outcome_unknown', json_decode((string) $event->diagnostic_context, true)['authoritative_status']);
            self::assertNull(app(TargetBatchWorker::class)->workOnce());
            self::assertSame(1, DB::table('batch_fixture_effects')->count());
        } finally {
            touch($barrier.'-release');
            RaceTestBatchProvider::$lateResultBarrier = null;
            foreach (glob($barrier.'-*') ?: [] as $path) {
                @unlink($path);
            }
        }
    }

    public function test_two_independent_workers_never_claim_or_dispatch_same_target_twice(): void
    {
        $user = User::query()->create([
            'name' => 'MariaDB Race', 'email' => 'batch-concurrency@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $ids = [];
        for ($i = 0; $i < 12; $i++) {
            $hostKey = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(50 + $i), 32));
            $target = app(SshTargetRegistration::class)->register(
                'race-host-'.$i, 'Race Host '.$i, 'race-'.$i.'.example.test',
                22, 'batchuser', $hostKey, 'password', 'fixture-secret', null,
            );
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
            $ids[] = $target->target_id;
        }
        $request = Request::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $core = app(TargetBatchCoordinator::class);
        $arguments = ['command' => 'fixture-read', 'timeout_seconds' => 10];
        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids, $arguments,
            'concurrent', false, 6);
        self::assertSame(12, $preview['eligible_count']);
        $id = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run',
            $ids, $arguments, $preview['preview_token'], 'concurrent', false, 6)['batch_id'];

        $children = [];
        $barrier = storage_path('framework/testing/batch-race-'.bin2hex(random_bytes(8)));
        foreach ([0, 1] as $index) {
            $pid = pcntl_fork();
            if ($pid === -1) {
                throw new RuntimeException('Could not start independent Batch worker.');
            }
            if ($pid === 0) {
                try {
                    DB::disconnect();
                    DB::reconnect();
                    touch($barrier.'-ready-'.$index);
                    $deadline = microtime(true) + 15;
                    while (! is_file($barrier.'-go') && microtime(true) < $deadline) {
                        usleep(20000);
                    }
                    if (! is_file($barrier.'-go')) {
                        exit(2);
                    }
                    $worker = app(TargetBatchWorker::class);
                    for ($attempt = 0; $attempt < 80; $attempt++) {
                        $worker->workOnce();
                        $state = DB::table('target_batches')->where('id', $id)->value('finished_at');
                        if ($state !== null) {
                            break;
                        }
                        usleep(20000);
                    }
                    DB::disconnect();
                    exit(0);
                } catch (\Throwable $exception) {
                    file_put_contents($barrier.'-error-'.$index, $exception::class.' '.$exception->getMessage());
                    exit(3);
                }
            }
            $children[] = $pid;
        }
        try {
            $deadline = microtime(true) + 15;
            while ((! is_file($barrier.'-ready-0') || ! is_file($barrier.'-ready-1'))
                && microtime(true) < $deadline) {
                usleep(20000);
            }
            self::assertFileExists($barrier.'-ready-0');
            self::assertFileExists($barrier.'-ready-1');
            touch($barrier.'-go');
            foreach ($children as $pid) {
                $status = 0;
                $wait = pcntl_waitpid($pid, $status);
                self::assertSame($pid, $wait);
                self::assertTrue(pcntl_wifexited($status));
                self::assertSame(0, pcntl_wexitstatus($status), (string) @file_get_contents($barrier.'-error-0').' '.(string) @file_get_contents($barrier.'-error-1'));
            }
            DB::disconnect();
            DB::reconnect();
            $result = $core->status($user, $origin, $id);
            self::assertSame('completed', $result['status']);
            self::assertSame(12, $result['counts']['completed']);
            self::assertSame(12, DB::table('batch_fixture_effects')->count());
            self::assertSame(2, DB::table('batch_fixture_effects')->distinct()->count('pid'));
            self::assertSame(12, DB::table('target_batch_items')
                ->where('batch_id', $id)->whereNotNull('dispatch_attempt_id')->count());
        } finally {
            foreach (glob($barrier.'-*') ?: [] as $path) {
                @unlink($path);
            }
        }
    }
}
