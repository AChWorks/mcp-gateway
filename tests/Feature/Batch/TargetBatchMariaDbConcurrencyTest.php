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
use App\Infrastructure\Activity\ActivityAttribution;
use App\Models\User;
use Closure;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

/** Independent PHP workers and real MariaDB row/unique locks, no remote I/O. */
final class RaceTestBatchProvider implements TargetBatchOperationProvider
{
    public static ?string $lateResultBarrier = null;

    public static bool $holdBeforeAdmission = false;

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

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess, Closure $admitRemoteEffect, ActivityAttribution $attribution): array
    {
        if (self::$holdBeforeAdmission) {
            $this->awaitReconciliation();
        }
        if (! $beforeRemoteEffect() || ! $admitRemoteEffect(static function (): void {})) {
            return ['ok' => false, 'status' => 'blocked', 'error_code' => 'authorization_revoked'];
        }
        DB::table('batch_fixture_effects')->insert([
            'target_id' => $target->target_id, 'pid' => getmypid(), 'created_at' => now(),
        ]);
        if (! self::$holdBeforeAdmission) {
            $this->awaitReconciliation();
        }
        // Keep the claim visibly in-flight while the sibling worker enters.
        usleep(30000);

        return ['ok' => true, 'status' => 'completed', 'result' => ['target_id' => $target->target_id]];
    }

    private function awaitReconciliation(): void
    {
        if (self::$lateResultBarrier === null) {
            return;
        }
        touch(self::$lateResultBarrier.'-waiting');
        $deadline = microtime(true) + 12;
        while (! is_file(self::$lateResultBarrier.'-release') && microtime(true) < $deadline) {
            usleep(10000);
        }
        if (! is_file(self::$lateResultBarrier.'-release')) {
            throw new RuntimeException('Attempt fixture synchronization timed out.');
        }
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

    public static function reconciliationCases(): array
    {
        return ['expired before admission' => [true], 'expired after admission' => [false]];
    }

    #[DataProvider('reconciliationCases')]
    public function test_second_process_reconciliation_preserves_dispatch_certainty_and_never_replays(bool $beforeAdmission): void
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

        if ($beforeAdmission) {
            $migration = require database_path('migrations/0001_01_01_000008_record_batch_dispatch_evidence.php');
            $migration->down();
            $before = (array) DB::table('target_batch_items')->where('batch_id', $id)->sole();
            Schema::table('target_batch_items', static function (Blueprint $table): void {
                $table->boolean('effect_admitted')->nullable();
            });
            $migration->up();
            $migration->up();
            $after = DB::table('target_batch_items')->where('batch_id', $id)->sole();
            self::assertNull($after->effect_admitted);
            self::assertNull($after->late_observation_ciphertext);
            $restored = (array) $after;
            unset($restored['effect_admitted'], $restored['late_observation_ciphertext']);
            self::assertSame($before, $restored);
        }

        $barrier = storage_path('framework/testing/batch-late-'.bin2hex(random_bytes(8)));
        RaceTestBatchProvider::$lateResultBarrier = $barrier;
        RaceTestBatchProvider::$holdBeforeAdmission = $beforeAdmission;
        $expected = $beforeAdmission ? 'blocked' : 'outcome_unknown';
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
            while (! is_file($barrier.'-waiting') && microtime(true) < $deadline) {
                usleep(10000);
            }
            self::assertFileExists($barrier.'-waiting');
            DB::table('target_batch_items')->where('batch_id', $id)->update([
                'lease_expires_at' => now()->subMinute(),
            ]);
            // Worker B sees the expired committed claim and reconciles without
            // dispatching a second remote operation.
            self::assertNull(app(TargetBatchWorker::class)->workOnce());
            self::assertSame($expected, DB::table('target_batch_items')->where('batch_id', $id)->value('status'));
            touch($barrier.'-release');
            $status = 0;
            self::assertSame($pid, pcntl_waitpid($pid, $status));
            self::assertSame(0, pcntl_wexitstatus($status), (string) @file_get_contents($barrier.'-error'));
            DB::disconnect();
            DB::reconnect();
            $worked = json_decode((string) file_get_contents($barrier.'-result'), true, 512, JSON_THROW_ON_ERROR);
            self::assertSame($expected, $worked['status']);
            self::assertSame('dispatch_lease_expired', $worked['error_code']);
            self::assertSame($beforeAdmission ? 'failed' : 'outcome_unknown', DB::table('target_batches')->where('id', $id)->value('status'));
            self::assertSame($beforeAdmission ? 0 : 1, DB::table('batch_fixture_effects')->where('target_id', $target->target_id)->count());
            self::assertSame(0, DB::table('activity_events')->where('operation', 'like', 'target-batch%')
                ->where('outcome', 'success')->count());
            $event = DB::table('activity_events')->where('correlation_id', $worked['diagnostic_reference'])->first();
            self::assertNotNull($event);
            self::assertSame($beforeAdmission ? 'failure' : 'unknown', $event->outcome);
            self::assertSame('late_result_ignored', $event->error_code);
            self::assertSame($expected, json_decode((string) $event->diagnostic_context, true)['authoritative_status']);
            $child = DB::table('target_batch_items')->where('batch_id', $id)->sole();
            self::assertSame(! $beforeAdmission, (bool) $child->effect_admitted);
            self::assertNull($child->result_ciphertext);
            $late = json_decode(Crypt::decryptString($child->late_observation_ciphertext), true, 512, JSON_THROW_ON_ERROR);
            self::assertSame($child->dispatch_attempt_id, $late['attempt_id']);
            self::assertSame($beforeAdmission ? 'blocked' : 'completed', $late['observation']['status']);
            if (! $beforeAdmission) {
                self::assertSame($target->target_id, $late['observation']['result']['target_id']);
            }
            self::assertNull(app(TargetBatchWorker::class)->workOnce());
            self::assertSame($beforeAdmission ? 0 : 1, DB::table('batch_fixture_effects')->count());
        } finally {
            touch($barrier.'-release');
            RaceTestBatchProvider::$lateResultBarrier = null;
            RaceTestBatchProvider::$holdBeforeAdmission = false;
            foreach (glob($barrier.'-*') ?: [] as $path) {
                @unlink($path);
            }
        }
    }

    public function test_fair_turn_survives_independent_php_workers_with_single_active_budget(): void
    {
        config()->set('batch.global_active', 1);
        config()->set('batch.user_active', 1);
        $user = User::query()->create([
            'name' => 'MariaDB Fairness', 'email' => 'batch-fairness@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $ids = [];
        for ($i = 0; $i < 6; $i++) {
            $pin = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(80 + $i), 32));
            $target = app(SshTargetRegistration::class)->register(
                'fair-race-'.$i, 'Fair Race '.$i, 'fair-race-'.$i.'.example.test',
                22, 'batchuser', $pin, 'password', 'fixture-secret', null,
            );
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
            $ids[] = $target->target_id;
        }
        $request = Request::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $core = app(TargetBatchCoordinator::class);
        $args = ['command' => 'fixture-read', 'timeout_seconds' => 10];
        $olderIds = array_slice($ids, 0, 5);
        $oldPreview = $core->preview($user, $origin, 'ssh.command.run', $olderIds, $args);
        $older = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run',
            $olderIds, $args, $oldPreview['preview_token'])['batch_id'];
        $newPreview = $core->preview($user, $origin, 'ssh.command.run', [$ids[5]], $args);
        $newer = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run',
            [$ids[5]], $args, $newPreview['preview_token'])['batch_id'];

        // Two independent PHP processes and DB connections must share one
        // durable fairness turn. No real host is contacted by this provider.
        $pid = pcntl_fork();
        if ($pid === -1) {
            throw new RuntimeException('Could not start independent Batch fairness worker.');
        }
        if ($pid === 0) {
            try {
                DB::disconnect();
                DB::reconnect();
                $worked = app(TargetBatchWorker::class)->workOnce();
                DB::disconnect();
                exit(($worked['target_id'] ?? null) === $ids[0] ? 0 : 3);
            } catch (\Throwable) {
                exit(4);
            }
        }
        $status = 0;
        self::assertSame($pid, pcntl_waitpid($pid, $status));
        self::assertTrue(pcntl_wifexited($status));
        self::assertSame(0, pcntl_wexitstatus($status),
            'First independent MariaDB worker did not claim the expected old child.');
        DB::disconnect();
        DB::reconnect();
        self::assertSame($ids[5], app(TargetBatchWorker::class)->workOnce()['target_id']);
        self::assertSame(2, (int) DB::table('operational_settings')->where('id', 1)
            ->value('batch_dispatch_turn'));
        self::assertSame(1, (int) DB::table('target_batches')->where('id', $older)
            ->value('last_dispatch_turn'));
        self::assertSame(2, (int) DB::table('target_batches')->where('id', $newer)
            ->value('last_dispatch_turn'));
        self::assertSame(4, DB::table('target_batch_items')->where('batch_id', $older)
            ->where('status', 'queued')->count());
        self::assertSame('completed', DB::table('target_batches')->where('id', $newer)->value('status'));
        self::assertSame(2, DB::table('batch_fixture_effects')->count());
        self::assertSame(2, DB::table('batch_fixture_effects')->distinct()->count('pid'));
    }

    /** @return iterable<string, array{bool}> */
    public static function prelockParentScenarios(): iterable
    {
        yield 'independent newer parent gets second slot' => [true];
        yield 'one parent can fill both slots after stale snapshot' => [false];
    }

    #[DataProvider('prelockParentScenarios')]
    public function test_two_workers_reselect_parent_after_both_observe_same_prelock_priority(bool $hasIndependentBatch): void
    {
        config()->set('batch.global_active', 2);
        config()->set('batch.user_active', 2);
        $user = User::query()->create([
            'name' => 'MariaDB Prelock Fairness', 'email' => 'batch-prelock@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $ids = [];
        for ($i = 0; $i < 3; $i++) {
            $pin = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(96 + $i), 32));
            $target = app(SshTargetRegistration::class)->register(
                'prelock-host-'.$i, 'Prelock '.$i, 'prelock-'.$i.'.example.test',
                22, 'batchuser', $pin, 'password', 'fixture-secret', null,
            );
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
            $ids[] = $target->target_id;
        }
        $request = Request::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $core = app(TargetBatchCoordinator::class);
        $arguments = ['command' => 'fixture-read', 'timeout_seconds' => 10];
        $olderIds = $hasIndependentBatch ? array_slice($ids, 0, 2) : $ids;
        $oldPreview = $core->preview($user, $origin, 'ssh.command.run', $olderIds,
            $arguments, 'concurrent', false, 2);
        $older = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run',
            $olderIds, $arguments, $oldPreview['preview_token'],
            'concurrent', false, 2)['batch_id'];
        $newer = null;
        if ($hasIndependentBatch) {
            $newPreview = $core->preview($user, $origin, 'ssh.command.run', [$ids[2]], $arguments);
            $newer = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run',
                [$ids[2]], $arguments, $newPreview['preview_token'])['batch_id'];
        }

        $barrier = storage_path('framework/testing/batch-prelock-'.bin2hex(random_bytes(8)));
        $await = static function (string $path): void {
            $deadline = microtime(true) + 12;
            while (! is_file($path) && microtime(true) < $deadline) {
                usleep(10000);
            }
            self::assertFileExists($path, 'The independent worker did not reach its expected barrier.');
        };
        $children = [];
        foreach ([0, 1] as $index) {
            $pid = pcntl_fork();
            if ($pid === -1) {
                throw new RuntimeException('Could not fork pre-lock fairness worker.');
            }
            if ($pid === 0) {
                try {
                    DB::disconnect();
                    DB::reconnect();
                    // Pause EACH process just after the old ordered parent
                    // SELECT, before it can enter the admission transaction.
                    // Both must have selected the older parent at turn zero.
                    DB::listen(static function ($query) use ($barrier, $index): void {
                        static $paused = false;
                        $sql = strtolower((string) $query->sql);
                        if ($paused || ! str_contains($sql, 'target_batches')
                            || ! str_contains($sql, 'last_dispatch_turn')
                            || ! str_contains($sql, 'order by')) {
                            return;
                        }
                        $paused = true;
                        touch($barrier.'-selected-'.$index);
                        $deadline = microtime(true) + 12;
                        while (! is_file($barrier.'-go-'.$index) && microtime(true) < $deadline) {
                            usleep(10000);
                        }
                        if (! is_file($barrier.'-go-'.$index)) {
                            throw new RuntimeException('Pre-lock candidate synchronization timed out.');
                        }
                    });
                    RaceTestBatchProvider::$lateResultBarrier = $barrier.'-effect-'.$index;
                    $result = app(TargetBatchWorker::class)->workOnce();
                    file_put_contents($barrier.'-result-'.$index, json_encode($result, JSON_THROW_ON_ERROR));
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
            $await($barrier.'-selected-0');
            $await($barrier.'-selected-1');
            touch($barrier.'-go-0');
            $await($barrier.'-effect-0-dispatched');
            // Worker 0 is still remote-in-flight. Worker 1 holds a stale
            // A snapshot and must re-evaluate priority without losing a
            // usable second admission slot.
            touch($barrier.'-go-1');
            $await($barrier.'-effect-1-dispatched');
            DB::disconnect();
            DB::reconnect();
            $dispatches = DB::table('target_batch_items')->where('status', 'dispatching')
                ->pluck('target_id_snapshot')->all();
            sort($dispatches);
            $expected = $hasIndependentBatch
                ? [$ids[0], $ids[2]] : [$ids[0], $ids[1]];
            sort($expected);
            self::assertSame($expected, $dispatches,
                'Stale parent snapshots must preserve fair priority and available capacity.');
            self::assertSame(1, DB::table('target_batch_items')->where('batch_id', $older)
                ->where('status', 'queued')->count());
            self::assertSame(2, (int) DB::table('operational_settings')->where('id', 1)
                ->value('batch_dispatch_turn'));
            self::assertSame($hasIndependentBatch ? 1 : 2,
                (int) DB::table('target_batches')->where('id', $older)
                    ->value('last_dispatch_turn'));
            if ($newer !== null) {
                self::assertSame(2, (int) DB::table('target_batches')->where('id', $newer)
                    ->value('last_dispatch_turn'));
            }
            foreach ([0, 1] as $index) {
                touch($barrier.'-effect-'.$index.'-release');
            }
            foreach ($children as $pid) {
                $status = 0;
                self::assertSame($pid, pcntl_waitpid($pid, $status));
                self::assertTrue(pcntl_wifexited($status));
                self::assertSame(0, pcntl_wexitstatus($status), 'Pre-lock worker failed.');
            }
            DB::disconnect();
            DB::reconnect();
            foreach ([0, 1] as $index) {
                self::assertFileDoesNotExist($barrier.'-error-'.$index,
                    (string) @file_get_contents($barrier.'-error-'.$index));
                $result = json_decode((string) file_get_contents($barrier.'-result-'.$index),
                    true, 512, JSON_THROW_ON_ERROR);
                self::assertSame('completed', $result['status']);
            }
            self::assertSame(2, DB::table('batch_fixture_effects')->count());
        } finally {
            // Even on failed assertions/timeouts, release any blocked child
            // and recover all task-owned fixture files/processes.
            foreach ([0, 1] as $index) {
                touch($barrier.'-go-'.$index);
                touch($barrier.'-effect-'.$index.'-release');
            }
            foreach ($children as $pid) {
                $status = 0;
                pcntl_waitpid($pid, $status);
            }
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
