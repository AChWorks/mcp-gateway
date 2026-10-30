<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessBatchWorkflow;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PDO;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Symfony\Component\Process\Process;
use Tests\TestCase;

/** Two real connections prove fresh review checks after waiting on access locks. */
#[Group('database-concurrency')]
final class AccessBatchConcurrencyTest extends TestCase
{
    private User $owner;

    protected function setUp(): void
    {
        parent::setUp();
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB/MySQL is required to prove access batch row-lock fencing.');
        }
        Artisan::call('migrate:fresh', ['--force' => true]);
        $this->owner = User::query()->create([
            'name' => 'Batch fixture Owner', 'email' => 'batch-owner@example.test',
            'password' => 'CorrectHorse!234', 'role' => GatewayRole::Owner->value,
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $this->actingAs($this->owner);
        $this->app['request']->setUserResolver(static fn () => Auth::user());
    }

    public function test_waiting_group_membership_apply_reads_new_ssh_denial_and_rejects_old_review(): void
    {
        $group = TargetGroup::query()->create(['name' => 'Locked group']);
        $user = $this->operator();
        $review = app(AccessBatchWorkflow::class)->review(
            $this->owner, 'group-users', $group->id, 'add', [(string) $user->id],
        );
        self::assertFalse($review['requires_ssh_confirmation']);
        $this->whileWorkerWaits('target_groups', (string) $group->id, [
            'context' => 'group-users', 'subject' => $group->id, 'token' => $review['token'],
        ], static function (PDO $pdo) use ($group): void {
            $insert = $pdo->prepare('INSERT INTO target_group_permission_denials '
                .'(target_group_id, permission, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)');
            $insert->execute([$group->id, 'ssh.command.run']);
        });
        self::assertSame(0, DB::table('target_group_users')->count());
        self::assertSame(0, DB::table('activity_events')->count());
        $fresh = app(AccessBatchWorkflow::class)->review(
            $this->owner, 'group-users', $group->id, 'add', [(string) $user->id],
        );
        self::assertTrue($fresh['requires_ssh_confirmation']);
    }

    public function test_waiting_direct_scope_apply_cannot_erase_or_ignore_new_individual_restriction(): void
    {
        $user = $this->operator();
        $target = Target::query()->create([
            'target_id' => 'batch-concurrency-target', 'display_name' => 'Locked Target',
            'connector_type' => 'wp_ai_bridge', 'connection_state' => 'disconnected',
        ]);
        $review = app(AccessBatchWorkflow::class)->review(
            $this->owner, 'user-targets', (string) $user->id, 'allow', [$target->id],
        );
        $this->whileWorkerWaits('users', (string) $user->id, [
            'context' => 'user-targets', 'subject' => (string) $user->id, 'token' => $review['token'],
        ], static function (PDO $pdo) use ($user, $target): void {
            $insert = $pdo->prepare('INSERT INTO user_target_permission_denials '
                .'(user_id, target_record_id, permission, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)');
            $insert->execute([$user->id, $target->id, 'wordpress.abilities.execute.mutating']);
        });
        self::assertSame(0, DB::table('user_target_access')->count());
        self::assertSame(0, DB::table('activity_events')->count());
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
            'permission' => 'wordpress.abilities.execute.mutating',
        ]);
    }

    public function test_actor_disabled_while_apply_waits_cannot_use_cached_authenticated_authority(): void
    {
        $group = TargetGroup::query()->create(['name' => 'Actor lock group']);
        $target = Target::query()->create([
            'target_id' => 'actor-lock-target', 'display_name' => 'Actor lock Target',
            'connector_type' => 'wp_ai_bridge', 'connection_state' => 'disconnected',
        ]);
        $review = app(AccessBatchWorkflow::class)->review(
            $this->owner, 'group-targets', $group->id, 'add', [$target->id],
        );
        $this->whileWorkerWaits('users', (string) $this->owner->id, [
            'context' => 'group-targets', 'subject' => $group->id, 'token' => $review['token'],
        ], function (PDO $pdo): void {
            $update = $pdo->prepare('UPDATE users SET access_enabled = 0 WHERE id = ?');
            $update->execute([$this->owner->id]);
        }, ['denied' => true]);
        self::assertSame(0, DB::table('target_group_targets')->count());
        self::assertSame(0, DB::table('activity_events')->count());
    }

    /** @param array<string,string> $payload
     * @param  callable(PDO):void  $mutate
     * @param  array<string,mixed>  $expected
     */
    private function whileWorkerWaits(string $table, string $key, array $payload, callable $mutate, array $expected = ['error' => 'batch_review_stale']): void
    {
        $directory = sys_get_temp_dir().'/gateway-access-batch-'.Str::random(16);
        if (! mkdir($directory, 0700)) {
            throw new RuntimeException('Could not create access batch fixture directory.');
        }
        $script = $directory.'/worker.php';
        $entered = $directory.'/entered';
        file_put_contents($script, $this->workerSource());
        $config = DB::connection()->getConfig();
        $environment = [
            'APP_ENV' => 'testing', 'APP_KEY' => (string) config('app.key'), 'APP_BASE_PATH' => base_path(),
            'DB_CONNECTION' => DB::getDefaultConnection(), 'DB_URL' => '',
            'DB_HOST' => (string) ($config['host'] ?? '127.0.0.1'),
            'DB_PORT' => (string) ($config['port'] ?? 3306), 'DB_DATABASE' => (string) $config['database'],
            'DB_USERNAME' => (string) $config['username'], 'DB_PASSWORD' => (string) ($config['password'] ?? ''),
            'DB_SOCKET' => (string) ($config['unix_socket'] ?? ''), 'CACHE_STORE' => 'array', 'SESSION_DRIVER' => 'array',
            'BCRYPT_ROUNDS' => '4',
        ];
        $dsn = ($config['unix_socket'] ?? '') !== ''
            ? 'mysql:unix_socket='.$config['unix_socket'].';dbname='.$config['database'].';charset=utf8mb4'
            : 'mysql:host='.$config['host'].';port='.$config['port'].';dbname='.$config['database'].';charset=utf8mb4';
        $pdo = new PDO($dsn, (string) $config['username'], (string) ($config['password'] ?? ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5,
        ]);
        $worker = new Process(
            [PHP_BINARY, $script, base_path(), $entered, $table], base_path(), $environment,
            json_encode([...$payload, 'actor' => (string) $this->owner->id], JSON_THROW_ON_ERROR), 20,
        );
        $pdo->beginTransaction();
        try {
            $lock = $pdo->prepare('SELECT id FROM '.$table.' WHERE id = ? FOR UPDATE');
            $lock->execute([$key]);
            self::assertSame($key, (string) $lock->fetchColumn());
            $worker->start();
            $deadline = microtime(true) + 10;
            while (! is_file($entered)) {
                if (! $worker->isRunning() || microtime(true) >= $deadline) {
                    throw new RuntimeException('Access worker did not reach its authoritative parent lock.');
                }
                usleep(2000);
            }
            // The marker is emitted immediately before the actual FOR UPDATE
            // statement. This committed change must win over the old preview.
            $mutate($pdo);
            $pdo->commit();
            $worker->wait();
            self::assertSame(0, $worker->getExitCode(), $worker->getErrorOutput());
            self::assertSame($expected, json_decode($worker->getOutput(), true, 16, JSON_THROW_ON_ERROR));
        } finally {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($worker->isRunning()) {
                $worker->stop(0.2);
            }
            foreach ([$script, $entered] as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
            rmdir($directory);
        }
    }

    private function workerSource(): string
    {
        return <<<'PHP'
<?php
require $argv[1].'/vendor/autoload.php';
$app = require $argv[1].'/bootstrap/app.php';
$app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$payload = json_decode(stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
$actor = \App\Models\User::query()->findOrFail($payload['actor']);
\Illuminate\Support\Facades\Auth::guard()->setUser($actor);
$app['request']->setUserResolver(static fn () => \Illuminate\Support\Facades\Auth::user());
\Illuminate\Support\Facades\DB::connection()->beforeExecuting(static function (string $sql) use ($argv): void {
    if (str_contains(strtolower($sql), 'for update') && str_contains($sql, $argv[3])) {
        touch($argv[2]);
    }
});
try {
    $result = $app->make(\App\Application\Access\AccessBatchWorkflow::class)->apply(
        $actor, $payload['context'], $payload['subject'], $payload['token'], true,
    );
    echo json_encode(['applied' => $result['changed_count']], JSON_THROW_ON_ERROR);
} catch (\DomainException $exception) {
    echo json_encode(['error' => $exception->getMessage()], JSON_THROW_ON_ERROR);
} catch (\Illuminate\Auth\Access\AuthorizationException) {
    echo json_encode(['denied' => true], JSON_THROW_ON_ERROR);
} catch (\Throwable $exception) {
    echo json_encode(['unexpected' => get_class($exception)], JSON_THROW_ON_ERROR);
}
PHP;
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'Batch fixture Operator', 'email' => Str::random(12).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => GatewayRole::Operator->value,
            'target_scope_mode' => 'selected', 'access_enabled' => true,
        ]);
    }
}
