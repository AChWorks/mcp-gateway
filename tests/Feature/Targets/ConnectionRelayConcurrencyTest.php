<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\ConnectionRelayAdministration;
use App\Application\Targets\ConnectionRelayTargetBinding;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostReadiness;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PDO;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Symfony\Component\Process\Process;
use Tests\TestCase;

/**
 * Independent MariaDB transactions prove route-binding serialization with
 * Relay disable. No sockets, host attestation, real target or OS changes.
 */
#[Group('database-concurrency')]
final class ConnectionRelayConcurrencyTest extends TestCase
{
    private ConnectionRelay $relay;

    private Target $target;

    protected function setUp(): void
    {
        parent::setUp();
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('Separate MariaDB transactions required.');
        }
        $database = (string) DB::connection()->getDatabaseName();
        if (! app()->environment('testing')
            || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', $database) !== 1) {
            throw new RuntimeException('Relay concurrency test refuses a non-test database.');
        }
        Artisan::call('migrate:fresh', ['--force' => true]);
        $this->app->instance(ConnectionRelayHostReadiness::class, new class extends ConnectionRelayHostReadiness
        {
            public function ready(ConnectionRelay $relay): bool
            {
                return true;
            }
        });
        $this->relay = ConnectionRelay::query()->create([
            'relay_id' => 'race-iran',
            'display_name' => 'Race fixture',
            'control_host' => '198.51.100.33',
            'control_port' => 22,
            'control_user' => 'test-control',
            'control_host_key' => 'ssh-ed25519 fixture-only',
            'local_socks_port' => 46123,
        ]);
        DB::table('connection_relays')->where('id', $this->relay->getKey())->update(['enabled' => true]);
        $this->relay->refresh();
        $this->target = Target::query()->create([
            'target_id' => 'relay-race-target', 'display_name' => 'Concurrent route',
            'connector_type' => 'wp_ai_bridge', 'connection_state' => 'disconnected',
        ]);
    }

    protected function tearDown(): void
    {
        try {
            if (isset($this->target) && Schema::hasTable('targets')) {
                DB::table('targets')->where('id', $this->target->getKey())->delete();
            }
        } finally {
            parent::tearDown();
        }
    }

    public function test_disable_wins_while_new_binding_waits_and_no_disabled_relay_is_attached(): void
    {
        $this->withBlockedBinding(false);
        $target = $this->target->fresh();
        self::assertNull($target->getAttribute('relay_record_id'));
        self::assertSame(0, $target->relay_binding_revision);
        self::assertFalse($this->relay->fresh()->enabled);
        self::assertSame(2, $this->relay->fresh()->configuration_revision);
    }

    public function test_binding_before_disable_is_fenced_and_old_epoch_cannot_dispatch(): void
    {
        $this->withBlockedBinding(true);
        $target = $this->target->fresh();
        self::assertSame((string) $this->relay->getKey(), (string) $target->getAttribute('relay_record_id'));
        self::assertSame(1, $target->relay_binding_revision);
        self::assertTrue(app(ConnectionRelayAdministration::class)->disable($this->relay, 1));
        $target = $this->target->fresh();
        self::assertSame('error', $target->connection_state->value);
        self::assertSame('relay_disabled', $target->last_error_code);
        self::assertSame(2, $target->relay_binding_revision);
    }

    private function withBlockedBinding(bool $allowBinding): void
    {
        $directory = sys_get_temp_dir().'/gateway-relay-race-'.bin2hex(random_bytes(8));
        if (! mkdir($directory, 0700)) {
            throw new RuntimeException('Cannot create disposable Relay race directory.');
        }
        $marker = $directory.'/ready';
        $config = DB::connection()->getConfig();
        $env = [
            'APP_ENV' => 'testing', 'APP_KEY' => (string) config('app.key'),
            'DB_CONNECTION' => DB::getDefaultConnection(), 'DB_URL' => '',
            'DB_HOST' => (string) ($config['host'] ?? '127.0.0.1'),
            'DB_PORT' => (string) ($config['port'] ?? 3306),
            'DB_DATABASE' => (string) $config['database'],
            'DB_USERNAME' => (string) $config['username'],
            'DB_PASSWORD' => (string) ($config['password'] ?? ''),
            'DB_SOCKET' => (string) ($config['unix_socket'] ?? ''),
            'CACHE_STORE' => 'array', 'SESSION_DRIVER' => 'array',
            'BCRYPT_ROUNDS' => '4',
        ];
        $dsn = ($config['unix_socket'] ?? '') !== ''
            ? 'mysql:unix_socket='.$config['unix_socket'].';dbname='.$config['database'].';charset=utf8mb4'
            : 'mysql:host='.$config['host'].';port='.$config['port'].';dbname='.$config['database'].';charset=utf8mb4';
        $pdo = new PDO($dsn, (string) $config['username'], (string) ($config['password'] ?? ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5,
        ]);
        $revision = app(ConnectionRelayTargetBinding::class)->revision($this->target);
        $worker = new Process(
            [PHP_BINARY, base_path('tests/Support/relay_concurrent_binding.php'),
                'relay-race-target', $revision, $marker],
            base_path(), $env, null, 20,
        );
        $pdo->beginTransaction();
        try {
            $statement = $pdo->prepare('SELECT id FROM connection_relays WHERE id = ? FOR UPDATE');
            $statement->execute([$this->relay->getKey()]);
            self::assertSame((string) $this->relay->getKey(), (string) $statement->fetchColumn());
            $worker->start();
            $deadline = microtime(true) + 10;
            while (! is_file($marker)) {
                if (! $worker->isRunning() || microtime(true) >= $deadline) {
                    throw new RuntimeException('Relay worker did not reach its locked selection.');
                }
                usleep(2500);
            }
            // The worker has entered its own real DB transaction but is
            // blocked acquiring the independently held Relay row lock.
            if (! $allowBinding) {
                $disable = $pdo->prepare('UPDATE connection_relays SET enabled = 0, configuration_revision = 2, lifecycle_revision = 2 WHERE id = ?');
                $disable->execute([$this->relay->getKey()]);
            }
            $pdo->commit();
            $worker->wait();
            self::assertSame(0, $worker->getExitCode(), $worker->getErrorOutput());
            self::assertSame(
                $allowBinding ? ['status' => 'bound'] : ['status' => 'blocked', 'reason' => 'relay_unavailable'],
                json_decode($worker->getOutput(), true, 16, JSON_THROW_ON_ERROR),
            );
        } finally {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($worker->isRunning()) {
                $worker->stop(0.2);
            }
            if (is_file($marker)) {
                unlink($marker);
            }
            rmdir($directory);
        }
    }
}
