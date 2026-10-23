<?php

namespace Tests\Feature\OAuth;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\DcrClientRegistration;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use PDO;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('database-concurrency')]
final class DcrAuthorizationRetirementConcurrencyTest extends TestCase
{
    private const CALLBACK = 'https://chatgpt.com/connector_platform_oauth_redirect';

    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB/MySQL is required to validate OAuth authorization row locking.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
        config()->set('oauth.dcr.registration_enabled', true);
    }

    public function test_prechecked_pending_consent_cannot_commit_after_owner_disables_and_retires_client(): void
    {
        [$clientId, $key] = $this->registerDcr();
        [$otherId] = $this->registerDcr();
        $userId = $this->operatorId();
        $registry = app(ClientProfileRegistry::class);

        $this->runWorker($clientId, $userId, function () use ($registry, $key, $clientId): void {
            $registry->disable($key);
            $registry->retireDcr($key);

            self::assertNotNull(DB::table('oauth_dcr_clients')
                ->where('client_id', $clientId)->value('retired_at'));
        });

        $this->assertNoStaleAuthorization($clientId);
        self::assertSame(2, (int) DB::table('oauth_client_profiles')
            ->where('profile_key', $key)->value('generation'));
        self::assertNull($registry->active($clientId));

        // Another client continues receiving real, usable parent grants.
        $grant = app(OAuthAuthorizationStore::class)->approve(
            $userId, $otherId, (string) config('oauth.resource'), ['mcp'],
        );
        self::assertSame($grant, DB::table('oauth_authorizations')
            ->where('client_id', $otherId)->whereNull('revoked_at')->value('id'));
        self::assertNotNull($registry->active($otherId));
    }

    public function test_approval_waiting_on_durable_profile_lock_cannot_write_after_disable(): void
    {
        [$clientId, $key] = $this->registerDcr();
        $userId = $this->operatorId();

        $this->runWorker($clientId, $userId, function (string $barrier, string $entered) use ($clientId, $key): void {
            // Hold the exact profile row targeted by the approval transaction.
            // A second process has already performed its positive preflight.
            $pdo = $this->databaseConnection();
            $pdo->beginTransaction();

            try {
                $lock = $pdo->prepare('SELECT profile_key FROM oauth_client_profiles WHERE client_id = ? FOR UPDATE');
                $lock->execute([$clientId]);
                self::assertSame($key, $lock->fetchColumn());

                if (! touch($barrier)) {
                    throw new RuntimeException('Could not release the approval worker.');
                }
                $deadline = microtime(true) + 10;
                while (! is_file($entered)) {
                    if (microtime(true) >= $deadline) {
                        throw new RuntimeException('Approval worker did not reach its transaction.');
                    }
                    usleep(1000);
                }

                // Model the Owner's exact persisted disable transition in the
                // held transaction. The waiting approval must then observe the
                // *committed* generation/disabled state, not the preflight.
                $disable = $pdo->prepare(
                    'UPDATE oauth_client_profiles SET generation = generation + 1, '
                    .'disabled_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP '
                    .'WHERE client_id = ?',
                );
                $disable->execute([$clientId]);
                self::assertSame(1, $disable->rowCount());
                $pdo->commit();
            } finally {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
            }

            app(ClientProfileRegistry::class)->retireDcr($key);
        }, releasesBarrier: false);

        $this->assertNoStaleAuthorization($clientId);
        self::assertNotNull(DB::table('oauth_dcr_clients')
            ->where('client_id', $clientId)->value('retired_at'));
    }

    /** @return array{0:string, 1:string} */
    private function registerDcr(): array
    {
        $registered = app(DcrClientRegistration::class)->register([
            'client_name' => 'ChatGPT',
            'redirect_uris' => [self::CALLBACK],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'client_secret_post',
        ]);

        $id = (string) $registered['client_id'];
        $profileKey = (string) DB::table('oauth_dcr_clients')->where('client_id', $id)
            ->value('profile_key');

        return [$id, $profileKey];
    }

    private function operatorId(): int
    {
        $user = User::query()->create([
            'name' => 'OAuth Consent Race Operator',
            'email' => 'dcr-retirement-race@example.test',
            'password' => Hash::make('Only-a-disposable-race-fixture-password'),
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true, 'ai_access_enabled' => true,
        ]);

        return (int) $user->id;
    }

    private function assertNoStaleAuthorization(string $clientId): void
    {
        foreach (['oauth_authorizations', 'oauth_auth_codes', 'oauth_access_tokens',
            'oauth_refresh_tokens', 'oauth_refresh_recoveries'] as $table) {
            self::assertSame(0, DB::table($table)->where('client_id', $clientId)->count(), $table);
        }
    }

    /** @param callable(string,string):void $ownerTransition */
    private function runWorker(
        string $clientId,
        int $userId,
        callable $ownerTransition,
        bool $releasesBarrier = true,
    ): void {
        $directory = storage_path('framework/testing/dcr-approval-retirement-'.Str::uuid());
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Unable to create isolated authorization-race fixture.');
        }

        $ready = $directory.'/ready';
        $barrier = $directory.'/go';
        $entered = $directory.'/entered';
        $pipes = [];
        $worker = null;

        try {
            $worker = proc_open([
                PHP_BINARY,
                base_path('tests/Support/dcr_concurrent_authorization_request.php'),
                $clientId, (string) $userId, $ready, $barrier, $entered,
            ], [
                0 => ['file', '/dev/null', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ], $pipes, base_path());

            if (! is_resource($worker)) {
                throw new RuntimeException('Unable to create independent approval process.');
            }

            $deadline = microtime(true) + 10;
            while (! is_file($ready)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Approval process did not finish the initial active-client check.');
                }
                usleep(1000);
            }

            $ownerTransition($barrier, $entered);

            if ($releasesBarrier && ! touch($barrier)) {
                throw new RuntimeException('Unable to release stale approval process.');
            }

            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $pipes = [];
            $exit = proc_close($worker);
            $worker = null;

            self::assertSame(0, $exit, trim((string) $stderr));
            $outcome = json_decode((string) $stdout, true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('refused', $outcome['result'] ?? null);
        } finally {
            foreach ($pipes as $pipe) {
                if (is_resource($pipe)) {
                    fclose($pipe);
                }
            }
            if (is_resource($worker)) {
                proc_terminate($worker);
                proc_close($worker);
            }
            foreach ([$ready, $barrier, $entered] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }
            if (is_dir($directory)) {
                rmdir($directory);
            }
        }
    }

    private function databaseConnection(): PDO
    {
        $config = DB::connection()->getConfig();
        $socket = (string) ($config['unix_socket'] ?? '');
        $dsn = $socket !== ''
            ? sprintf('mysql:unix_socket=%s;dbname=%s;charset=utf8mb4', $socket, (string) ($config['database'] ?? ''))
            : sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
                (string) ($config['host'] ?? '127.0.0.1'),
                (string) ($config['port'] ?? '3306'), (string) ($config['database'] ?? ''));

        return new PDO($dsn, (string) ($config['username'] ?? ''), (string) ($config['password'] ?? ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
}
