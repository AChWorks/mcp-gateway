<?php

namespace Tests\Feature\OAuth;

use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PDO;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('database-concurrency')]
final class DcrRegistrationConcurrencyTest extends TestCase
{
    private const CALLBACK = 'https://chatgpt.com/connector_platform_oauth_redirect';

    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB/MySQL row locking is required for concurrent DCR admission validation.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
        config()->set('oauth.dcr.registration_enabled', true);
    }

    public function test_dcr_registration_near_capacity_is_serialized_after_safe_retirement(): void
    {
        // No public endpoint/network request or real credentials are involved.
        // The test uses a fresh disposable MariaDB schema in the CI service.
        $this->seedDormantProfiles(512);
        $retiredKey = 'dcr_'.str_pad('0', 32, '0', STR_PAD_LEFT);
        $registry = app(ClientProfileRegistry::class);
        $registry->disable($retiredKey);
        $registry->retireDcr($retiredKey);

        self::assertSame(512, DB::table('oauth_dcr_clients')->count());
        self::assertSame(511, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());
        self::assertNull($registry->active('dcr_'.str_pad('0', 48, '0', STR_PAD_LEFT)));

        // Hold the same durable admission lock used by both registration and
        // retirement until both independent workers have been released.
        $blocker = $this->lockRegistrationAnchor();
        $directory = storage_path('framework/testing/dcr-admission-'.Str::uuid());
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create isolated DCR concurrency fixture directory.');
        }

        $barrier = $directory.'/go';
        $ready = [$directory.'/ready-1', $directory.'/ready-2'];
        $workers = [];

        try {
            foreach ($ready as $path) {
                $pipes = [];
                $worker = proc_open([
                    PHP_BINARY,
                    base_path('tests/Support/dcr_concurrent_registration_request.php'),
                    $barrier,
                    $path,
                ], [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ], $pipes, base_path());

                if (! is_resource($worker)) {
                    throw new RuntimeException('Failed to start DCR concurrency worker.');
                }

                $workers[] = ['process' => $worker, 'pipes' => $pipes];
            }

            $deadline = microtime(true) + 10;
            while (! is_file($ready[0]) || ! is_file($ready[1])) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('DCR concurrency workers did not signal readiness.');
                }
                usleep(1000);
            }

            if (! touch($barrier)) {
                throw new RuntimeException('Could not release DCR concurrency barrier.');
            }

            // Both processes enter the registration transaction and queue on
            // this locked anchor. At most one can occupy the last free slot.
            usleep(500_000);
            $blocker->commit();

            $outcomes = [];
            foreach ($workers as $worker) {
                $stdout = stream_get_contents($worker['pipes'][1]);
                $stderr = stream_get_contents($worker['pipes'][2]);
                fclose($worker['pipes'][1]);
                fclose($worker['pipes'][2]);
                $exitCode = proc_close($worker['process']);

                self::assertSame(0, $exitCode, trim((string) $stderr));
                $parsed = json_decode((string) $stdout, true, flags: JSON_THROW_ON_ERROR);
                self::assertIsArray($parsed);
                self::assertContains($parsed['outcome'] ?? null, ['registered', 'capacity']);
                $outcomes[] = $parsed['outcome'];
            }

            sort($outcomes);
            self::assertSame(['capacity', 'registered'], $outcomes);
            self::assertSame(513, DB::table('oauth_dcr_clients')->count());
            self::assertSame(512, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());
            self::assertSame(1, DB::table('oauth_dcr_clients')->whereNotNull('retired_at')->count());
            // Legacy CIMD + 511 surviving DCR clients + 1 new DCR client.
            self::assertSame(513, DB::table('oauth_client_profiles')
                ->whereNull('disabled_at')->count());
            self::assertSame(513, DB::table('oauth_dcr_clients')
                ->distinct()->count('client_id'));
        } finally {
            if ($blocker->inTransaction()) {
                $blocker->rollBack();
            }
            foreach ($workers as $worker) {
                if (is_resource($worker['process'])) {
                    proc_terminate($worker['process']);
                }
            }
            foreach ([$barrier, ...$ready] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }
            if (is_dir($directory)) {
                rmdir($directory);
            }
        }
    }

    public function test_expired_registration_cannot_be_retired_after_concurrent_consent_commits(): void
    {
        $this->seedDormantProfiles(512);
        $clientId = 'dcr_'.str_pad('0', 48, '0', STR_PAD_LEFT);
        $profileKey = 'dcr_'.str_pad('0', 32, '0', STR_PAD_LEFT);
        DB::table('oauth_dcr_clients')->where('client_id', $clientId)
            ->update(['created_at' => now()->subHours(25)]);

        $user = User::query()->create([
            'name' => 'Concurrent consent owner',
            'email' => 'consent-race@example.test',
            'password' => 'CorrectHorse!234',
        ]);

        // Consent holds the profile lock while creating its authorization.
        // Registration may have selected the orphan under MariaDB's older
        // transaction snapshot, but MUST re-read grants after acquiring the
        // profile lock. This test proves that exact race under two PDO sessions.
        $consent = $this->newDatabaseConnection();
        $consent->beginTransaction();
        $locked = $consent->prepare('SELECT profile_key FROM oauth_client_profiles WHERE profile_key=? FOR UPDATE');
        $locked->execute([$profileKey]);
        self::assertSame($profileKey, $locked->fetchColumn());

        $directory = storage_path('framework/testing/dcr-consent-race-'.Str::uuid());
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Cannot create disposable DCR consent race fixture.');
        }

        $barrier = $directory.'/go';
        $ready = $directory.'/ready';
        $pipes = [];
        $worker = null;

        try {
            $worker = proc_open([
                PHP_BINARY,
                base_path('tests/Support/dcr_concurrent_registration_request.php'),
                $barrier,
                $ready,
            ], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, base_path());
            if (! is_resource($worker)) {
                throw new RuntimeException('Cannot start concurrent DCR registration fixture.');
            }

            $deadline = microtime(true) + 10;
            while (! is_file($ready)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Concurrent DCR registration did not report readiness.');
                }
                usleep(1000);
            }
            if (! touch($barrier)) {
                throw new RuntimeException('Cannot release concurrent DCR registration barrier.');
            }

            // Registration selects the old unconsented candidate and must
            // block when acquiring its profile row FOR UPDATE.
            usleep(500_000);

            $insert = $consent->prepare(
                'INSERT INTO oauth_authorizations '
                .'(id, user_id, client_id, client_profile_key, client_profile_generation, '
                .'resource, resource_hash, scopes, revoked_at, created_at, updated_at) '
                .'VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NOW(), NOW())',
            );
            $resource = (string) config('oauth.resource');
            $insert->execute([
                (string) Str::ulid(), $user->id, $clientId, $profileKey, 1,
                $resource, hash('sha256', $resource),
                json_encode(['mcp'], JSON_THROW_ON_ERROR),
            ]);
            $consent->commit();

            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exit = proc_close($worker);
            $worker = null;

            self::assertSame(0, $exit, trim((string) $stderr));
            self::assertSame('capacity', json_decode((string) $stdout, true, flags: JSON_THROW_ON_ERROR)['outcome']);
            self::assertSame(512, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());
            self::assertNull(DB::table('oauth_dcr_clients')->where('client_id', $clientId)->value('retired_at'));
            self::assertNull(DB::table('oauth_client_profiles')->where('profile_key', $profileKey)->value('disabled_at'));
            self::assertSame(1, DB::table('oauth_authorizations')->where('client_id', $clientId)->count());
        } finally {
            if ($consent->inTransaction()) {
                $consent->rollBack();
            }
            if (is_resource($worker)) {
                proc_terminate($worker);
                proc_close($worker);
            }
            foreach ([$barrier, $ready] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }
            if (is_dir($directory)) {
                rmdir($directory);
            }
        }
    }

    private function seedDormantProfiles(int $count): void
    {
        $profiles = [];
        $clients = [];
        for ($i = 0; $i < $count; $i++) {
            $id = 'dcr_'.str_pad(dechex($i), 48, '0', STR_PAD_LEFT);
            $key = 'dcr_'.str_pad(dechex($i), 32, '0', STR_PAD_LEFT);
            $profiles[] = ['profile_key' => $key, 'client_id' => $id,
                'auth_strategy' => 'dcr_client_secret_post', 'generation' => 1,
                'disabled_at' => null, 'created_at' => now(), 'updated_at' => now()];
            $clients[] = ['client_id' => $id, 'profile_key' => $key,
                'secret_hash' => hash('sha256', $id),
                'redirect_uris' => json_encode([self::CALLBACK], JSON_THROW_ON_ERROR),
                'display_name' => 'ChatGPT (DCR)', 'retired_at' => null,
                'created_at' => now(), 'updated_at' => now()];
        }

        foreach (array_chunk($profiles, 60) as $rows) {
            DB::table('oauth_client_profiles')->insert($rows);
        }
        foreach (array_chunk($clients, 60) as $rows) {
            DB::table('oauth_dcr_clients')->insert($rows);
        }
    }

    private function lockRegistrationAnchor(): PDO
    {
        $pdo = $this->newDatabaseConnection();
        $pdo->beginTransaction();
        $row = $pdo->query("SELECT profile_key FROM oauth_client_profiles WHERE profile_key='chatgpt' FOR UPDATE");
        if ($row === false || $row->fetchColumn() === false) {
            $pdo->rollBack();
            throw new RuntimeException('DCR admission lock anchor is missing.');
        }

        return $pdo;
    }

    private function newDatabaseConnection(): PDO
    {
        $configuration = DB::connection()->getConfig();
        $socket = (string) ($configuration['unix_socket'] ?? '');
        $dsn = $socket !== ''
            ? sprintf('mysql:unix_socket=%s;dbname=%s;charset=utf8mb4',
                $socket, (string) ($configuration['database'] ?? ''))
            : sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
                (string) ($configuration['host'] ?? '127.0.0.1'),
                (string) ($configuration['port'] ?? '3306'),
                (string) ($configuration['database'] ?? ''));

        return new PDO($dsn, (string) ($configuration['username'] ?? ''),
            (string) ($configuration['password'] ?? ''), [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
    }
}
