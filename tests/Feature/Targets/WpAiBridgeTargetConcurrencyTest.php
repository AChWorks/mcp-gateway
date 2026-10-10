<?php

namespace Tests\Feature\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetVault;
use App\Infrastructure\OAuth\GatewayBridgeClientIdentity;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('database-concurrency')]
final class WpAiBridgeTargetConcurrencyTest extends TestCase
{
    private bool $ownsFixture = false;

    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('Independent MariaDB connections are needed for WordPress refresh races.');
        }

        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/targets/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');
        // This suite intentionally wipes/rebuilds schema for independent
        // worker connections. Never let a developer accidentally point it at
        // a non-disposable database.
        $database = (string) DB::connection()->getDatabaseName();
        if (! app()->environment('testing')
            || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', $database) !== 1) {
            throw new RuntimeException('WordPress concurrency fixture refuses a non-test MariaDB database.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
        $this->ownsFixture = true;
        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);
        $this->createExpiredCredential();
    }

    protected function tearDown(): void
    {
        try {
            // RefreshDatabase tests that run next must not inherit the
            // committed seed from these deliberately cross-process cases.
            if ($this->ownsFixture && Schema::hasTable('targets')) {
                Target::query()->where('target_id', 'race')->delete();
            }
        } finally {
            parent::tearDown();
        }
    }

    public function test_two_process_refresh_and_disconnect_cannot_race_over_rotating_token_generation(): void
    {
        $directory = storage_path('framework/testing/wp-target-race-'.bin2hex(random_bytes(8)));
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Cannot create process barrier directory.');
        }
        $processes = [];

        try {
            $processes[] = $this->startWorker($directory, 'refresh', 'first', true);
            $this->waitFor($directory.'/remote-first');
            self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());

            $processes[] = $this->startWorker($directory, 'refresh', 'second', false);
            $processes[] = $this->startWorker($directory, 'disconnect', 'third', false);
            $this->waitFor($directory.'/ready-second');
            $this->waitFor($directory.'/ready-third');

            self::assertSame(['status' => 'blocked', 'reason' => 'refresh_pending'],
                $this->completeWorker($processes[1]));
            self::assertSame(['status' => 'blocked', 'reason' => 'refresh_pending'],
                $this->completeWorker($processes[2]));

            self::assertFileDoesNotExist($directory.'/remote-second');
            self::assertFileDoesNotExist($directory.'/remote-third');
            self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
            self::assertSame(1, (int) DB::table('wp_ai_bridge_credential_metadata')->value('generation'));

            touch($directory.'/release');
            self::assertSame(['status' => 'ok', 'result' => 'race-rotated-access'],
                $this->completeWorker($processes[0]));

            self::assertSame(2, (int) DB::table('wp_ai_bridge_credential_metadata')->value('generation'));
            self::assertSame(0, DB::table('wp_ai_bridge_refresh_intents')->count());
            $credential = TargetCredential::query()->firstOrFail();
            $secret = app(WpAiBridgeTargetVault::class)->openCredential(Target::query()->firstOrFail(), $credential);
            self::assertSame('race-rotated-refresh', $secret['refresh_token']);

            // Only *after* all in-flight rotations have settled can an
            // independent process revoke the actual successor and disconnect.
            $processes[] = $this->startWorker($directory, 'disconnect', 'fourth', false);
            self::assertSame(['status' => 'ok', 'result' => 'disconnected'],
                $this->completeWorker($processes[3]));
            self::assertFileExists($directory.'/remote-fourth');
            self::assertSame(0, DB::table('target_credentials')->count());
            self::assertSame(0, DB::table('wp_ai_bridge_revocation_intents')->count());
            self::assertSame('disconnected', Target::query()->firstOrFail()->connection_state->value);
        } finally {
            touch($directory.'/release');
            foreach ($processes as $worker) {
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

    /** @return array{process: resource|false, pipes: array<int,resource>} */
    private function startWorker(string $directory, string $action, string $id, bool $holdRemote): array
    {
        $pipes = [];
        $process = proc_open([
            PHP_BINARY,
            base_path('tests/Support/wp_target_concurrent_action.php'),
            $action, $directory, $id, $holdRemote ? 'yes' : 'no',
        ], [
            0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes, base_path());
        if (! is_resource($process)) {
            throw new RuntimeException('Could not launch WP concurrency worker.');
        }

        return ['process' => $process, 'pipes' => $pipes];
    }

    /** @param array{process: resource|false,pipes: array<int,resource>} $worker
     * @return array{status:string,reason?:string,result?:string}
     */
    private function completeWorker(array &$worker): array
    {
        $stdout = stream_get_contents($worker['pipes'][1]);
        $stderr = stream_get_contents($worker['pipes'][2]);
        fclose($worker['pipes'][1]);
        fclose($worker['pipes'][2]);
        $worker['pipes'] = [];
        $exit = proc_close($worker['process']);
        $worker['process'] = false;
        self::assertSame(0, $exit, trim((string) $stderr));
        $result = json_decode((string) $stdout, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($result);

        return $result;
    }

    private function waitFor(string $path): void
    {
        $deadline = microtime(true) + 10;
        while (! is_file($path)) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Timed out waiting for independent WordPress worker.');
            }
            usleep(10000);
        }
    }

    private function createExpiredCredential(): void
    {
        $base = 'https://race.example.test';
        $resource = $base.'/wp-json/wp-ai-bridge/v1/mcp';
        $client = app(GatewayBridgeClientIdentity::class)->clientId();

        $target = Target::query()->create([
            'target_id' => 'race',
            'display_name' => 'Isolated WP Race',
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => 'connected',
            'connected_at' => now(),
        ]);
        WpAiBridgeTargetConfig::query()->create([
            'target_record_id' => $target->getKey(),
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'mcp_resource_url' => $resource,
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
        ]);
        $credential = TargetCredential::query()->create([
            'target_record_id' => $target->getKey(),
            'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth',
            'encrypted_payload' => app(WpAiBridgeTargetVault::class)->sealCredential(
                $target, $client, $resource, 'race-old-access', 'race-old-refresh',
                now()->subMinute(), ['mcp:use', 'offline_access'],
            ),
        ]);
        DB::table('wp_ai_bridge_credential_metadata')->insert([
            'credential_id' => $credential->getKey(),
            'client_id' => $client,
            'resource_url' => $resource,
            'binding_hash' => hash('sha256',
                $target->getKey()."\0".$target->target_id."\0".$client."\0".$resource,
            ),
            'access_expires_at' => now()->subMinute(),
            'refresh_expires_at' => now()->addHours(2),
            'refresh_due_at' => now()->subMinute(),
            'generation' => 1,
        ]);
    }
}
