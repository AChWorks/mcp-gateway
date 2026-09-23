<?php

namespace Tests\Feature\Sites;

use App\Application\Sites\SiteCheckOperationService;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteCheckOperationStatus;
use App\Domain\Sites\SiteCheckTargetStatus;
use App\Domain\Sites\SiteConnectionState;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('database-concurrency')]
final class SiteCheckOperationConcurrencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB or MySQL is required for bulk-check row-lock concurrency validation.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
    }

    public function test_parallel_advance_requests_cannot_execute_the_same_target_twice(): void
    {
        $user = User::query()->create([
            'name' => 'Concurrency Operator',
            'email' => 'bulk-concurrency@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Administrator->value,
            'site_scope_mode' => SiteScopeMode::All->value,
            'access_enabled' => true,
        ]);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $operation = app(SiteCheckOperationService::class)->start(
            $user,
            [$alpha->site_id, $beta->site_id],
            (string) Str::uuid(),
        );

        $second = $operation->targets()->where('position', 2)->firstOrFail();
        $second->forceFill([
            'status' => SiteCheckTargetStatus::Succeeded,
            'attempts' => 1,
            'started_at' => now(),
            'finished_at' => now(),
        ])->save();

        $directory = storage_path('framework/testing/site-check-concurrency-'.Str::uuid());
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create bulk-check concurrency fixture directory.');
        }

        $barrier = $directory.'/go';
        $checkLog = $directory.'/checks.log';
        $workers = [];
        $readyPaths = [];
        $payloadPaths = [];

        try {
            for ($index = 0; $index < 2; $index++) {
                $payloadPath = $directory.'/payload-'.$index.'.json';
                $readyPath = $directory.'/ready-'.$index;
                $payloadPaths[] = $payloadPath;
                $readyPaths[] = $readyPath;
                file_put_contents($payloadPath, json_encode([
                    'user_id' => $user->getKey(),
                    'operation_id' => $operation->getKey(),
                    'check_log' => $checkLog,
                    'delay_us' => 750_000,
                ], JSON_THROW_ON_ERROR), LOCK_EX);
                chmod($payloadPath, 0600);

                $pipes = [];
                $process = proc_open([
                    PHP_BINARY,
                    base_path('tests/Support/site_check_concurrent_action.php'),
                    $payloadPath,
                    $barrier,
                    $readyPath,
                ], [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ], $pipes, base_path());

                if (! is_resource($process)) {
                    throw new RuntimeException('Could not start bulk-check concurrency worker.');
                }

                $workers[] = ['process' => $process, 'pipes' => $pipes];
            }

            $deadline = microtime(true) + 10;
            while (count(array_filter($readyPaths, 'is_file')) !== count($readyPaths)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Bulk-check concurrency workers did not become ready.');
                }
                usleep(1000);
            }

            if (! touch($barrier)) {
                throw new RuntimeException('Could not release bulk-check concurrency barrier.');
            }

            foreach ($workers as $worker) {
                $stdout = stream_get_contents($worker['pipes'][1]);
                $stderr = stream_get_contents($worker['pipes'][2]);
                fclose($worker['pipes'][1]);
                fclose($worker['pipes'][2]);
                $exitCode = proc_close($worker['process']);
                self::assertSame(0, $exitCode, trim((string) $stderr));
                $response = json_decode((string) $stdout, true, flags: JSON_THROW_ON_ERROR);
                self::assertTrue((bool) ($response['ok'] ?? false));
            }

            $checks = is_file($checkLog)
                ? array_values(array_filter(explode("\n", trim((string) file_get_contents($checkLog)))))
                : [];

            self::assertSame(['alpha.example.test'], $checks);

            $first = $operation->targets()->where('position', 1)->firstOrFail();
            self::assertSame(SiteCheckTargetStatus::Succeeded, $first->statusValue());
            self::assertSame(1, $first->attempts);
            self::assertSame(
                SiteCheckOperationStatus::Completed,
                $operation->refresh()->statusValue(),
            );
        } finally {
            foreach ($workers as $worker) {
                if (is_resource($worker['process'])) {
                    proc_terminate($worker['process']);
                }
            }

            foreach ([$barrier, $checkLog, ...$payloadPaths, ...$readyPaths] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }

            if (is_dir($directory)) {
                rmdir($directory);
            }
        }
    }

    private function site(string $siteId): Site
    {
        $base = 'https://'.$siteId.'.example.test';

        return Site::query()->create([
            'site_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => SiteConnectionState::Disconnected,
        ]);
    }
}
