<?php

namespace Tests\Feature\Mcp;

use App\Application\Files\ChatGptFileCapacity;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

/**
 * Two real independent PHP workers against one disposable MariaDB.
 * Neither worker fetches source bytes or makes any remote network request.
 */
#[Group('database-concurrency')]
final class ChatGptFileCapacityConcurrencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('Independent admission locking requires disposable MariaDB.');
        }
        $db = (string) DB::connection()->getDatabaseName();
        if (! app()->environment('testing')
            || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', $db) !== 1) {
            throw new RuntimeException('File admission race fixture refuses non-test databases.');
        }
        Artisan::call('migrate:fresh', ['--force' => true]);
    }

    public function test_independent_requests_cannot_oversubscribe_a_single_active_slot(): void
    {
        $this->race('wordpress', 131072, 1);
    }

    public function test_independent_requests_cannot_oversubscribe_total_temporary_bytes(): void
    {
        // Both workers fit the concurrency limit of TWO, but two reservations
        // of 700000 bytes cannot fit the shared 1 MiB budget.
        $this->race('wordpress', 700000, 2);
    }

    private function race(string $mode, int $bytes, int $maxActive): void
    {
        $dir = storage_path('framework/testing/file-admission-'.bin2hex(random_bytes(8)));
        if (! mkdir($dir, 0700, true) && ! is_dir($dir)) {
            throw new RuntimeException('Private concurrency barrier creation failed.');
        }

        $workers = [];
        try {
            foreach (['a', 'b'] as $name) {
                $pipes = [];
                $process = proc_open([
                    PHP_BINARY, base_path('tests/Support/chatgpt_file_capacity_race.php'),
                    $dir, $name, $mode, (string) $bytes, (string) $maxActive,
                ], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                    $pipes, base_path());
                if (! is_resource($process)) {
                    throw new RuntimeException('Failed to launch independent admission worker.');
                }
                $workers[$name] = ['process' => $process, 'pipes' => $pipes];
            }

            $this->waitUntil(static fn (): bool => is_file($dir.'/ready-a') && is_file($dir.'/ready-b'));
            touch($dir.'/go');
            $this->waitUntil(static fn (): bool => is_file($dir.'/admitted-a') || is_file($dir.'/admitted-b'));
            $winner = is_file($dir.'/admitted-a') ? 'a' : 'b';
            $loser = $winner === 'a' ? 'b' : 'a';
            $this->waitUntil(static fn (): bool => is_file($dir.'/result-'.$loser));
            self::assertFileDoesNotExist($dir.'/admitted-'.$loser);
            $denied = json_decode((string) file_get_contents($dir.'/result-'.$loser),
                true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('denied', $denied['status']);
            self::assertSame('file_capacity_exceeded', $denied['reason']);
            self::assertSame(1, DB::table('chatgpt_file_admission_leases')->count());
            self::assertSame($bytes, (int) DB::table('chatgpt_file_admission_leases')->sum('reserved_bytes'));

            touch($dir.'/release');
            $this->waitUntil(static fn (): bool => is_file($dir.'/result-'.$winner));
            $accepted = json_decode((string) file_get_contents($dir.'/result-'.$winner),
                true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('admitted', $accepted['status']);
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

            self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());
            config()->set('bridge.file_input.capacity.max_active', $maxActive);
            config()->set('bridge.file_input.capacity.max_reserved_bytes', 1048576);
            $fresh = app(ChatGptFileCapacity::class)->reserve('wordpress', $bytes, 20);
            $fresh->release();
            self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());
        } finally {
            touch($dir.'/release');
            touch($dir.'/go');
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
            foreach (glob($dir.'/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    private function waitUntil(\Closure $ready): void
    {
        $until = microtime(true) + 15;
        while (! $ready()) {
            if (microtime(true) >= $until) {
                throw new RuntimeException('Independent capacity workers failed to reach the test barrier.');
            }
            usleep(10000);
        }
    }
}
