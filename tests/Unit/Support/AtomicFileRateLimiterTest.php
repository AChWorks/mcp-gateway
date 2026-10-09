<?php

namespace Tests\Unit\Support;

use App\Support\AtomicFileRateLimiter;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Tests\TestCase;

final class AtomicFileRateLimiterTest extends TestCase
{
    public function test_concurrent_file_cache_attempts_are_all_accounted_for(): void
    {
        if (! function_exists('pcntl_fork') || ! function_exists('pcntl_waitpid')) {
            $this->markTestSkipped('pcntl is required for multi-process rate-limit validation.');
        }

        $directory = sys_get_temp_dir().'/oauth-file-rate-limit-'.Str::random(16);
        File::ensureDirectoryExists($directory);

        $previousFile = config('cache.stores.file');
        $children = [];

        try {
            config()->set('cache.stores.file.path', $directory);
            config()->set('cache.stores.file.lock_path', $directory);
            Cache::purge('file');

            $limiter = new AtomicFileRateLimiter(Cache::store('file'));
            $key = 'test:client:profile:bucket';
            for ($i = 0; $i < 6; $i++) {
                $pid = pcntl_fork();
                if ($pid === -1) {
                    self::fail('Unable to fork a rate-limit test worker.');
                }
                if ($pid === 0) {
                    for ($j = 0; $j < 20; $j++) {
                        $limiter->hit($key, 60);
                    }

                    exit(0);
                }

                $children[] = $pid;
            }

            foreach ($children as $pid) {
                self::assertSame($pid, pcntl_waitpid($pid, $status));
                self::assertTrue(pcntl_wifexited($status));
                self::assertSame(0, pcntl_wexitstatus($status));
            }
            $children = [];
            self::assertSame(120, $limiter->attempts($key));
        } finally {
            foreach ($children as $pid) {
                if (function_exists('posix_kill')) {
                    posix_kill($pid, SIGTERM);
                }
                pcntl_waitpid($pid, $status);
            }

            config()->set('cache.stores.file', $previousFile);
            Cache::purge('file');
            File::deleteDirectory($directory);
        }
    }

    public function test_non_file_cache_driver_keeps_native_rate_limiter_behavior(): void
    {
        self::assertInstanceOf(AtomicFileRateLimiter::class, app(\Illuminate\Cache\RateLimiter::class));

        $limiter = new AtomicFileRateLimiter(Cache::store('array'));
        $key = 'test:native:'.Str::random(16);

        self::assertSame(1, $limiter->hit($key, 60));
        self::assertSame(2, $limiter->hit($key, 60));
        self::assertTrue($limiter->tooManyAttempts($key, 2));
        $limiter->clear($key);
        self::assertSame(0, $limiter->attempts($key));
    }
}
