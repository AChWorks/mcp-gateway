<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshConnectionAdmission;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class SshConnectionAdmissionTest extends TestCase
{
    public function test_rate_limit_is_per_target_and_zero_configuration_cannot_disable_it(): void
    {
        config()->set('ssh.verification.max_attempts_per_minute', 2);
        $admission = new SshConnectionAdmission;
        $firstTarget = 'target-'.Str::random(16);

        self::assertSame('one', $admission->run($firstTarget, static fn (): string => 'one'));
        self::assertSame('two', $admission->run($firstTarget, static fn (): string => 'two'));
        $this->expectReason('rate_limited', static fn () => $admission->run($firstTarget, static fn (): null => null));

        self::assertSame('other', $admission->run(
            'other-'.Str::random(16),
            static fn (): string => 'other',
        ));

        config()->set('ssh.verification.max_attempts_per_minute', 0);
        $clamped = 'clamped-'.Str::random(16);
        self::assertSame('allowed', $admission->run($clamped, static fn (): string => 'allowed'));
        $this->expectReason('rate_limited', static fn () => $admission->run($clamped, static fn (): null => null));
    }

    public function test_failed_operation_releases_the_per_target_lease_immediately(): void
    {
        $admission = new SshConnectionAdmission;
        $target = 'failed-'.Str::random(16);

        try {
            $admission->run($target, static function (): never {
                throw new RuntimeException('fixture failure');
            });
            self::fail('Fixture exception was not propagated.');
        } catch (RuntimeException $exception) {
            self::assertSame('fixture failure', $exception->getMessage());
        }

        self::assertSame('recovered', $admission->run($target, static fn (): string => 'recovered'));
    }

    public function test_file_backed_lease_is_shared_across_php_workers(): void
    {
        if (! function_exists('pcntl_fork') || ! function_exists('pcntl_waitpid')) {
            $this->markTestSkipped('pcntl is required for multi-process SSH admission validation.');
        }

        $directory = sys_get_temp_dir().'/ssh-admission-'.Str::random(16);
        File::ensureDirectoryExists($directory);
        $previousDefault = config('cache.default');
        $previousFile = config('cache.stores.file');
        $target = 'shared-'.Str::random(16);
        $ready = $directory.'/ready';
        $pid = null;

        try {
            config()->set('cache.default', 'file');
            config()->set('cache.stores.file.path', $directory);
            config()->set('cache.stores.file.lock_path', $directory);
            Cache::purge('file');

            $pid = pcntl_fork();
            if ($pid === -1) {
                self::fail('Unable to fork an SSH admission test worker.');
            }
            if ($pid === 0) {
                try {
                    (new SshConnectionAdmission)->run($target, static function () use ($ready): void {
                        file_put_contents($ready, 'ready');
                        usleep(750000);
                    });
                    exit(0);
                } catch (\Throwable $exception) {
                    file_put_contents($ready.'.error', $exception::class.':'.$exception->getMessage());
                    exit(2);
                }
            }

            for ($i = 0; $i < 100 && ! is_file($ready); $i++) {
                usleep(10000);
            }
            self::assertFileExists($ready, is_file($ready.'.error') ? (string) file_get_contents($ready.'.error') : '');
            $this->expectReason('connection_busy', static fn () => (new SshConnectionAdmission)
                ->run($target, static fn (): null => null));

            self::assertSame($pid, pcntl_waitpid($pid, $status));
            self::assertTrue(pcntl_wifexited($status));
            self::assertSame(0, pcntl_wexitstatus($status));
            $pid = null;

            self::assertSame('after', (new SshConnectionAdmission)
                ->run($target, static fn (): string => 'after'));
        } finally {
            if (is_int($pid)) {
                if (function_exists('posix_kill')) {
                    posix_kill($pid, SIGTERM);
                }
                pcntl_waitpid($pid, $status);
            }
            config()->set('cache.default', $previousDefault);
            config()->set('cache.stores.file', $previousFile);
            Cache::purge('file');
            File::deleteDirectory($directory);
        }
    }

    private function expectReason(string $reason, callable $operation): void
    {
        try {
            $operation();
            self::fail('Expected SSH admission failure: '.$reason);
        } catch (SshTargetConnectionException $exception) {
            self::assertSame($reason, $exception->reason);
            self::assertSame('SSH connection cannot be completed safely.', $exception->getMessage());
        }
    }
}
