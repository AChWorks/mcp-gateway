<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshFileAdmission;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class SshFileAdmissionTest extends TestCase
{
    public function test_rate_and_target_isolation(): void
    {
        $service = new SshFileAdmission;
        $id = Str::random(24);
        for ($i = 0; $i < 30; $i++) {
            self::assertSame('ok', $service->run($id, static fn (): string => 'ok'));
        }
        try {
            $service->run($id, static fn (): string => 'unexpected');
            self::fail('Expected rate_limited');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('rate_limited', $exception->reason);
        }
        self::assertSame('other', $service->run(Str::random(24), static fn (): string => 'other'));
    }

    public function test_extended_transfer_lease_covers_original_deadline_without_changing_short_operations(): void
    {
        $service = new SshFileAdmission;
        foreach ([55 => 90, 56 => 146, 3600 => 3690] as $seconds => $expected) {
            $id = Str::random(24);
            $key = 'ssh-file:'.hash('sha256', $id).':lease';
            $actual = $service->run($id, static function () use ($key): int {
                $locks = Cache::getStore()->locks;
                self::assertArrayHasKey($key, $locks);

                return now()->diffInSeconds($locks[$key]['expiresAt']);
            }, hrtime(true) + $seconds * 1_000_000_000);
            self::assertEqualsWithDelta($expected, $actual, 2);
        }
        try {
            $service->run('too-long', static fn (): string => 'wrong',
                hrtime(true) + 3601 * 1_000_000_000);
            self::fail('SFTP lock must reject out-of-policy deadlines.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('invalid_input', $exception->reason);
        }
    }

    public function test_stream_primitive_accepts_exact_3600_seconds_but_rejects_larger_budgets(): void
    {
        $reflection = new \ReflectionClass(SshFileRuntime::class);
        $runtime = $reflection->newInstanceWithoutConstructor();
        $validate = $reflection->getMethod('validateStreamDeadline');
        $validate->invoke($runtime, 3600);
        try {
            $validate->invoke($runtime, 3601);
            self::fail('A stream must reject over-policy budgets before SFTP.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('invalid_input', $exception->reason);
        }
    }

    public function test_upload_stream_honors_an_already_expired_whole_file_deadline_before_remote_effects(): void
    {
        // No network fixture required: an expired ingress deadline must fail
        // before connector/credential inspection, not reset for SFTP staging.
        $runtime = (new \ReflectionClass(SshFileRuntime::class))->newInstanceWithoutConstructor();
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        try {
            $runtime->uploadFromStream(
                new User, new Target, '/tmp/destination.bin', $source,
                0, hash('sha256', ''), 65536, 3600, '/tmp/private',
                overallDeadlineNs: hrtime(true) - 1,
            );
            self::fail('An expired whole-file deadline must not restart at SFTP dispatch.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('transfer_timed_out', $exception->reason);
        } finally {
            fclose($source);
        }
    }

    public function test_reentry_and_lease_release_after_failure(): void
    {
        $service = new SshFileAdmission;
        $id = Str::random(24);
        $service->run($id, static function () use ($service, $id): void {
            try {
                $service->run($id, static fn (): string => 'unexpected');
                self::fail('Expected busy');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame('connection_busy', $exception->reason);
            }
        });
        try {
            $service->run($id, static function (): never {
                throw new RuntimeException('fixture-failure');
            });
        } catch (RuntimeException $exception) {
            self::assertSame('fixture-failure', $exception->getMessage());
        }
        self::assertSame('recovered', $service->run($id, static fn (): string => 'recovered'));
    }
}
