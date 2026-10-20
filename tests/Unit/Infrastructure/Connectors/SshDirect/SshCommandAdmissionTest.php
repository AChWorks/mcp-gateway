<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshCommandAdmission;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class SshCommandAdmissionTest extends TestCase
{
    public function test_command_budget_is_finite_and_scoped_per_target(): void
    {
        $admission = new SshCommandAdmission;
        $target = 'rate-'.Str::random(16);
        for ($i = 0; $i < 30; $i++) {
            self::assertSame('ok', $admission->run($target, static fn (): string => 'ok'));
        }

        try {
            $admission->run($target, static fn (): string => 'wrong');
            self::fail('Target should be rate limited.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('rate_limited', $exception->reason);
        }

        self::assertSame('other', $admission->run('other-'.Str::random(16), static fn (): string => 'other'));
    }

    public function test_selected_command_timeout_extends_same_target_lease_beyond_old_90_seconds(): void
    {
        $admission = new SshCommandAdmission;
        foreach ([15 => 90, 35 => 125, 95 => 185, 360 => 450, 600 => 690] as $commandSeconds => $expectedLease) {
            $target = 'lease-dynamic-'.Str::random(12);
            $key = 'ssh-command:'.hash('sha256', $target).':lease';
            $observed = $admission->run($target, static function () use ($key): int {
                $store = Cache::getStore();
                self::assertArrayHasKey($key, $store->locks);
                $expiresAt = $store->locks[$key]['expiresAt'];

                return now()->diffInSeconds($expiresAt);
            }, $commandSeconds);
            self::assertEqualsWithDelta($expectedLease, $observed, 2);
        }

        try {
            $admission->run('invalid-lease', static fn (): string => 'wrong', 601);
            self::fail('Over-range lease must fail before lock acquisition.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('invalid_input', $exception->reason);
        }
    }

    public function test_per_target_reentry_fails_closed_and_failure_releases_admission(): void
    {
        $admission = new SshCommandAdmission;
        $target = 'lease-'.Str::random(16);
        $admission->run($target, static function () use ($target, $admission): void {
            try {
                $admission->run($target, static fn (): string => 'wrong');
                self::fail('Reentry must be denied.');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame('connection_busy', $exception->reason);
            }
        });

        try {
            $admission->run($target, static function (): never {
                throw new RuntimeException('fixture-dispatch-failed');
            });
            self::fail('Expected fixture failure.');
        } catch (RuntimeException $exception) {
            self::assertSame('fixture-dispatch-failed', $exception->getMessage());
        }

        self::assertSame('recovered', $admission->run($target, static fn (): string => 'recovered'));
    }
}
