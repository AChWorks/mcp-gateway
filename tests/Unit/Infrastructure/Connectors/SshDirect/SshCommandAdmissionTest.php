<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshCommandAdmission;
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
