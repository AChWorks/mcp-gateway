<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshFileAdmission;
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
