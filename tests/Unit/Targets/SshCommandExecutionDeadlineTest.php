<?php

namespace Tests\Unit\Targets;

use App\Application\Targets\SshCommandExecutionDeadline;
use RuntimeException;
use Tests\TestCase;

final class SshCommandExecutionDeadlineTest extends TestCase
{
    public function test_continuous_packet_processing_consumes_monotonic_budget_even_without_socket_waits(): void
    {
        $nowNs = 10_000_000_000;
        $deadline = new SshCommandExecutionDeadline(
            3, static function () use (&$nowNs): int {
                return $nowNs;
            },
        );

        self::assertSame(3, $deadline->remainingSocketSeconds());
        for ($packet = 0; $packet < 250; $packet++) {
            // Simulate 250 consecutive packets whose reads never block,
            // but whose callbacks/decoding collectively cost 2.5 seconds.
            $nowNs += 10_000_000;
            self::assertGreaterThanOrEqual(1, $deadline->remainingSocketSeconds());
        }

        self::assertSame(1, $deadline->remainingSocketSeconds());
        self::assertFalse($deadline->expired());

        $nowNs += 500_000_000;
        self::assertTrue($deadline->expired());
        $this->expectException(RuntimeException::class);
        $deadline->remainingSocketSeconds();
    }

    public function test_600_second_command_deadline_is_finite_and_601_is_rejected(): void
    {
        $now = 1_000_000_000;
        $deadline = new SshCommandExecutionDeadline(600, static function () use (&$now): int {
            return $now;
        });
        self::assertSame(600, $deadline->remainingSocketSeconds());
        $now += 599_100_000_000;
        self::assertSame(1, $deadline->remainingSocketSeconds());
        $now += 900_000_000;
        self::assertTrue($deadline->expired());
        $this->expectException(\InvalidArgumentException::class);
        new SshCommandExecutionDeadline(601);
    }

    public function test_socket_wait_is_clamped_to_remaining_elapsed_budget_not_restarted_per_packet(): void
    {
        $nowNs = 50_000_000_000;
        $deadline = new SshCommandExecutionDeadline(
            360, static function () use (&$nowNs): int {
                return $nowNs;
            },
        );

        self::assertSame(360, $deadline->remainingSocketSeconds());
        $nowNs += 100_500_000_000;
        self::assertSame(260, $deadline->remainingSocketSeconds());
        $nowNs += 259_400_000_000;
        self::assertSame(1, $deadline->remainingSocketSeconds());
        $nowNs += 100_000_000;
        self::assertTrue($deadline->expired());
        $this->expectException(RuntimeException::class);
        $deadline->remainingSocketSeconds();
    }
}
