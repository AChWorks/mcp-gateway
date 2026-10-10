<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshSubsystemOnlySftp;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class SshSftpFrameBudgetTest extends TestCase
{
    public function test_split_frame_headers_and_multi_frame_fragments_preserve_state(): void
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection, 0);

        $parse = $reflection->getMethod('verifySftpFrames');
        $first = pack('NCN', 5, 103, 0);
        $second = pack('NCN', 5, 103, 1);
        $third = pack('NCN', 5, 103, 2);
        $parse->invoke($connection, substr($first, 0, 2));
        $parse->invoke($connection, substr($first, 2).$second.substr($third, 0, 6));
        $parse->invoke($connection, substr($third, 6));

        self::assertSame('', $reflection->getProperty('incomingLengthBytes')->getValue($connection));
        self::assertSame(0, $reflection->getProperty('incomingFrameRemaining')->getValue($connection));
        self::assertSame(3, $reflection->getProperty('readBatchResponses')->getValue($connection));
        self::assertSame(27, $reflection->getProperty('readBatchResponseBytes')->getValue($connection));
    }

    public function test_many_legal_length_responses_hit_aggregate_budget_not_php_memory_limit(): void
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection, 0);
        $parse = $reflection->getMethod('verifySftpFrames');
        $frame = pack('NCN', 5, 103, 0);

        try {
            for ($i = 0; $i < 66; $i++) {
                $parse->invoke($connection, $frame);
            }
            self::fail('A buffer of many tiny wrong-id packets must fail closed.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
            self::assertSame(65, $reflection->getProperty('readBatchResponses')->getValue($connection));
        }

        $connection2 = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection2, 0);
        $legal = pack('N', 250000).str_repeat('L', 250000);
        try {
            for ($i = 0; $i < 10; $i++) {
                $parse->invoke($connection2, $legal);
            }
            self::fail('Legal-size packets must still be bounded in aggregate bytes.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
            self::assertLessThan(11, $reflection->getProperty('readBatchResponses')->getValue($connection2));
        }
    }
}
