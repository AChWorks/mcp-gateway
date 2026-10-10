<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshSubsystemOnlySftp;
use phpseclib4\Net\SFTP;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class SshSftpFrameBudgetTest extends TestCase
{
    public function test_split_frame_headers_and_multi_frame_fragments_preserve_state(): void
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection, 0);
        $reflection->getProperty('readBatchIssuedIds')->setValue($connection, [0 => true, 1 => true, 2 => true]);

        $parse = $reflection->getMethod('verifySftpFrames');
        $first = pack('NCN', 5, 103, 1);
        $second = pack('NCN', 5, 103, 0);
        $third = pack('NCN', 5, 103, 2);
        $parse->invoke($connection, substr($first, 0, 2));
        $parse->invoke($connection, substr($first, 2).$second.substr($third, 0, 6));
        $parse->invoke($connection, substr($third, 6));

        self::assertSame('', $reflection->getProperty('incomingLengthBytes')->getValue($connection));
        self::assertSame(0, $reflection->getProperty('incomingFrameRemaining')->getValue($connection));
        self::assertSame(3, $reflection->getProperty('readBatchResponses')->getValue($connection));
        self::assertSame(27, $reflection->getProperty('readBatchResponseBytes')->getValue($connection));
        self::assertCount(3, $reflection->getProperty('readBatchRepliedIds')->getValue($connection));
    }

    public function test_unissued_or_duplicate_read_ids_fail_before_private_request_buffer(): void
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection, 0);
        $reflection->getProperty('readBatchIssuedIds')->setValue($connection, [0 => true, 1 => true]);
        $parse = $reflection->getMethod('verifySftpFrames');

        try {
            $parse->invoke($connection, pack('NCN', 5, 103, 0x60000001));
            self::fail('Unissued request ID must be rejected before buffering.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
        }

        $connection2 = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection2, 0);
        $reflection->getProperty('readBatchIssuedIds')->setValue($connection2, [0 => true]);
        $parse->invoke($connection2, pack('NCN', 5, 103, 0));
        try {
            $parse->invoke($connection2, pack('NCN', 5, 103, 0));
            self::fail('Duplicated response ID must not survive another read batch.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
        }
    }

    public function test_next_read_batch_cannot_reset_tracking_of_unanswered_previous_ids(): void
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection, 1024);
        $reflection->getProperty('readBatchIssuedIds')->setValue($connection, [0 => true, 1 => true]);
        $reflection->getProperty('readBatchRepliedIds')->setValue($connection, [0 => true]);

        $channel = (new ReflectionClass(SFTP::class))->getConstant('CHANNEL');
        self::assertIsInt($channel);
        try {
            $reflection->getMethod('send_channel_packet')->invoke(
                $connection, $channel, pack('NCN', 5, 5, 0),
            );
            self::fail('New READ id=0 must not erase pending predecessor budget.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
        }
    }

    public function test_many_legal_length_issued_responses_still_hit_aggregate_byte_limit(): void
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('readBatchResponseBytes')->setValue($connection, 0);
        $reflection->getProperty('readBatchIssuedIds')->setValue(
            $connection, array_fill_keys(range(0, 31), true),
        );
        $parse = $reflection->getMethod('verifySftpFrames');

        try {
            for ($i = 0; $i < 32; $i++) {
                // Every frame is below 256KiB and carries a legitimately
                // issued unique ID, but a hostile server over-delivers data.
                $frame = pack('NCN', 125000, 103, $i).str_repeat('L', 124995);
                $parse->invoke($connection, $frame);
            }
            self::fail('Aggregate buffered replies must not consume unbounded PHP memory.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
            self::assertLessThan(19, $reflection->getProperty('readBatchResponses')->getValue($connection));
        }
    }
}
