<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshSubsystemOnlySftp;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class SshSftpFrameBudgetTest extends TestCase
{
    private function probe(): array
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('versionSeen')->setValue($connection, true);

        return [$connection, $reflection];
    }

    private function request(object $connection, ReflectionClass $reflection, int $id, int $type = 5): void
    {
        $reflection->getMethod('trackSftpRequest')->invoke($connection, pack('NCN', 5, $type, $id));
    }

    private function response(object $connection, ReflectionClass $reflection, int $id, int $type = 103): void
    {
        $reflection->getMethod('verifySftpFrames')->invoke($connection, pack('NCN', 5, $type, $id));
    }

    public function test_fragmented_and_out_of_order_valid_replies_are_accepted(): void
    {
        [$connection, $reflection] = $this->probe();
        foreach ([0, 1, 2] as $id) {
            $this->request($connection, $reflection, $id);
        }
        $stream = pack('NCN', 5, 103, 2).pack('NCN', 5, 103, 0).pack('NCN', 5, 103, 1);
        $parse = $reflection->getMethod('verifySftpFrames');
        $parse->invoke($connection, substr($stream, 0, 2));
        $parse->invoke($connection, substr($stream, 2, 11));
        $parse->invoke($connection, substr($stream, 13));

        self::assertSame([], $reflection->getProperty('pendingRequestIds')->getValue($connection));
        self::assertSame(3, $reflection->getProperty('batchFrames')->getValue($connection));
        self::assertSame(27, $reflection->getProperty('batchBytes')->getValue($connection));

        // More chunks are allowed: budget resets only after all issued replies.
        $this->request($connection, $reflection, 0);
        $this->response($connection, $reflection, 0);
        self::assertSame(1, $reflection->getProperty('batchFrames')->getValue($connection));
    }

    public function test_unknown_and_duplicate_ids_fail_before_dependency_buffering(): void
    {
        [$connection, $reflection] = $this->probe();
        $this->request($connection, $reflection, 0);
        try {
            $this->response($connection, $reflection, 0x60000001);
            self::fail('Wrong ID accepted');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
        }

        [$connection, $reflection] = $this->probe();
        $this->request($connection, $reflection, 0);
        $this->response($connection, $reflection, 0);
        try {
            $this->response($connection, $reflection, 0);
            self::fail('Duplicate reply accepted');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
        }
    }

    public function test_all_public_operation_ids_and_types_are_protected(): void
    {
        // LSTAT / READDIR / WRITE / SETSTAT do not receive special exemptions.
        foreach ([7, 4, 6, 9] as $requestType) {
            [$connection, $reflection] = $this->probe();
            $this->request($connection, $reflection, 1, $requestType);
            $this->response($connection, $reflection, 1, 101); // STATUS

            try {
                $this->response($connection, $reflection, 888, 101);
                self::fail('Unsolicited reply accepted for request type '.$requestType);
            } catch (SshTargetConnectionException $e) {
                self::assertSame('sftp_response_budget_exceeded', $e->reason);
            }
        }
    }

    public function test_finite_aggregate_bytes_even_for_individually_valid_frames(): void
    {
        [$connection, $reflection] = $this->probe();
        foreach (range(0, 31) as $id) {
            $this->request($connection, $reflection, $id);
        }
        $parse = $reflection->getMethod('verifySftpFrames');
        try {
            for ($id = 0; $id < 32; $id++) {
                $parse->invoke($connection, pack('NCN', 125000, 103, $id).str_repeat('x', 124995));
            }
            self::fail('Aggregate bytes not bounded');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
            self::assertLessThan(19, $reflection->getProperty('batchFrames')->getValue($connection));
        }
    }

    public function test_single_frame_size_and_inflight_request_count_are_bounded(): void
    {
        [$connection, $reflection] = $this->probe();
        $this->request($connection, $reflection, 1);
        try {
            $reflection->getMethod('verifySftpFrames')->invoke($connection, pack('N', 256 * 1024 + 1));
            self::fail('Oversize frame accepted');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_frame_too_large', $e->reason);
        }

        [$connection, $reflection] = $this->probe();
        foreach (range(0, 63) as $id) {
            $this->request($connection, $reflection, $id);
        }
        try {
            $this->request($connection, $reflection, 64);
            self::fail('Unbounded pending replies accepted');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('sftp_response_budget_exceeded', $e->reason);
        }
    }

    public function test_init_version_only_precedes_regular_request_ids(): void
    {
        $reflection = new ReflectionClass(SshSubsystemOnlySftp::class);
        $connection = $reflection->newInstanceWithoutConstructor();
        $reflection->getMethod('trackSftpRequest')->invoke($connection, pack('NC', 1, 1));
        $reflection->getMethod('verifySftpFrames')->invoke($connection, pack('NCN', 5, 2, 3));
        self::assertTrue($reflection->getProperty('versionSeen')->getValue($connection));

        $this->request($connection, $reflection, 1, 17);
        $this->response($connection, $reflection, 1, 105);
        self::assertSame([], $reflection->getProperty('pendingRequestIds')->getValue($connection));
    }

    public function test_deadline_armed_during_authentication_is_not_reset_by_subsequent_sftp_calls(): void
    {
        [$connection, $reflection] = $this->probe();
        $deadline = hrtime(true) + 10_000_000_000;
        $connection->startOperationDeadline($deadline);

        self::assertSame('accepted', $connection->withTransferDeadline($deadline, static fn (): string => 'accepted'));
        self::assertSame($deadline, $reflection->getProperty('transferDeadlineNs')->getValue($connection));

        try {
            $connection->withTransferDeadline($deadline + 1, static fn (): string => 'incorrect');
            self::fail('A nested SFTP operation must not extend the original deadline.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('transfer_timed_out', $e->reason);
        }

        $reflection->getProperty('transferDeadlineNs')->setValue($connection, hrtime(true) - 1);
        try {
            $reflection->getMethod('enforceTransferDeadline')->invoke($connection);
            self::fail('Expired operation allowed');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('transfer_timed_out', $e->reason);
        }
    }
}
