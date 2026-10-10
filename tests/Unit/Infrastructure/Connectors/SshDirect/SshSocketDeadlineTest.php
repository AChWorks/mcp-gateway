<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshSocketDeadline;
use PHPUnit\Framework\TestCase;

final class SshSocketDeadlineTest extends TestCase
{
    public function test_transparent_socket_read_and_write_are_bounded_by_the_same_monotonic_deadline(): void
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertIsArray($sockets);
        [$socket, $peer] = $sockets;

        try {
            SshSocketDeadline::attach($socket, hrtime(true) + 100_000_000);
            fwrite($peer, 'incoming');
            self::assertSame('incoming', fread($socket, 8));
            fwrite($socket, 'outbound');
            self::assertSame('outbound', fread($peer, 8));
            usleep(120_000);
            try {
                @fwrite($socket, 'after-expiry');
                self::fail('Expired transfer must not send raw SSH bytes.');
            } catch (SshTargetConnectionException $e) {
                self::assertSame('transfer_timed_out', $e->reason);
            }
        } finally {
            fclose($socket);
            fclose($peer);
        }
    }

    public function test_expired_socket_filter_refuses_late_incoming_bytes(): void
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertIsArray($sockets);
        [$socket, $peer] = $sockets;

        try {
            SshSocketDeadline::attach($socket, hrtime(true) + 25_000_000);
            usleep(45_000);
            fwrite($peer, 'remote');
            try {
                @fread($socket, 6);
                self::fail('Expired transfer must not read raw SSH bytes.');
            } catch (SshTargetConnectionException $e) {
                self::assertSame('transfer_timed_out', $e->reason);
            }
        } finally {
            fclose($socket);
            fclose($peer);
        }
    }
}
