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
            $socket = SshSocketDeadline::wrap($socket, hrtime(true) + 100_000_000, 1);
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

    public function test_expired_socket_refuses_late_incoming_bytes(): void
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertIsArray($sockets);
        [$socket, $peer] = $sockets;

        try {
            $socket = SshSocketDeadline::wrap($socket, hrtime(true) + 25_000_000, 1);
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

    public function test_select_and_buffered_identification_remain_compatible_with_the_original_socket(): void
    {
        $listener = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($listener);
        $socket = stream_socket_client('tcp://'.stream_socket_get_name($listener, false));
        self::assertIsResource($socket);
        $peer = stream_socket_accept($listener, 1);
        self::assertIsResource($peer);
        $stream = SshSocketDeadline::wrap($socket, hrtime(true) + 1_000_000_000, 1);
        try {
            fwrite($peer, "notice\r\nSSH-2.0-fixture\r\nfirst-packet");
            $read = [$stream];
            $write = $except = null;
            self::assertSame(1, stream_select($read, $write, $except, 0, 100_000));
            self::assertSame("notice\r", stream_get_line($stream, 255, "\n"));
            $read = [$stream];
            self::assertSame(1, stream_select($read, $write, $except, 0, 100_000));
            self::assertSame("SSH-2.0-fixture\r", stream_get_line($stream, 255, "\n"));
            self::assertSame('first-packet', stream_get_contents($stream, 12));
        } finally {
            fclose($stream);
            self::assertFalse(is_resource($socket), 'The wrapper owns the same original socket.');
            fclose($peer);
            fclose($listener);
        }
    }

    public function test_library_timeout_reset_cannot_extend_a_blocked_write(): void
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertIsArray($sockets);
        [$socket, $peer] = $sockets;
        $started = hrtime(true);
        $stream = SshSocketDeadline::wrap($socket, $started + 150_000_000, 1);
        try {
            self::assertTrue(stream_set_timeout($stream, 8));
            // Peer deliberately does not drain its finite socket buffer.
            @fwrite($stream, str_repeat('x', 2 * 1024 * 1024));
            self::fail('A blocked write must stop at the original deadline.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('transfer_timed_out', $exception->reason);
            self::assertLessThan(0.75, (hrtime(true) - $started) / 1_000_000_000);
        } finally {
            fclose($stream);
            fclose($peer);
        }
    }
}
