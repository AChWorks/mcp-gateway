<?php

namespace Tests\Unit\Infrastructure\Connectors\Relay;

use App\Infrastructure\Connectors\Relay\Socks5NumericDialer;
use RuntimeException;
use Tests\TestCase;

final class Socks5NumericDialerTest extends TestCase
{
    public function test_rejects_name_host_invalid_port_and_timeout_before_any_connection(): void
    {
        $dialer = new Socks5NumericDialer;
        foreach ([
            [49103, 'metadata.google.internal', 443, 5],
            [49103, '1.1.1.1', 0, 5],
            [0, '1.1.1.1', 443, 5],
            [49103, '1.1.1.1', 443, 0],
        ] as $args) {
            try {
                $dialer->connect(...$args);
                self::fail('Accepted an invalid SOCKS5 endpoint.');
            } catch (RuntimeException $exception) {
                self::assertSame('relay_endpoint_invalid', $exception->getMessage());
            }
        }
    }

    public function test_ipv4_connect_sends_only_numeric_address_and_preserves_tunnel_stream(): void
    {
        $this->fixture('203.0.113.42', 443, 1, 4);
    }

    public function test_ipv6_connect_sends_only_numeric_address_and_preserves_tunnel_stream(): void
    {
        $this->fixture('2001:db8::42', 8443, 4, 16);
    }

    public function test_socks5_reply_rejection_is_fail_closed(): void
    {
        if (! function_exists('pcntl_fork')) {
            $this->markTestSkipped('Bounded local socket fixture needs pcntl.');
        }
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertIsResource($server);
        $port = (int) substr((string) stream_socket_get_name($server, false), strrpos((string) stream_socket_get_name($server, false), ':') + 1);
        $child = pcntl_fork();
        self::assertNotSame(-1, $child);
        if ($child === 0) {
            $peer = stream_socket_accept($server, 3);
            if (is_resource($peer)) {
                fread($peer, 3);
                fwrite($peer, "\x05\x00");
                fread($peer, 10);
                fwrite($peer, "\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x00");
                fclose($peer);
            }
            exit(0);
        }
        fclose($server);
        try {
            $this->expectExceptionMessage('relay_connect_denied');
            (new Socks5NumericDialer)->connect($port, '203.0.113.42', 443, 3);
        } finally {
            pcntl_waitpid($child, $status);
        }
    }

    public function test_stalled_socks_handshake_ends_within_one_absolute_budget(): void
    {
        if (! function_exists('pcntl_fork')) {
            $this->markTestSkipped('Bounded local socket fixture needs pcntl.');
        }

        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        self::assertIsResource($server);
        $address = (string) stream_socket_get_name($server, false);
        $port = (int) substr($address, strrpos($address, ':') + 1);
        $child = pcntl_fork();
        self::assertNotSame(-1, $child);
        if ($child === 0) {
            $peer = stream_socket_accept($server, 3);
            if (is_resource($peer)) {
                fread($peer, 3);
                // A partial SOCKS5 reply cannot buy a fresh full timeout.
                fwrite($peer, "\x05");
                usleep(1_300_000);
                fclose($peer);
            }
            exit(0);
        }
        fclose($server);

        $start = microtime(true);
        try {
            (new Socks5NumericDialer)->connect($port, '203.0.113.42', 443, 1);
            self::fail('Accepted an incomplete SOCKS5 greeting.');
        } catch (RuntimeException $exception) {
            self::assertSame('relay_handshake_failed', $exception->getMessage());
        } finally {
            pcntl_waitpid($child, $status);
            self::assertLessThan(2.5, microtime(true) - $start);
        }
    }

    private function fixture(string $destination, int $port, int $expectedType, int $ipLength): void
    {
        if (! function_exists('pcntl_fork')) {
            $this->markTestSkipped('Bounded local socket fixture needs pcntl.');
        }
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertIsResource($server);
        $address = (string) stream_socket_get_name($server, false);
        $listenPort = (int) substr($address, strrpos($address, ':') + 1);
        $child = pcntl_fork();
        self::assertNotSame(-1, $child);
        if ($child === 0) {
            $peer = stream_socket_accept($server, 3);
            if (! is_resource($peer)) {
                exit(2);
            }
            stream_set_timeout($peer, 3);
            $hello = fread($peer, 3);
            fwrite($peer, "\x05\x00");
            $request = fread($peer, 4 + $ipLength + 2);
            $valid = $hello === "\x05\x01\x00"
                && strlen($request) === 4 + $ipLength + 2
                && ord($request[3]) === $expectedType
                && substr($request, 4, $ipLength) === inet_pton($destination)
                && unpack('n', substr($request, -2))[1] === $port;
            if (! $valid) {
                fclose($peer);
                exit(3);
            }
            fwrite($peer, "\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00");
            if (fread($peer, 4) !== 'PING') {
                fclose($peer);
                exit(4);
            }
            fwrite($peer, 'PONG');
            fclose($peer);
            fclose($server);
            exit(0);
        }
        fclose($server);

        try {
            $stream = (new Socks5NumericDialer)->connect($listenPort, $destination, $port, 3);
            self::assertIsResource($stream);
            fwrite($stream, 'PING');
            self::assertSame('PONG', fread($stream, 4));
            fclose($stream);
        } finally {
            pcntl_waitpid($child, $status);
            self::assertTrue(pcntl_wifexited($status));
            self::assertSame(0, pcntl_wexitstatus($status));
        }
    }
}
