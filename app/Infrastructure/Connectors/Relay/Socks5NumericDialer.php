<?php

namespace App\Infrastructure\Connectors\Relay;

use RuntimeException;

/**
 * SOCKS5 CONNECT to one caller-approved numeric TCP endpoint.
 *
 * The relay control process is a separate, operator-managed OpenSSH -D
 * tunnel. This class never resolves destination names or accepts untrusted
 * proxy hosts. Reachability through a relay is NOT proof of remote peer
 * identity; consumers must still verify TLS certificates / SSH host keys.
 */
final class Socks5NumericDialer
{
    /**
     * @return resource
     */
    public function connect(
        int $loopbackPort, string $destinationIp, int $destinationPort,
        int $timeoutSeconds = 5,
    ): mixed {
        $packed = @inet_pton($destinationIp);
        if ($loopbackPort < 1024 || $loopbackPort > 65535
            || $destinationPort < 1 || $destinationPort > 65535
            || $timeoutSeconds < 1 || $timeoutSeconds > 120
            || $packed === false || ! in_array(strlen($packed), [4, 16], true)) {
            throw new RuntimeException('relay_endpoint_invalid');
        }

        // One absolute handshake budget. A peer that trickles bytes must not
        // extend the deadline by receiving a fresh timeout on every read.
        $deadlineNs = hrtime(true) + ($timeoutSeconds * 1_000_000_000);
        $errorNumber = 0;
        $errorText = '';
        $socket = @stream_socket_client(
            'tcp://127.0.0.1:'.$loopbackPort, $errorNumber, $errorText,
            $timeoutSeconds, STREAM_CLIENT_CONNECT,
        );
        if (! is_resource($socket)) {
            throw new RuntimeException('relay_unavailable');
        }

        try {
            $peer = @stream_socket_get_name($socket, true);
            if ($peer !== '127.0.0.1:'.$loopbackPort) {
                throw new RuntimeException('relay_peer_mismatch');
            }
            $this->write($socket, "\x05\x01\x00", $deadlineNs);
            if ($this->read($socket, 2, $deadlineNs) !== "\x05\x00") {
                throw new RuntimeException('relay_handshake_failed');
            }

            $atype = strlen($packed) === 4 ? "\x01" : "\x04";
            $this->write($socket, "\x05\x01\x00".$atype.$packed.pack('n', $destinationPort), $deadlineNs);
            $reply = $this->read($socket, 4, $deadlineNs);
            if (substr($reply, 0, 1) !== "\x05"
                || substr($reply, 2, 1) !== "\x00"
                || ord($reply[1]) !== 0) {
                throw new RuntimeException('relay_connect_denied');
            }

            // Consume the entire SOCKS response; it is NOT an identity proof
            // for the destination host. No domain is sent in our CONNECT.
            $size = match (ord($reply[3])) {
                1 => 4,
                4 => 16,
                3 => ord($this->read($socket, 1, $deadlineNs)),
                default => throw new RuntimeException('relay_handshake_failed'),
            };
            $this->read($socket, $size + 2, $deadlineNs);

            // The handshake used a shrinking deadline; do not leak its
            // near-zero stream timeout into subsequent SSH KEX/login.
            // phpseclib will apply its own operation-specific budgets.
            stream_set_timeout($socket, $timeoutSeconds);

            return $socket;
        } catch (RuntimeException $exception) {
            fclose($socket);

            throw $exception;
        } catch (\Throwable) {
            fclose($socket);

            throw new RuntimeException('relay_handshake_failed');
        }
    }

    /** @param resource $socket */
    private function write(mixed $socket, string $data, int $deadlineNs): void
    {
        $offset = 0;
        $length = strlen($data);
        while ($offset < $length) {
            $this->applyRemainingTimeout($socket, $deadlineNs);
            $sent = @fwrite($socket, substr($data, $offset));
            if (! is_int($sent) || $sent === 0 || ($this->timedOut($socket))) {
                throw new RuntimeException('relay_handshake_failed');
            }
            $offset += $sent;
        }
    }

    /** @param resource $socket */
    private function read(mixed $socket, int $size, int $deadlineNs): string
    {
        $result = '';
        while (strlen($result) < $size) {
            $this->applyRemainingTimeout($socket, $deadlineNs);
            $next = @fread($socket, $size - strlen($result));
            if (! is_string($next) || $next === '' || $this->timedOut($socket)) {
                throw new RuntimeException('relay_handshake_failed');
            }
            $result .= $next;
        }

        return $result;
    }

    /** @param resource $socket */
    private function applyRemainingTimeout(mixed $socket, int $deadlineNs): void
    {
        $remainingNs = $deadlineNs - hrtime(true);
        if ($remainingNs <= 0) {
            throw new RuntimeException('relay_handshake_failed');
        }

        $seconds = intdiv($remainingNs, 1_000_000_000);
        $microseconds = intdiv($remainingNs % 1_000_000_000, 1000);
        // Avoid a zero microsecond poll when less than one microsecond remains.
        stream_set_timeout($socket, $seconds, max(1, $microseconds));
    }

    /** @param resource $socket */
    private function timedOut(mixed $socket): bool
    {
        $meta = stream_get_meta_data($socket);

        return $meta['timed_out'];
    }
}
