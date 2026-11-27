<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;

/**
 * Deadline-aware view of an already connected, peer-verified TCP socket.
 *
 * phpseclib reads identification with stream_select + stream_get_line, then
 * private binary packet reads. PHP cannot select a filtered TCP stream.
 * Cast only to the original socket for select; every actual read/write uses
 * that same socket and the immutable monotonic deadline. No proxy process,
 * additional connection, DNS lookup, or vendor-private packet replacement.
 *
 * PHP's stream wrapper API owns the public stream_* methods and context.
 */
final class SshSocketDeadline
{
    private const SCHEME = 'achworks-ssh-deadline';

    private static bool $registered = false;

    /** @var resource */
    public $context;

    /** @var resource */
    private $socket;

    private int $deadlineNs;

    private int $timeoutNs;

    /** @param resource $socket
     * @return resource
     */
    public static function wrap(mixed $socket, int $deadlineNs, int $timeoutSeconds): mixed
    {
        if ($deadlineNs <= hrtime(true)) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }
        if (! self::$registered) {
            if (in_array(self::SCHEME, stream_get_wrappers(), true)
                || ! stream_wrapper_register(self::SCHEME, self::class)) {
                throw new SshTargetConnectionException('transfer_unavailable');
            }
            self::$registered = true;
        }

        $stream = @fopen(self::SCHEME.'://connection', 'r+b', false, stream_context_create([
            self::SCHEME => ['socket' => $socket, 'deadline' => $deadlineNs, 'timeout' => $timeoutSeconds],
        ]));
        if (! is_resource($stream)) {
            throw new SshTargetConnectionException('transfer_unavailable');
        }

        // PHP initially advertises user streams as seekable, even when the
        // wrapper has no seek method. Its first read-to-write transition
        // then attempts a seek and discards unread buffered packet bytes.
        // Discover the non-seekable capability before any network I/O;
        // this failed seek marks the stream as full-duplex/non-seekable.
        if (stream_get_meta_data($stream)['seekable']) {
            // The capability probe is expected to report this one warning.
            // Do not suppress unrelated PHP/runtime diagnostics.
            $previous = set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$previous): bool {
                if ($severity === E_WARNING && $message === 'fseek(): Stream does not support seeking') {
                    return true;
                }

                return is_callable($previous) && $previous($severity, $message, $file, $line) !== false;
            }, E_WARNING);
            try {
                fseek($stream, 1, SEEK_CUR);
            } finally {
                restore_error_handler();
            }
        }
        if (stream_get_meta_data($stream)['seekable']) {
            fclose($stream);
            throw new SshTargetConnectionException('transfer_unavailable');
        }

        return $stream;
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $settings = stream_context_get_options($this->context)[self::SCHEME] ?? [];
        $socket = $settings['socket'] ?? null;
        $deadline = $settings['deadline'] ?? null;
        $timeout = $settings['timeout'] ?? null;
        if ($path !== self::SCHEME.'://connection' || $mode !== 'r+b'
            || ! is_resource($socket) || ! is_int($deadline) || ! is_int($timeout)
            || $deadline <= hrtime(true) || $timeout < 1
            || ! stream_set_blocking($socket, false)) {
            return false;
        }

        $this->socket = $socket;
        $this->deadlineNs = $deadline;
        $this->timeoutNs = $timeout * 1_000_000_000;

        return true;
    }

    /** @return resource|false */
    public function stream_cast(int $castAs): mixed
    {
        // No raw descriptor export except PHP's select implementation.
        return $castAs === STREAM_CAST_FOR_SELECT ? $this->socket : false;
    }

    public function stream_set_option(int $option, int $arg1, int $arg2): bool
    {
        if ($option !== STREAM_OPTION_READ_TIMEOUT) {
            return false;
        }
        // Keep the library's shorter waits, but never extend the absolute
        // operation budget when it resets its own timeout for another packet.
        $this->timeoutNs = max(1, $arg1 * 1_000_000_000 + $arg2 * 1000);

        return true;
    }

    public function stream_read(int $count): string|false
    {
        $this->assertAvailable();
        if ($count === 0) {
            return '';
        }
        $until = min($this->deadlineNs, hrtime(true) + $this->timeoutNs);
        do {
            $data = @fread($this->socket, $count);
            $this->assertAvailable();
            if ($data === false || $data !== '' || feof($this->socket)) {
                return $data;
            }
        } while ($this->wait(true, $until));

        return '';
    }

    public function stream_write(#[\SensitiveParameter] string $data): int|false
    {
        $this->assertAvailable();
        if ($data === '') {
            return 0;
        }
        $until = min($this->deadlineNs, hrtime(true) + $this->timeoutNs);
        do {
            $count = @fwrite($this->socket, $data);
            $this->assertAvailable();
            if ($count === false || $count > 0 || feof($this->socket)) {
                return $count;
            }
        } while ($this->wait(false, $until));

        return 0;
    }

    public function stream_eof(): bool
    {
        return ! is_resource($this->socket) || feof($this->socket);
    }

    public function stream_flush(): bool
    {
        return true;
    }

    public function stream_close(): void
    {
        if (is_resource($this->socket)) {
            fclose($this->socket);
        }
    }

    /** @return array<mixed>|false */
    public function stream_stat(): array|false
    {
        return fstat($this->socket);
    }

    private function wait(bool $reading, int $until): bool
    {
        $this->assertAvailable();
        $remaining = $until - hrtime(true);
        if ($remaining <= 0) {
            return false;
        }
        $read = $reading ? [$this->socket] : null;
        $write = $reading ? null : [$this->socket];
        $except = null;
        $micros = intdiv($remaining + 999, 1000);
        $ready = @stream_select($read, $write, $except, intdiv($micros, 1_000_000), $micros % 1_000_000);
        $this->assertAvailable();
        if ($ready === false) {
            throw new SshTargetConnectionException('transfer_unavailable');
        }

        return $ready > 0;
    }

    private function assertAvailable(): void
    {
        if (hrtime(true) >= $this->deadlineNs) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }
    }
}
