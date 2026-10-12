<?php

namespace App\Application\Files;

use App\Application\Targets\SshTargetConnectionException;

/**
 * Verified, bounded private PHP stream. No persistent object store or transfer handles.
 * Accepts raw binary; no Base64 conversion of file contents.
 */
final class VerifiedTransferSpool
{
    private const BLOCK_BYTES = 65536;

    /**
     * @param  resource  $source
     * @return resource
     */
    public static function capture(mixed $source, int $expectedBytes, string $expectedHash, int $maxBytes, int $deadlineNs): mixed
    {
        if (! is_resource($source) || $expectedBytes < 0 || $expectedBytes > $maxBytes
            || preg_match('/^[a-f0-9]{64}$/D', $expectedHash) !== 1) {
            throw new SshTargetConnectionException('invalid_input');
        }

        // php://temp uses memory for the ordinary small case; securely
        // spills to an unlink-on-close temporary stream for larger files.
        $sink = fopen('php://temp/maxmemory:65536', 'w+b');
        if ($sink === false) {
            throw new SshTargetConnectionException('output_unavailable');
        }

        $hash = hash_init('sha256');
        $received = 0;

        try {
            do {
                if (hrtime(true) >= $deadlineNs) {
                    throw new SshTargetConnectionException('transfer_timed_out');
                }

                // Read at most the expected remainder plus ONE byte to detect
                // an overlong source without consuming unbounded attacker data.
                $length = min(self::BLOCK_BYTES, $expectedBytes - $received + 1);
                $chunk = fread($source, $length);
                if (! is_string($chunk)) {
                    throw new SshTargetConnectionException('input_unavailable');
                }
                if ($chunk === '') {
                    break;
                }
                $size = strlen($chunk);
                if ($received + $size > $expectedBytes || $received + $size > $maxBytes) {
                    throw new SshTargetConnectionException('input_changed');
                }
                hash_update($hash, $chunk);
                $cursor = 0;
                while ($cursor < $size) {
                    $written = fwrite($sink, substr($chunk, $cursor));
                    if (! is_int($written) || $written < 1) {
                        throw new SshTargetConnectionException('output_unavailable');
                    }
                    $cursor += $written;
                }
                $received += $size;
            } while (true);

            if ($received !== $expectedBytes
                || ! hash_equals($expectedHash, hash_final($hash))
                || fseek($sink, 0) !== 0) {
                throw new SshTargetConnectionException('input_changed');
            }

            return $sink;
        } catch (\Throwable $exception) {
            fclose($sink);
            throw $exception;
        }
    }

    /** @return resource */
    public static function empty(): mixed
    {
        $sink = fopen('php://temp/maxmemory:65536', 'w+b');
        if ($sink === false) {
            throw new SshTargetConnectionException('output_unavailable');
        }

        return $sink;
    }
}
