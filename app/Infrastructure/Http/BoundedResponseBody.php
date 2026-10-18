<?php

namespace App\Infrastructure\Http;

use RuntimeException;

final class BoundedResponseBody
{
    private const FILTER_NAME = 'mcp_gateway.response_body_limit';

    /** @var resource|null */
    private $stream = null;

    /** @var resource|null */
    private $writeFilter = null;

    private bool $ownsStream = true;

    private int $decodedBytes = 0;

    private bool $limitExceeded = false;

    private ?string $limitPhase = null;

    private ?int $observedBytes = null;

    /**
     * For signed-file downloads, borrow the caller's ONLY writable private
     * spool; do not create a second response buffer or copy the full body.
     * The caller owns closing and discarding incomplete/invalid file bytes.
     *
     * @param  resource|null  $borrowedStream
     */
    public function __construct(private readonly int $maxBytes, mixed $borrowedStream = null)
    {
        if ($this->maxBytes < 1) {
            throw new RuntimeException('Response body limit must be positive.');
        }

        $this->registerFilter();

        if ($borrowedStream !== null) {
            if (! is_resource($borrowedStream)
                || stream_get_meta_data($borrowedStream)['seekable'] !== true
                || ftell($borrowedStream) !== 0
                || ($stat = fstat($borrowedStream)) === false
                || $stat['size'] !== 0) {
                throw new RuntimeException('A fresh seekable private file stream is required.');
            }
        }

        // Ordinary in-memory responses retain their existing buffering.
        // Only the FileParams streaming path uses an externally owned spool.
        $stream = $borrowedStream ?? fopen('php://temp', 'w+b');
        if ($stream === false) {
            throw new RuntimeException('Unable to create bounded response stream.');
        }

        $filter = stream_filter_append($stream, self::FILTER_NAME, STREAM_FILTER_WRITE, $this);
        if ($filter === false) {
            if ($borrowedStream === null) {
                fclose($stream);
            }

            throw new RuntimeException('Unable to attach bounded response stream filter.');
        }

        $this->stream = $stream;
        $this->writeFilter = $filter;
        $this->ownsStream = $borrowedStream === null;
    }

    /** @return resource */
    public function stream()
    {
        if (! is_resource($this->stream)) {
            throw new RuntimeException('Bounded response stream is closed.');
        }

        return $this->stream;
    }

    public function progress(
        int $downloadTotal,
        int $downloadNow,
        int $uploadTotal,
        int $uploadNow,
    ): bool {
        if ($downloadNow > $this->maxBytes) {
            $this->markLimitExceeded('wire_progress', $downloadNow);

            return true;
        }

        return false;
    }

    public function acceptDecodedBytes(int $bytes): bool
    {
        if ($bytes < 0 || $bytes > $this->maxBytes - $this->decodedBytes) {
            $this->markLimitExceeded('decoded_body', $this->decodedBytes + max(0, $bytes));

            return false;
        }

        $this->decodedBytes += $bytes;

        return true;
    }

    public function limitExceeded(): bool
    {
        return $this->limitExceeded;
    }

    public function decodedBytes(): int
    {
        return $this->decodedBytes;
    }

    public function limitPhase(): ?string
    {
        return $this->limitPhase;
    }

    public function observedBytes(): ?int
    {
        return $this->observedBytes;
    }

    private function markLimitExceeded(string $phase, int $observedBytes): void
    {
        $this->limitExceeded = true;
        $this->limitPhase ??= $phase;
        $this->observedBytes ??= $observedBytes;
    }

    public function close(): void
    {
        // Remove our write limiter without closing the caller-owned stream;
        // the caller still needs that SAME verified spool for SHA-256 and
        // destination delivery. Ordinary response streams remain owned here.
        if (is_resource($this->writeFilter)) {
            stream_filter_remove($this->writeFilter);
        }
        $this->writeFilter = null;

        if ($this->ownsStream && is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }

    public function __destruct()
    {
        $this->close();
    }

    private function registerFilter(): void
    {
        if (in_array(self::FILTER_NAME, stream_get_filters(), true)) {
            return;
        }

        if (! class_exists(BoundedResponseBodyFilter::class)
            || ! stream_filter_register(self::FILTER_NAME, BoundedResponseBodyFilter::class)) {
            throw new RuntimeException('Unable to register bounded response stream filter.');
        }
    }
}
