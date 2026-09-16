<?php

namespace App\Infrastructure\Http;

use RuntimeException;

final class BoundedResponseBody
{
    private const FILTER_NAME = 'mcp_gateway.response_body_limit';

    /** @var resource|null */
    private $stream = null;

    private int $decodedBytes = 0;

    private bool $limitExceeded = false;

    public function __construct(private readonly int $maxBytes)
    {
        if ($this->maxBytes < 1) {
            throw new RuntimeException('Response body limit must be positive.');
        }

        $this->registerFilter();

        $stream = fopen('php://temp', 'w+');
        if ($stream === false) {
            throw new RuntimeException('Unable to create bounded response stream.');
        }

        $filter = stream_filter_append($stream, self::FILTER_NAME, STREAM_FILTER_WRITE, $this);
        if ($filter === false) {
            fclose($stream);

            throw new RuntimeException('Unable to attach bounded response stream filter.');
        }

        $this->stream = $stream;
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
            $this->limitExceeded = true;

            return true;
        }

        return false;
    }

    public function acceptDecodedBytes(int $bytes): bool
    {
        if ($bytes < 0 || $bytes > $this->maxBytes - $this->decodedBytes) {
            $this->limitExceeded = true;

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

    public function close(): void
    {
        if (is_resource($this->stream)) {
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
