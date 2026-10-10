<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use php_user_filter;

/**
 * Socket-level monotonic budget for the INTRA-REQUEST streamed SFTP path.
 *
 * SFTP and SSH2 packet parsers are dependency-private. This transparent
 * stream filter makes the same deadline observable on every raw SSH read
 * and write, including authenticated negotiation and unsolicited replies.
 * Ordinary non-streaming SSH and SFTP calls do not install this filter.
 */
final class SshSocketDeadline extends php_user_filter
{
    private const NAME = 'achworks.ssh-sftp-stream-deadline.v1';

    /** @param resource $socket */
    public static function attach(mixed $socket, int $deadlineNs): void
    {
        if (! is_resource($socket) || $deadlineNs <= hrtime(true)) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }

        if (! in_array(self::NAME, stream_get_filters(), true)
            && ! stream_filter_register(self::NAME, self::class)) {
            throw new SshTargetConnectionException('transfer_unavailable');
        }

        if (@stream_filter_append($socket, self::NAME, STREAM_FILTER_READ, $deadlineNs) === false
            || @stream_filter_append($socket, self::NAME, STREAM_FILTER_WRITE, $deadlineNs) === false) {
            throw new SshTargetConnectionException('transfer_unavailable');
        }

        // Bound a stalled socket write independently of the PHP default
        // socket timeout. phpseclib sets finer per-READ timeouts itself.
        @stream_set_timeout($socket, 8);
    }

    /**
     * @param  resource  $in
     * @param  resource  $out
     */
    public function filter($in, $out, &$consumed, bool $closing): int
    {
        if (! is_int($this->params)) {
            throw new SshTargetConnectionException('transfer_unavailable');
        }

        // Never forward any buffered data after expiry, including while
        // closing the socket after an ambiguous remote write.
        $expired = hrtime(true) >= $this->params;
        if ($expired && ! $closing) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }

        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed += $bucket->datalen;
            if ($expired) {
                continue;
            }

            if (hrtime(true) >= $this->params) {
                throw new SshTargetConnectionException('transfer_timed_out');
            }
            stream_bucket_append($out, $bucket);
        }

        return PSFS_PASS_ON;
    }
}
