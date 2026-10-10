<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use Closure;
use phpseclib4\Net\SFTP;

/**
 * Fail-closed SFTP framing and per-stream deadline boundary for the locked
 * phpseclib 4.0.2 runtime. No implicit fallback to SSH shell execution.
 *
 * Upstream SFTP::get_sftp_packet() is private, and its 256 KiB check stops
 * applying after request IDs are enabled. This class inspects the complete
 * logical byte stream at the protected SSH channel boundary BEFORE upstream
 * appends the received bytes to its private packet_buffer.
 */
final class SshSubsystemOnlySftp extends SFTP
{
    private const MAX_SFTP_FRAME_PAYLOAD = 256 * 1024;

    private string $incomingLengthBytes = '';

    private int $incomingFrameRemaining = 0;

    private ?int $transferDeadlineNs = null;

    /** @param Closure():mixed $action */
    public function withTransferDeadline(int $deadlineNs, Closure $action): mixed
    {
        if ($this->transferDeadlineNs !== null || $deadlineNs <= hrtime(true)) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }

        $this->transferDeadlineNs = $deadlineNs;
        try {
            return $action();
        } finally {
            $this->transferDeadlineNs = null;
        }
    }

    protected function get_channel_packet(int $client_channel, bool $skip_extended = false): string|bool
    {
        // SFTP::get_sftp_packet() resets curTimeout for every queued STATUS
        // reply. Re-clamp its socket wait against ONE monotonic deadline at
        // every request/response channel boundary, including after login.
        $this->enforceTransferDeadline();
        $result = parent::get_channel_packet($client_channel, $skip_extended);
        $this->enforceTransferDeadline();

        if ($client_channel === self::CHANNEL && is_string($result) && $result !== '') {
            $this->verifySftpFrames($result);
        }

        return $result;
    }

    protected function send_binary_packet(
        #[\SensitiveParameter] string $data,
        ?string $logged = null,
    ): void {
        // SSH_MSG_CHANNEL_REQUEST = 98; string request type "exec" follows
        // the four-byte channel id. This guards the exact locked dependency.
        if (strlen($data) >= 13 && ord($data[0]) === 98
            && substr($data, 5, 8) === "\0\0\0\4exec") {
            throw new SshTargetConnectionException('sftp_unavailable');
        }

        $this->enforceTransferDeadline();
        parent::send_binary_packet($data, $logged);
        $this->enforceTransferDeadline();
    }

    private function enforceTransferDeadline(): void
    {
        if ($this->transferDeadlineNs === null) {
            return;
        }

        $remaining = ($this->transferDeadlineNs - hrtime(true)) / 1_000_000_000;
        if ($remaining <= 0) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }
        // get_binary_packet() uses this value for the socket read budget.
        // Never permit the dependency's per-packet timeout reset to extend
        // beyond the original end-to-end stream deadline.
        if ($this->curTimeout === null || $this->curTimeout <= 0) {
            $this->curTimeout = $remaining;
        } else {
            $this->curTimeout = min($this->curTimeout, $remaining);
        }
    }

    /**
     * A single SSH channel-data fragment may split a frame header/payload or
     * contain multiple frames. Keep only the 4 header bytes and a counter.
     * The SSH transport independently caps one decrypted SSH packet at 0x9000;
     * this protects against accumulation of multiple packets into a malicious
     * multi-megabyte SFTP response.
     */
    private function verifySftpFrames(string $bytes): void
    {
        $offset = 0;
        $total = strlen($bytes);
        while ($offset < $total) {
            if ($this->incomingFrameRemaining > 0) {
                $consumed = min($this->incomingFrameRemaining, $total - $offset);
                $this->incomingFrameRemaining -= $consumed;
                $offset += $consumed;

                continue;
            }

            $needed = 4 - strlen($this->incomingLengthBytes);
            $taken = min($needed, $total - $offset);
            $this->incomingLengthBytes .= substr($bytes, $offset, $taken);
            $offset += $taken;

            if (strlen($this->incomingLengthBytes) === 4) {
                $payloadLength = unpack('Nsize', $this->incomingLengthBytes)['size'];
                $this->incomingLengthBytes = '';
                if ($payloadLength < 1 || $payloadLength > self::MAX_SFTP_FRAME_PAYLOAD) {
                    throw new SshTargetConnectionException('sftp_frame_too_large');
                }
                $this->incomingFrameRemaining = $payloadLength;
            }
        }
    }
}
