<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use Closure;
use phpseclib4\Net\SFTP;

/**
 * SFTP-only, bounded framing / request-ID tracking for pinned phpseclib 4.0.2.
 *
 * phpseclib's SFTP::get_sftp_packet() is private; after version negotiation
 * it does not enforce its 256 KiB frame limit, and its wrong-ID requestBuffer
 * has no aggregate bound. Validate at the SSH channel boundary BEFORE bytes
 * enter either dependency-private buffer, for every public SFTP operation.
 *
 * The finite budget resets per complete request batch, not per file/transfer.
 * This preserves legitimate multi-batch streaming and out-of-order replies.
 */
final class SshSubsystemOnlySftp extends SFTP
{
    private const MAX_SFTP_FRAME_PAYLOAD = 256 * 1024;

    private const MAX_BATCH_BYTES = 2 * 1024 * 1024;

    private const MAX_BATCH_FRAMES = 64;

    private const MAX_OUTSTANDING_REQUESTS = 64;

    private string $incomingLengthBytes = '';

    private int $incomingFrameRemaining = 0;

    private string $incomingFramePrefix = '';

    private bool $expectVersion = false;

    private bool $versionSeen = false;

    /** @var array<int,true> SFTP IDs whose replies have not fully arrived. */
    private array $pendingRequestIds = [];

    private int $batchBytes = 0;

    private int $batchFrames = 0;

    private ?int $transferDeadlineNs = null;

    /**
     * Arm before the first SSH handshake so a slow authentication cannot
     * restart the SFTP lifetime. A fresh connection owns exactly one budget.
     */
    public function startOperationDeadline(int $deadlineNs): void
    {
        if ($this->transferDeadlineNs !== null || $deadlineNs <= hrtime(true)) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }
        $this->transferDeadlineNs = $deadlineNs;
    }

    /** @param Closure():mixed $action */
    public function withTransferDeadline(int $deadlineNs, Closure $action): mixed
    {
        if ($deadlineNs <= hrtime(true)
            || ($this->transferDeadlineNs !== null && $this->transferDeadlineNs !== $deadlineNs)) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }

        $alreadyArmed = $this->transferDeadlineNs !== null;
        if (! $alreadyArmed) {
            $this->transferDeadlineNs = $deadlineNs;
        }
        try {
            return $action();
        } finally {
            if (! $alreadyArmed) {
                $this->transferDeadlineNs = null;
            }
        }
    }

    protected function send_channel_packet(
        int $client_channel,
        #[\SensitiveParameter] string $data,
    ): void {
        if ($client_channel === self::CHANNEL) {
            $this->trackSftpRequest($data);
        }

        $this->enforceTransferDeadline();
        parent::send_channel_packet($client_channel, $data);
        $this->enforceTransferDeadline();
    }

    protected function get_channel_packet(int $client_channel, bool $skip_extended = false): string|bool
    {
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
        // Reject phpseclib's implicit "exec sftp-server" shell fallback.
        if (strlen($data) >= 13 && ord($data[0]) === 98
            && substr($data, 5, 8) === "\0\0\0\4exec") {
            throw new SshTargetConnectionException('sftp_unavailable');
        }

        $this->enforceTransferDeadline();
        parent::send_binary_packet($data, $logged);
        $this->enforceTransferDeadline();
    }

    private function trackSftpRequest(string $data): void
    {
        if (strlen($data) < 5 || unpack('Nsize', substr($data, 0, 4))['size'] !== strlen($data) - 4) {
            throw new SshTargetConnectionException('sftp_response_budget_exceeded');
        }

        $type = ord($data[4]);
        if ($type === 1) { // SSH_FXP_INIT has no request ID.
            if ($this->expectVersion || $this->versionSeen || $this->pendingRequestIds !== []) {
                throw new SshTargetConnectionException('sftp_response_budget_exceeded');
            }
            $this->expectVersion = true;

            return;
        }

        if (! $this->versionSeen || $this->expectVersion || strlen($data) < 9) {
            throw new SshTargetConnectionException('sftp_response_budget_exceeded');
        }

        $id = unpack('Nid', substr($data, 5, 4))['id'];
        if ($this->pendingRequestIds === []) {
            // Previous batch is complete. A new batch gets a fresh budget.
            $this->batchBytes = 0;
            $this->batchFrames = 0;
        }

        if (isset($this->pendingRequestIds[$id])
            || count($this->pendingRequestIds) >= self::MAX_OUTSTANDING_REQUESTS) {
            throw new SshTargetConnectionException('sftp_response_budget_exceeded');
        }

        $this->pendingRequestIds[$id] = true;
    }

    /**
     * A channel fragment may split a header/payload, or contain many frames.
     * Store only the four-byte length and five-byte response prefix; account
     * for the entire advertised frame before forwarding its bytes upstream.
     */
    private function verifySftpFrames(string $bytes): void
    {
        $offset = 0;
        $total = strlen($bytes);

        while ($offset < $total) {
            if ($this->incomingFrameRemaining === 0) {
                $take = min(4 - strlen($this->incomingLengthBytes), $total - $offset);
                $this->incomingLengthBytes .= substr($bytes, $offset, $take);
                $offset += $take;

                if (strlen($this->incomingLengthBytes) < 4) {
                    continue;
                }

                $length = unpack('Nsize', $this->incomingLengthBytes)['size'];
                $this->incomingLengthBytes = '';

                if ($length < 5 || $length > self::MAX_SFTP_FRAME_PAYLOAD) {
                    throw new SshTargetConnectionException('sftp_frame_too_large');
                }
                if (! $this->expectVersion && ($this->pendingRequestIds === [] || ! $this->versionSeen)) {
                    throw new SshTargetConnectionException('sftp_response_budget_exceeded');
                }

                $this->batchBytes += $length + 4;
                $this->batchFrames++;
                if ($this->batchBytes > self::MAX_BATCH_BYTES
                    || $this->batchFrames > self::MAX_BATCH_FRAMES) {
                    throw new SshTargetConnectionException('sftp_response_budget_exceeded');
                }

                $this->incomingFrameRemaining = $length;
                $this->incomingFramePrefix = '';
            }

            $take = min($this->incomingFrameRemaining, $total - $offset);
            if (strlen($this->incomingFramePrefix) < 5) {
                $prefixTake = min(5 - strlen($this->incomingFramePrefix), $take);
                $this->incomingFramePrefix .= substr($bytes, $offset, $prefixTake);
                if (strlen($this->incomingFramePrefix) === 5) {
                    $type = ord($this->incomingFramePrefix[0]);
                    if ($this->expectVersion) {
                        if ($type !== 2) { // SSH_FXP_VERSION
                            throw new SshTargetConnectionException('sftp_response_budget_exceeded');
                        }
                    } else {
                        $id = unpack('Nid', substr($this->incomingFramePrefix, 1, 4))['id'];
                        if (! isset($this->pendingRequestIds[$id])
                            || $type < 101 || ($type > 105 && $type !== 201)) {
                            // Wrong/duplicate IDs never reach requestBuffer.
                            throw new SshTargetConnectionException('sftp_response_budget_exceeded');
                        }
                        // Prevent a second reply to the same ID while the
                        // current frame is being drained.
                        unset($this->pendingRequestIds[$id]);
                    }
                }
            }

            $this->incomingFrameRemaining -= $take;
            $offset += $take;
            if ($this->incomingFrameRemaining === 0) {
                if ($this->expectVersion) {
                    $this->expectVersion = false;
                    $this->versionSeen = true;
                }
                $this->incomingFramePrefix = '';
            }
        }
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

        // Upstream SFTP resets its per-packet timeout, so clamp every wait
        // to the remaining whole-operation budget before blocking.
        $this->curTimeout = $this->curTimeout === null || $this->curTimeout <= 0
            ? $remaining : min($this->curTimeout, $remaining);
    }
}
