<?php

namespace App\Application\Files;

use App\Application\Access\AccessControl;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\TargetOperationGate;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Models\User;
use App\Support\CorrelationId;
use Throwable;

/**
 * One authorized whole-file lifecycle over the existing SFTP engine.
 * Incoming bytes and outgoing bytes share the same verified private spool.
 *
 * The only durable state is the remote Target file; no replayable token or
 * retained server-side download is implied by a successful response.
 */
final readonly class SshWholeFileTransfer
{
    public function __construct(
        private AccessControl $access,
        private SshFileRuntime $ssh,
        private ActivityRecorder $activity,
        private OperationalSettings $settings,
        private SshTargetVault $vault,
    ) {}

    public function target(User $user, string $id, GatewayPermission $permission): Target
    {
        if (! $user->access_enabled || strlen($id) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $id) !== 1) {
            throw new SshTargetConnectionException('target_not_found');
        }

        $target = $this->access->scopeTargets(Target::query(), $user, $permission)
            ->where('target_id', $id)->where('connector_type', 'ssh_direct')->first();

        if (! $target instanceof Target) {
            throw new SshTargetConnectionException('target_not_found');
        }
        if (TargetOperationGate::isPaused($target)) {
            throw new SshTargetConnectionException('target_paused');
        }

        return $target;
    }

    /**
     * ChatGPT signed-file prefetch requires a destination that is CURRENTLY
     * ready, not merely an in-scope/unused SSH Target. It must not request
     * confidential source bytes for disconnected or missing-credential Targets.
     * The effect-time SFTP engine still performs its independent live gates.
     */
    public function readyForChatgptFile(User $user, string $id): Target
    {
        $target = $this->target($user, $id, GatewayPermission::SshFileWrite);
        if ($target->getAttribute('connection_state') !== TargetConnectionState::Connected) {
            throw new SshTargetConnectionException('target_not_connected');
        }

        $config = $target->sshConfig()->first();
        $credential = TargetCredential::query()
            ->where('target_record_id', $target->getKey())
            ->where('connector_type', 'ssh_direct')
            ->where('purpose', SshTargetVault::PURPOSE)
            ->first();
        if (! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
            throw new SshTargetConnectionException('target_not_connected');
        }

        try {
            // Verification is local only: do not dial the SSH server, reveal
            // the secret or log the decrypt/binding error in the file response.
            $this->vault->open($target, $config, $credential);
        } catch (Throwable) {
            throw new SshTargetConnectionException('target_not_connected');
        }

        if (TargetOperationGate::isPaused($target)
            || ! $this->access->allows($user, GatewayPermission::SshFileWrite, $target)) {
            // Recheck the scope against the current revision just before GET.
            throw new SshTargetConnectionException('target_not_found');
        }

        return $target;
    }

    /** The wire is an optional, explicitly configured SSH transfer profile. */
    /** @return array{max_bytes:int,max_seconds:int} */
    public function limits(): array
    {
        return $this->settings->sshTransferLimits();
    }

    /**
     * @param  resource  $input  The HTTP raw request body, NEVER passed to SFTP directly.
     * @param  array<string,mixed>  $metadata
     * @return array<string,mixed>
     */
    public function upload(User $user, Target $target, string $path, mixed $input, array $metadata, ?int $overallDeadlineNs = null): array
    {
        $this->validatePath($path);
        $this->validatePath($metadata['private_staging_dir']);
        $budget = $this->limits();
        $deadline = min(hrtime(true) + $budget['max_seconds'] * 1_000_000_000, $overallDeadlineNs ?? PHP_INT_MAX);

        $stream = VerifiedTransferSpool::capture(
            $input, $metadata['size'], $metadata['sha256'], $budget['max_bytes'], $deadline,
        );
        try {
            $remaining = $this->secondsRemaining($deadline);
            $result = $this->ssh->uploadFromStream(
                $user, $target, $path, $stream, $metadata['size'], $metadata['sha256'],
                $budget['max_bytes'], $remaining, $metadata['private_staging_dir'],
                $metadata['overwrite'], $metadata['expected_size'] ?? null, $metadata['expected_mtime'] ?? null,
                overallDeadlineNs: $deadline,
            );
            $this->record($target, 'mcp-file-upload', ($result['status'] ?? '') === 'outcome_unknown' ? 'unknown' : 'success',
                ($result['status'] ?? '') === 'outcome_unknown' ? 'outcome_unknown' : null);

            return $result;
        } catch (SshTargetConnectionException $exception) {
            $this->record($target, 'mcp-file-upload', 'failure', $exception->reason);
            throw $exception;
        } catch (Throwable) {
            $this->record($target, 'mcp-file-upload', 'failure', 'file_unavailable');
            throw new SshTargetConnectionException('file_unavailable');
        } finally {
            fclose($stream);
        }
    }

    /**
     * The result is wholly staged and SHA-256-verified BEFORE HTTP 200 headers
     * or any bytes can reach the external client.
     *
     * @param  array<string,mixed>  $metadata
     * @return array{stream:resource,identity:array<string,mixed>}
     */
    public function download(User $user, Target $target, string $path, array $metadata): array
    {
        $this->validatePath($path);
        $budget = $this->limits();
        $stream = VerifiedTransferSpool::empty();

        try {
            $result = $this->ssh->downloadToStream(
                $user, $target, $path, $stream, $budget['max_bytes'], $budget['max_seconds'],
                $metadata['expected_sha256'] ?? null,
                $metadata['expected_size'] ?? null, $metadata['expected_mtime'] ?? null,
            );
            $stat = fstat($stream);
            if (! is_array($stat) || $stat['size'] !== $result['bytes_read']
                || fseek($stream, 0) !== 0
                || ! hash_equals($result['sha256'], self::streamHash($stream))
                || fseek($stream, 0) !== 0) {
                throw new SshTargetConnectionException('source_changed');
            }

            $this->record($target, 'mcp-file-download', 'success', null);

            return ['stream' => $stream, 'identity' => $result];
        } catch (SshTargetConnectionException $exception) {
            $this->record($target, 'mcp-file-download', 'failure', $exception->reason);
            fclose($stream);
            throw $exception;
        } catch (Throwable) {
            $this->record($target, 'mcp-file-download', 'failure', 'file_unavailable');
            fclose($stream);
            throw new SshTargetConnectionException('file_unavailable');
        }
    }

    /** @param resource $stream */
    private static function streamHash(mixed $stream): string
    {
        $context = hash_init('sha256');
        if (hash_update_stream($context, $stream) < 0) {
            throw new SshTargetConnectionException('source_changed');
        }

        return hash_final($context);
    }

    private function secondsRemaining(int $deadline): int
    {
        $remainingNs = $deadline - hrtime(true);
        if ($remainingNs <= 0) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }

        return min(3600, max(1, (int) ceil($remainingNs / 1_000_000_000)));
    }

    private function validatePath(string $path): void
    {
        if ($path === '' || strlen($path) > 1024 || ! str_starts_with($path, '/')
            || ! mb_check_encoding($path, 'UTF-8') || preg_match('/[\x00-\x1f\x7f]/', $path) === 1) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    private function record(Target $target, string $operation, string $status, ?string $reason): void
    {
        $this->activity->record(CorrelationId::current(), $operation, $status, $target, $reason);
    }
}
