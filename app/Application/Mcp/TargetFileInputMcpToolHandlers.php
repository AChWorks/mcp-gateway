<?php

namespace App\Application\Mcp;

use App\Application\Files\ChatGptFileIngress;
use App\Application\Files\SshWholeFileTransfer;
use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Http\OutboundRequestException;
use App\Models\User;
use Throwable;

/**
 * One ChatGPT file-param envelope; Target-specific authorized operation
 * adapters retain their native permission, grant, and integrity semantics.
 * No native WordPress Media import or arbitrary SSH command is performed.
 */
final readonly class TargetFileInputMcpToolHandlers
{
    public function __construct(
        private WordpressFileInputMcpToolHandlers $wordpress,
        private SshWholeFileTransfer $ssh,
        private ChatGptFileIngress $ingress,
    ) {}

    /**
     * @param  array<string,mixed>  $file
     * @param  array<string,mixed>|null  $ssh_destination
     * @return array<string,mixed>
     */
    public function receive(User $user, string $target_id, array $file, string $mode,
        ?array $ssh_destination = null): array
    {
        if (($validationClass = ChatGptFileIngress::inputValidationClass($file)) !== null) {
            return self::failure('invalid_file_input', false, $validationClass);
        }
        if ($mode === 'wordpress_media_stage' && $ssh_destination === null) {
            return $this->wordpress->receive($user, $target_id, $file);
        }
        if ($mode !== 'ssh_sftp_upload' || ! self::validSshDestination($ssh_destination)) {
            return self::failure('invalid_destination');
        }
        if (! config('ssh.file_transfer.enabled', false)) {
            return self::failure('unsupported_mode');
        }

        // Target/grant/Pause must be checked BEFORE retrieving the bearer-like
        // signed file URL. The SFTP upload itself rechecks the live gate.
        try {
            $this->ssh->readyForChatgptFile($user, $target_id);
        } catch (SshTargetConnectionException $exception) {
            return self::failure($exception->reason);
        } catch (Throwable) {
            return self::failure('target_not_found');
        }

        $budget = $this->ssh->limits();
        $deadline = hrtime(true) + $budget['max_seconds'] * 1_000_000_000;
        try {
            $download = $this->ingress->download($file, $budget['max_bytes'], $budget['max_seconds'], 'ssh');
        } catch (OutboundRequestException $exception) {
            return self::failure($exception->reason);
        } catch (Throwable) {
            return self::failure('file_download_unavailable');
        }

        $stream = $download['stream'];
        try {
            if (hrtime(true) >= $deadline) {
                return self::failure('file_transfer_timed_out');
            }
            // Refresh authorization against the current DB revision after the
            // possibly long download; never trust a cached Target snapshot.
            try {
                $target = $this->ssh->readyForChatgptFile($user, $target_id);
            } catch (SshTargetConnectionException $exception) {
                // No remote SFTP dispatch has occurred after the download;
                // a changed Target is a definite pre-effect denial.
                return self::failure($exception->reason);
            }
            $result = $this->ssh->upload($user, $target, $ssh_destination['path'], $stream, [
                'size' => $download['bytes'],
                'sha256' => $download['sha256'],
                'private_staging_dir' => $ssh_destination['private_staging_dir'],
                'overwrite' => $ssh_destination['overwrite'] ?? false,
                ...array_intersect_key($ssh_destination, array_flip(['expected_size', 'expected_mtime'])),
            ], $deadline);
            if (($result['status'] ?? null) === 'outcome_unknown') {
                return self::failure('outcome_unknown', true);
            }
            if (($result['status'] ?? null) !== 'completed'
                || ($result['bytes_written'] ?? null) !== $download['bytes']
                || ($result['sha256'] ?? null) !== $download['sha256']) {
                return self::failure('transfer_integrity_unknown', true);
            }

            return [
                'ok' => true, 'state' => 'verified_ssh_file', 'target_id' => $target_id,
                'bytes' => $download['bytes'], 'sha256' => $download['sha256'],
                'path' => $ssh_destination['path'],
                'retry_safe' => false,
            ];
        } catch (SshTargetConnectionException $exception) {
            return self::failure($exception->reason, true);
        } catch (Throwable) {
            return self::failure('file_unavailable', true);
        } finally {
            try {
                fclose($stream);
            } finally {
                $download['capacity_lease']->release();
            }
        }
    }

    /** @param array<string,mixed>|null $destination */
    private static function validSshDestination(?array $destination): bool
    {
        if (! is_array($destination)
            || array_diff(['path', 'private_staging_dir'], array_keys($destination)) !== []
            || array_diff(array_keys($destination),
                ['path', 'private_staging_dir', 'overwrite', 'expected_size', 'expected_mtime']) !== []) {
            return false;
        }
        foreach (['path', 'private_staging_dir'] as $key) {
            $value = $destination[$key];
            if (! is_string($value) || strlen($value) < 2 || strlen($value) > 1024
                || ! str_starts_with($value, '/') || ! mb_check_encoding($value, 'UTF-8')
                || preg_match('/[\x00-\x1f\x7f]/', $value) === 1) {
                return false;
            }
        }
        if (isset($destination['overwrite']) && ! is_bool($destination['overwrite'])) {
            return false;
        }
        if (isset($destination['expected_size']) !== isset($destination['expected_mtime'])
            || (isset($destination['expected_size'])
                && (! is_int($destination['expected_size']) || $destination['expected_size'] < 0
                    || ! is_int($destination['expected_mtime']) || $destination['expected_mtime'] < 0
                    || ($destination['overwrite'] ?? false) !== true))) {
            return false;
        }

        return true;
    }

    /** @return array<string,mixed> */
    private static function failure(
        string $code,
        bool $possibleRemoteEffect = false,
        ?string $inputValidationClass = null,
    ): array {
        return ['ok' => false, 'error' => [
            'code' => $code,
            'message' => $possibleRemoteEffect
                ? 'The SSH write result is uncertain; inspect the exact destination before any manual retry.'
                : 'The selected Target could not accept the private file safely.',
            'retry_safe' => false,
            ...($possibleRemoteEffect ? ['possible_remote_effect' => true] : []),
            ...($inputValidationClass !== null ? ['input_validation_class' => $inputValidationClass] : []),
        ]];
    }
}
