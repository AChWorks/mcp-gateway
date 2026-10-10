<?php

namespace App\Application\Targets\Concerns;

use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use phpseclib4\Exception\FileSystemException;
use phpseclib4\Net\SFTP;
use phpseclib4\Net\SFTP\FileType;
use Throwable;

/**
 * Internal SFTP byte-stream primitives. No public binary ingress/egress API.
 * Caller-owned local streams must remain private until integrity is verified.
 */
trait StreamsSshFiles
{
    private const MAX_SFTP_UPLOAD_BLOCK = 65536;

    /**
     * Read into a caller-owned private sink; discard that sink on any failure.
     *
     * @param  resource  $sink
     * @return array<string, mixed>
     */
    public function downloadToStream(
        User $user, Target $target, string $path, mixed $sink, int $maxBytes, int $maxSeconds,
        ?string $expectedSha256 = null, ?int $expectedSize = null, ?int $expectedMtime = null,
    ): array {
        $this->validatePath($path);
        $this->validateStream($sink);
        $this->validateTransferLimit($maxBytes);
        $this->validateStreamDeadline($maxSeconds);
        $deadline = hrtime(true) + $maxSeconds * 1_000_000_000;
        $this->validatePrecondition($expectedSize, $expectedMtime);
        $this->validateSha256($expectedSha256);

        return $this->operate($user, $target, GatewayPermission::SshFileRead,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use (
                $path, $sink, $maxBytes, $deadline, $expectedSha256, $expectedSize, $expectedMtime,
            ): array {
                $sftp->disableStatCache();
                try {
                    $this->ensureStreamDeadline($deadline);
                    $before = $this->stableRegularFile($sftp, $path);
                    $this->requireVersion($before, $expectedSize, $expectedMtime);
                    if ($before['size'] > $maxBytes) {
                        throw new SshTargetConnectionException('file_too_large');
                    }

                    $digest = hash_init('sha256');
                    $received = 0;
                    if ($before['size'] > 0) {
                        $sftp->get($path, static function (string $bytes) use (
                            $sink, &$received, $digest, $before, $maxBytes, $deadline,
                        ): void {
                            if (hrtime(true) > $deadline) {
                                throw new SshTargetConnectionException('transfer_timed_out');
                            }
                            $length = strlen($bytes);
                            if ($received + $length > $before['size'] || $received + $length > $maxBytes) {
                                throw new SshTargetConnectionException('source_changed');
                            }
                            $offset = 0;
                            while ($offset < $length) {
                                $written = fwrite($sink, substr($bytes, $offset));
                                if (! is_int($written) || $written < 1) {
                                    throw new SshTargetConnectionException('output_unavailable');
                                }
                                $offset += $written;
                            }
                            hash_update($digest, $bytes);
                            $received += $length;
                        }, 0, $before['size']);
                    }
                    if ($received !== $before['size']) {
                        throw new SshTargetConnectionException('source_changed');
                    }
                    $this->ensureStreamDeadline($deadline);
                    $after = $this->stableRegularFile($sftp, $path);
                    $this->requireVersion($after, $before['size'], $before['mtime']);
                    $sha256 = hash_final($digest);
                    if ($expectedSha256 !== null && ! hash_equals($expectedSha256, $sha256)) {
                        throw new SshTargetConnectionException('source_changed');
                    }
                } catch (SshTargetConnectionException $exception) {
                    throw $exception;
                } catch (Throwable) {
                    throw new SshTargetConnectionException('file_unavailable');
                }

                return [
                    ...$this->context($ip, $config, $path),
                    'status' => 'completed',
                    'complete' => true,
                    'bytes_read' => $received,
                    'size' => $before['size'],
                    'mtime' => $before['mtime'],
                    'sha256' => $sha256,
                    'source_check' => $expectedSha256 === null
                        ? 'size_mtime_best_effort' : 'size_mtime_and_sha256',
                ];
            }, $deadline);
    }

    /**
     * Upload a known-size byte stream into an ALREADY PROVISIONED private
     * SFTP directory with mode 0700, on the same filesystem as the target.
     * Do not create a private directory via SFTP::mkdir(): phpseclib 4.0.2
     * first creates it using ambient permissions, then chmods it, which
     * permits a confidentiality window.
     *
     * Generic streamed overwrite is deliberately NOT offered. SFTP
     * lstat+posix_rename is atomic replacement, NOT atomic conditional
     * replacement / compare-and-swap.
     *
     * @param  resource  $source
     * @return array<string, mixed>
     */
    public function uploadFromStream(
        User $user, Target $target, string $path, mixed $source, int $expectedBytes,
        string $expectedSha256, int $maxBytes, int $maxSeconds, string $privateStagingDir,
        bool $overwrite = false, ?int $expectedSize = null, ?int $expectedMtime = null,
    ): array {
        $this->validatePath($path);
        $this->validatePath($privateStagingDir);
        $this->validateStream($source);
        $this->validateTransferLimit($maxBytes);
        $this->validateStreamDeadline($maxSeconds);
        $deadline = hrtime(true) + $maxSeconds * 1_000_000_000;
        $this->validateSha256($expectedSha256);
        $this->validatePrecondition($expectedSize, $expectedMtime);
        if ($overwrite || $expectedSize !== null || $expectedMtime !== null) {
            // A concurrent writer can win between lstat and POSIX rename.
            // Fail before any remote mutation until a true CAS is available.
            throw new SshTargetConnectionException('overwrite_unsupported');
        }
        if ($path === '/' || str_ends_with($path, '/') || $expectedBytes < 0
            || $expectedBytes > $maxBytes || $privateStagingDir === '/'
            || str_ends_with($privateStagingDir, '/') || $path === $privateStagingDir) {
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->operate($user, $target, GatewayPermission::SshFileWrite,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use (
                $path, $source, $expectedBytes, $expectedSha256, $deadline, $privateStagingDir,
            ): array {
                $sftp->disableStatCache();
                try {
                    $this->ensureStreamDeadline($deadline);
                    $directory = $sftp->lstat($privateStagingDir);
                    // A pre-existing directory with mode 0700 is the sole
                    // confidentiality boundary during SFTP::put(), which
                    // otherwise uses the SFTP server's ambient create mode.
                    if (($directory['type'] ?? null) !== FileType::DIRECTORY
                        || ! isset($directory['mode'])
                        || ($directory['mode'] & 0777) !== 0700) {
                        throw new SshTargetConnectionException('staging_not_private');
                    }

                    // No overwrite, even when caller sends a different source
                    // or a competing operation creates this pathname.
                    $sftp->lstat($path);
                    throw new SshTargetConnectionException('file_exists');
                } catch (SshTargetConnectionException $exception) {
                    throw $exception;
                } catch (FileSystemException $exception) {
                    if (! in_array($exception->getCode(), [2, 10], true)) {
                        throw new SshTargetConnectionException('file_unavailable');
                    }
                } catch (Throwable) {
                    throw new SshTargetConnectionException('file_unavailable');
                }

                $temporary = $privateStagingDir.'/.gateway-stream-'.bin2hex(random_bytes(16)).'.tmp';
                $submittedBytes = 0;
                $submittedDigest = hash_init('sha256');

                try {
                    // Deliberately submit at most 64 KiB to each SFTP::put.
                    // The locked library otherwise buffers up to 1024
                    // outstanding WRITE STATUS replies before checking the
                    // application callback deadline again.
                    do {
                        $this->ensureStreamDeadline($deadline);
                        $remaining = $expectedBytes - $submittedBytes;
                        $next = $remaining > 0
                            ? fread($source, min(self::MAX_SFTP_UPLOAD_BLOCK, $remaining))
                            : '';
                        if (! is_string($next) || ($next === '' && $expectedBytes !== 0)) {
                            throw new SshTargetConnectionException('input_unavailable');
                        }

                        $sftp->put($temporary, $next, SFTP::SOURCE_STRING, $submittedBytes);
                        $submittedBytes += strlen($next);
                        hash_update($submittedDigest, $next);
                    } while ($submittedBytes < $expectedBytes);

                    $this->ensureStreamDeadline($deadline);
                    $extra = fread($source, 1);
                    if ($extra !== '' || $submittedBytes !== $expectedBytes
                        || ! hash_equals($expectedSha256, hash_final($submittedDigest))) {
                        throw new SshTargetConnectionException('input_changed');
                    }

                    $sftp->clearStatCache();
                    $attributes = $sftp->lstat($temporary);
                    if (($attributes['type'] ?? null) !== FileType::REGULAR
                        || ($attributes['size'] ?? null) !== $expectedBytes) {
                        throw new SshTargetConnectionException('write_incomplete');
                    }

                    $verifiedBytes = 0;
                    $verifiedDigest = hash_init('sha256');
                    if ($expectedBytes > 0) {
                        $sftp->get($temporary, static function (string $bytes) use (
                            &$verifiedBytes, $verifiedDigest, $expectedBytes, $deadline,
                        ): void {
                            if (hrtime(true) > $deadline) {
                                throw new SshTargetConnectionException('transfer_timed_out');
                            }
                            $verifiedBytes += strlen($bytes);
                            if ($verifiedBytes > $expectedBytes) {
                                throw new SshTargetConnectionException('write_unverified');
                            }
                            hash_update($verifiedDigest, $bytes);
                        }, 0, $expectedBytes);
                    }
                    if ($verifiedBytes !== $expectedBytes
                        || ! hash_equals($expectedSha256, hash_final($verifiedDigest))) {
                        throw new SshTargetConnectionException('write_unverified');
                    }

                    // Set the new inode's publication policy BEFORE linking
                    // it into an unrestricted destination directory.
                    $this->ensureStreamDeadline($deadline);
                    $sftp->chmod($temporary, 0600);
                    $sftp->clearStatCache();
                    $restricted = $sftp->lstat($temporary);
                    if (($restricted['type'] ?? null) !== FileType::REGULAR
                        || ! isset($restricted['mode'])
                        || ($restricted['mode'] & 0777) !== 0600) {
                        throw new SshTargetConnectionException('staging_not_private');
                    }

                    // The server hardlink extension is the actual no-clobber
                    // atomic primitive. It fails for an existing destination
                    // or unsupported cross-filesystem link; no rename fallback.
                    $this->ensureStreamDeadline($deadline);
                    $sftp->hardlink($temporary, $path);
                    $sftp->delete($temporary, false);

                    $sftp->clearStatCache();
                    $published = $sftp->lstat($path);
                    if (($published['type'] ?? null) !== FileType::REGULAR
                        || ($published['size'] ?? null) !== $expectedBytes
                        || ! isset($published['mode'])
                        || ($published['mode'] & 0777) !== 0600) {
                        throw new SshTargetConnectionException('write_unverified');
                    }
                } catch (Throwable) {
                    $cleanup = false;
                    try {
                        $sftp->delete($temporary, false);
                        $cleanup = true;
                    } catch (Throwable) {
                        // Remote temp effects remain unknown on disconnect.
                    }

                    return [
                        ...$this->context($ip, $config, $path),
                        'status' => 'outcome_unknown',
                        'complete' => false,
                        'possible_remote_effect' => true,
                        'temporary_cleanup_confirmed' => $cleanup,
                    ];
                }

                return [
                    ...$this->context($ip, $config, $path),
                    'status' => 'completed',
                    'complete' => true,
                    'bytes_written' => $expectedBytes,
                    'sha256' => $expectedSha256,
                    'integrity_check' => 'remote_readback_sha256',
                    'atomic_publish' => true,
                    'publish_method' => 'exclusive_hardlink',
                    'overwrote' => false,
                    'published_mode' => '0600',
                ];
            }, $deadline);
    }

    private function validateTransferLimit(int $maxBytes): void
    {
        if ($maxBytes < 1) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    private function validateStreamDeadline(int $maxSeconds): void
    {
        if ($maxSeconds < 1 || $maxSeconds > 40) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    private function ensureStreamDeadline(int $deadline): void
    {
        if (hrtime(true) > $deadline) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }
    }

    private function validateStream(mixed $stream): void
    {
        if (! is_resource($stream) || get_resource_type($stream) !== 'stream') {
            throw new SshTargetConnectionException('invalid_input');
        }

        // Internal byte streams must be already staged regular local files
        // (including PHP's memory/temp wrappers). A socket, FIFO, HTTP body
        // or arbitrary stream wrapper may block indefinitely on fread/fwrite
        // and silently outlive the Target admission lease. The future public
        // data plane owns authenticated ingress, bounded staging and expiry.
        $info = stream_get_meta_data($stream);
        $stat = @fstat($stream);
        $localFile = ($info['wrapper_type'] ?? null) === 'plainfile'
            && ($info['stream_type'] ?? null) === 'STDIO';
        $phpTemp = ($info['wrapper_type'] ?? null) === 'PHP'
            && in_array($info['stream_type'] ?? null, ['TEMP', 'MEMORY'], true);
        if (! is_array($stat) || ! isset($stat['mode'])
            || ($stat['mode'] & 0170000) !== 0100000
            || ($info['seekable'] ?? false) !== true
            || (! $localFile && ! $phpTemp)) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    private function validateSha256(?string $sha256): void
    {
        if ($sha256 !== null && preg_match('/^[a-f0-9]{64}$/D', $sha256) !== 1) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }
}
