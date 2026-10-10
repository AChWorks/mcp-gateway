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
 * Byte-stream primitives for a future authenticated data plane.
 *
 * Neither method is a public MCP tool or an HTTP endpoint. Callers must first
 * enforce their own finite transfer quota and stage untrusted input/output
 * outside the public web root; never publish an unverified partial sink.
 */
trait StreamsSshFiles
{
    /**
     * Download a whole regular file to a caller-owned writable stream.
     * The caller must discard the sink on ANY failure (including source_changed).
     *
     * @param  resource  $sink
     * @return array<string, mixed>
     */
    public function downloadToStream(
        User $user, Target $target, string $path, mixed $sink, int $maxBytes,
        ?string $expectedSha256 = null, ?int $expectedSize = null, ?int $expectedMtime = null,
    ): array {
        $this->validatePath($path);
        $this->validateStream($sink);
        $this->validateTransferLimit($maxBytes);
        $this->validatePrecondition($expectedSize, $expectedMtime);
        $this->validateSha256($expectedSha256);

        return $this->operate($user, $target, GatewayPermission::SshFileRead,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use (
                $path, $sink, $maxBytes, $expectedSha256, $expectedSize, $expectedMtime,
            ): array {
                $sftp->disableStatCache();
                try {
                    $before = $this->stableRegularFile($sftp, $path);
                    $this->requireVersion($before, $expectedSize, $expectedMtime);
                    if ($before['size'] > $maxBytes) {
                        throw new SshTargetConnectionException('file_too_large');
                    }

                    $digest = hash_init('sha256');
                    $received = 0;
                    if ($before['size'] > 0) {
                        $sftp->get($path, static function (string $bytes) use (
                            $sink, &$received, $digest, $before, $maxBytes,
                        ): void {
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
            });
    }

    /**
     * Upload a known-size stream to an unpredictable remote temporary file,
     * verify its exact SHA-256 by reading it back, then publish atomically.
     * This may read the SFTP bytes twice, deliberately trading bandwidth for
     * end-to-end integrity. Remote effects can be unknown after dispatch.
     *
     * @param  resource  $source
     * @return array<string, mixed>
     */
    public function uploadFromStream(
        User $user, Target $target, string $path, mixed $source, int $expectedBytes,
        string $expectedSha256, int $maxBytes,
        bool $overwrite = false, ?int $expectedSize = null, ?int $expectedMtime = null,
    ): array {
        $this->validatePath($path);
        $this->validateStream($source);
        $this->validateTransferLimit($maxBytes);
        $this->validateSha256($expectedSha256);
        $this->validatePrecondition($expectedSize, $expectedMtime);
        if ($path === '/' || str_ends_with($path, '/') || $expectedBytes < 0
            || $expectedBytes > $maxBytes || (($expectedSize !== null) !== $overwrite)) {
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->operate($user, $target, GatewayPermission::SshFileWrite,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use (
                $path, $source, $expectedBytes, $expectedSha256,
                $overwrite, $expectedSize, $expectedMtime,
            ): array {
                $sftp->disableStatCache();
                try {
                    $existing = $sftp->lstat($path);
                    if (! $overwrite) {
                        throw new SshTargetConnectionException('file_exists');
                    }
                    if (($existing['type'] ?? null) !== FileType::REGULAR) {
                        throw new SshTargetConnectionException('unsupported_file_type');
                    }
                    $this->requireVersion($existing, $expectedSize, $expectedMtime);
                } catch (SshTargetConnectionException $exception) {
                    throw $exception;
                } catch (FileSystemException $exception) {
                    if ($overwrite) {
                        throw new SshTargetConnectionException('source_changed');
                    }
                    if (! in_array($exception->getCode(), [2, 10], true)) {
                        throw new SshTargetConnectionException('file_unavailable');
                    }
                } catch (Throwable) {
                    throw new SshTargetConnectionException('file_unavailable');
                }

                $dir = dirname($path);
                $temporary = ($dir === '/' ? '' : $dir).'/.gateway-stream-'.bin2hex(random_bytes(12)).'.tmp';
                $submittedBytes = 0;
                $submittedDigest = hash_init('sha256');

                try {
                    $sftp->put($temporary, static function (int $limit) use (
                        $source, $expectedBytes, &$submittedBytes, $submittedDigest,
                    ): ?string {
                        if ($submittedBytes === $expectedBytes) {
                            return null;
                        }
                        $next = fread($source, min($limit, $expectedBytes - $submittedBytes));
                        if (! is_string($next) || ($next === '' && ! feof($source))) {
                            throw new SshTargetConnectionException('input_unavailable');
                        }
                        if ($next === '') {
                            return null;
                        }
                        $submittedBytes += strlen($next);
                        hash_update($submittedDigest, $next);

                        return $next;
                    }, SFTP::SOURCE_CALLBACK);

                    $extra = fread($source, 1);
                    if ($submittedBytes !== $expectedBytes || $extra !== ''
                        || ! hash_equals($expectedSha256, hash_final($submittedDigest))) {
                        throw new SshTargetConnectionException('input_changed');
                    }

                    $sftp->clearStatCache();
                    $attributes = $sftp->stat($temporary);
                    if (($attributes['size'] ?? null) !== $expectedBytes) {
                        throw new SshTargetConnectionException('write_incomplete');
                    }

                    $verifiedBytes = 0;
                    $verifiedDigest = hash_init('sha256');
                    if ($expectedBytes > 0) {
                        $sftp->get($temporary, static function (string $bytes) use (
                            &$verifiedBytes, $verifiedDigest, $expectedBytes,
                        ): void {
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

                    $sftp->clearStatCache();
                    if ($overwrite) {
                        $latest = $sftp->lstat($path);
                        $this->requireVersion($latest, $expectedSize, $expectedMtime);
                        $sftp->posix_rename($temporary, $path);
                    } else {
                        // No check-then-rename fallback: exclusive hardlink
                        // ensures a concurrent writer cannot be overwritten.
                        $sftp->hardlink($temporary, $path);
                        $sftp->delete($temporary, false);
                    }
                    $sftp->clearStatCache();
                    $published = $sftp->stat($path);
                    if (($published['size'] ?? null) !== $expectedBytes) {
                        throw new SshTargetConnectionException('write_unverified');
                    }
                } catch (Throwable) {
                    $cleanup = false;
                    try {
                        $sftp->delete($temporary, false);
                        $cleanup = true;
                    } catch (Throwable) {
                        // Hard disconnect may leave an uncertain temporary file.
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
                    'publish_method' => $overwrite ? 'posix_replace' : 'exclusive_hardlink',
                    'overwrote' => $overwrite,
                ];
            });
    }

    private function validateTransferLimit(int $maxBytes): void
    {
        if ($maxBytes < 1) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    private function validateStream(mixed $stream): void
    {
        if (! is_resource($stream) || get_resource_type($stream) !== 'stream') {
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
