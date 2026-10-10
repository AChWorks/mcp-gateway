<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshFileAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Models\User;
use Closure;
use phpseclib4\Exception\FileSystemException;
use phpseclib4\Net\SFTP;
use phpseclib4\Net\SFTP\FileType;
use Throwable;

/**
 * Bounded SFTP metadata, directory inspection and binary-safe range/small write.
 * The remote OS/SFTP subsystem owns pathname, symlink and filesystem policy.
 */
final readonly class SshFileRuntime
{
    private const MAX_PATH_BYTES = 1024;

    private const MAX_RANGE_BYTES = 16384;

    private const MAX_WRITE_BYTES = 16384;

    private const MAX_LIST_ITEMS = 100;

    private const MAX_LIST_NAME_BYTES = 16384;

    public function __construct(
        private SshTargetVault $vault,
        private SshVerifiedTransport $transport,
        private SshFileAdmission $admission,
        private AccessControl $access,
    ) {}

    /** @return array<string,mixed> */
    public function stat(User $user, Target $target, string $path): array
    {
        $this->validatePath($path);

        return $this->operate($user, $target, GatewayPermission::SshFileRead,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use ($path): array {
                $sftp->disableStatCache();
                try {
                    $attributes = $sftp->lstat($path);
                } catch (SshTargetConnectionException $exception) {
                    // Preserve an explicit no-SFTP-subsystem result; never
                    // replace it with a generic file-not-found outcome.
                    throw $exception;
                } catch (Throwable) {
                    throw new SshTargetConnectionException('file_unavailable');
                }

                return [
                    ...$this->context($ip, $config, $path),
                    'status' => 'completed',
                    'file' => $this->safeAttributes($attributes),
                ];
            });
    }

    /** @return array<string,mixed> */
    public function list(User $user, Target $target, string $path, int $limit = 100): array
    {
        $this->validatePath($path);
        if ($limit < 1 || $limit > self::MAX_LIST_ITEMS) {
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->operate($user, $target, GatewayPermission::SshFileRead,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use ($path, $limit): array {
                $sftp->disableStatCache();
                $entries = [];
                $nameBytes = 0;
                $onFile = function (string $dir, string $name, array $attributes) use (
                    &$entries, &$nameBytes, $limit,
                ): void {
                    if ($name === '.' || $name === '..') {
                        return;
                    }
                    $nameBytes += strlen($name);
                    if (count($entries) >= $limit || $nameBytes > self::MAX_LIST_NAME_BYTES
                        || ! mb_check_encoding($name, 'UTF-8')) {
                        // rawlist's onFile fires per entry, before adding another
                        // network batch. Fail as oversize; never fake pagination.
                        throw new SshTargetConnectionException('listing_too_large');
                    }
                    $entries[] = ['name' => $name, ...$this->safeAttributes($attributes)];
                };

                try {
                    $attributes = $sftp->stat($path);
                    if (($attributes['type'] ?? null) !== FileType::DIRECTORY) {
                        throw new SshTargetConnectionException('not_directory');
                    }
                    $sftp->rawlist($path, false, $onFile);
                } catch (SshTargetConnectionException $exception) {
                    throw $exception;
                } catch (Throwable) {
                    throw new SshTargetConnectionException('file_unavailable');
                }

                usort($entries, static fn (array $a, array $b): int => strcmp($a['name'], $b['name']));

                return [
                    ...$this->context($ip, $config, $path),
                    'status' => 'completed',
                    'items' => $entries,
                    'count' => count($entries),
                    'complete' => true,
                    'continuation_available' => false,
                ];
            });
    }

    /** @return array<string,mixed> */
    public function read(
        User $user, Target $target, string $path, int $offset = 0, int $length = 16384,
        ?int $expectedSize = null, ?int $expectedMtime = null,
    ): array {
        $this->validatePath($path);
        if ($offset < 0 || $offset > 1099511627776 || $length < 1 || $length > self::MAX_RANGE_BYTES) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $this->validatePrecondition($expectedSize, $expectedMtime);

        return $this->operate($user, $target, GatewayPermission::SshFileRead,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use (
                $path, $offset, $length, $expectedSize, $expectedMtime,
            ): array {
                $sftp->disableStatCache();
                try {
                    $before = $this->stableRegularFile($sftp, $path);
                    $this->requireVersion($before, $expectedSize, $expectedMtime);
                    $bytesToRead = max(0, min($length, $before['size'] - $offset));
                    $bytes = $bytesToRead > 0 ? $sftp->get($path, null, $offset, $bytesToRead) : '';
                    if (! is_string($bytes) || strlen($bytes) !== $bytesToRead) {
                        throw new SshTargetConnectionException('source_changed');
                    }
                    $after = $this->stableRegularFile($sftp, $path);
                    $this->requireVersion($after, $before['size'], $before['mtime']);
                } catch (SshTargetConnectionException $exception) {
                    throw $exception;
                } catch (Throwable) {
                    throw new SshTargetConnectionException('file_unavailable');
                }

                return [
                    ...$this->context($ip, $config, $path),
                    'status' => 'completed',
                    'offset' => $offset,
                    'length' => strlen($bytes),
                    'size' => $before['size'],
                    'mtime' => $before['mtime'],
                    'encoding' => 'base64',
                    'data' => base64_encode($bytes),
                    'end_of_file' => $offset + strlen($bytes) >= $before['size'],
                    'complete' => true,
                    'source_check' => 'size_mtime_best_effort',
                ];
            });
    }

    /** @return array<string,mixed> */
    public function write(
        User $user, Target $target, string $path, string $contentBase64,
        bool $overwrite = false, ?int $expectedSize = null, ?int $expectedMtime = null,
    ): array {
        $this->validatePath($path);
        if ($path === '/' || str_ends_with($path, '/') || strlen($contentBase64) > 21848
            || ! preg_match('/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/D', $contentBase64)) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $data = base64_decode($contentBase64, true);
        if (! is_string($data) || strlen($data) > self::MAX_WRITE_BYTES
            || base64_encode($data) !== $contentBase64) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $this->validatePrecondition($expectedSize, $expectedMtime);
        if (($expectedSize !== null) !== $overwrite) {
            // Create-only is the default; overwrite always needs an explicit
            // size/mtime comparison to discourage accidental replacement.
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->operate($user, $target, GatewayPermission::SshFileWrite,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use (
                $path, $data, $overwrite, $expectedSize, $expectedMtime,
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
                    // Only an exact SFTP "missing path" status can establish
                    // create-only intent; authorization, transport, and server
                    // errors MUST NOT masquerade as a missing file.
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
                $temporary = ($dir === '/' ? '' : $dir).'/.gateway-sftp-'.bin2hex(random_bytes(12)).'.tmp';
                // All remote modifications are below; any subsequent exception
                // has a potentially unknown outcome. Never retry a write.
                try {
                    $sftp->put($temporary, $data, SFTP::SOURCE_STRING);
                    $temporaryAttributes = $sftp->stat($temporary);
                    if (! isset($temporaryAttributes['size']) || $temporaryAttributes['size'] !== strlen($data)) {
                        throw new SshTargetConnectionException('write_incomplete');
                    }

                    $sftp->clearStatCache();
                    if (! $overwrite) {
                        // Some SFTP servers implement rename using POSIX
                        // replacement semantics. A check-then-rename is NOT
                        // reliably no-clobber under concurrent writers.
                        // OpenSSH hardlink is atomic/exclusive: if the final
                        // path already exists, it cannot be replaced.
                        // Without that extension fail closed, never fall back
                        // to a possibly overwriting standard rename.
                        $sftp->hardlink($temporary, $path);
                        $sftp->delete($temporary, false);
                    } else {
                        // Only servers supporting atomic POSIX replacement can
                        // replace a file; never delete the original as fallback.
                        $latest = $sftp->lstat($path);
                        $this->requireVersion($latest, $expectedSize, $expectedMtime);
                        $sftp->posix_rename($temporary, $path);
                    }
                    $sftp->clearStatCache();
                    $result = $sftp->stat($path);
                    if (! isset($result['size']) || $result['size'] !== strlen($data)) {
                        throw new SshTargetConnectionException('write_unverified');
                    }
                } catch (Throwable) {
                    $cleanup = false;
                    try {
                        $sftp->delete($temporary, false);
                        $cleanup = true;
                    } catch (Throwable) {
                        // Remote temporary write may persist after interruption.
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
                    'bytes_written' => strlen($data),
                    'submitted_sha256' => hash('sha256', $data),
                    'atomic_publish' => true,
                    'publish_method' => $overwrite ? 'posix_replace' : 'exclusive_hardlink',
                    'overwrote' => $overwrite,
                ];
            });
    }

    /** @param Closure(SFTP,string,SshTargetConfig):array<string,mixed> $operation
     * @return array<string,mixed>
     */
    private function operate(User $user, Target $target, GatewayPermission $permission, Closure $operation): array
    {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }

        return $this->admission->run((string) $target->getKey(), function () use (
            $user, $target, $permission, $operation,
        ): array {
            $fresh = Target::query()->whereKey($target->getKey())->first();
            $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
            $credential = TargetCredential::query()
                ->where('target_record_id', $target->getKey())
                ->where('connector_type', 'ssh_direct')
                ->where('purpose', SshTargetVault::PURPOSE)->first();
            if (! $fresh instanceof Target || $fresh->connector_type !== 'ssh_direct'
                || ! hash_equals((string) $target->target_id, (string) $fresh->target_id)
                || ! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
                throw new SshTargetConnectionException('credential_unavailable');
            }

            try {
                $material = $this->vault->open($fresh, $config, $credential);
                $pin = SshHostKeyPin::fromLine($config->pinned_host_key);
            } catch (Throwable) {
                throw new SshTargetConnectionException('credential_unavailable');
            }

            return $this->transport->withAuthenticatedSftpSession(
                $config->endpoint(), $pin, $config->auth_method,
                $material['secret'], $material['passphrase'],
                function (SFTP $sftp, string $ip) use (
                    $user, $target, $permission, $config, $credential, $operation,
                ): array {
                    $currentTarget = Target::query()->whereKey($target->getKey())->first();
                    $currentUser = User::query()->whereKey($user->getKey())->first();
                    $currentCredential = TargetCredential::query()->whereKey($credential->getKey())->first();
                    $currentConfig = SshTargetConfig::query()->whereKey($config->getKey())->first();
                    if (! $currentTarget instanceof Target || $currentTarget->connector_type !== 'ssh_direct'
                        || ! hash_equals((string) $target->target_id, (string) $currentTarget->target_id)
                        || ! $currentUser instanceof User || ! $currentCredential instanceof TargetCredential
                        || ! $currentConfig instanceof SshTargetConfig
                        || ! hash_equals((string) $credential->encrypted_payload, (string) $currentCredential->encrypted_payload)
                        || ! hash_equals((string) $config->pinned_host_key, (string) $currentConfig->pinned_host_key)
                        || ! hash_equals((string) $config->host, (string) $currentConfig->host)
                        || $config->port !== $currentConfig->port
                        || ! hash_equals((string) $config->username, (string) $currentConfig->username)
                        || ! $this->access->allows($currentUser, $permission, $currentTarget)) {
                        throw new SshTargetConnectionException('target_changed');
                    }

                    $sftp->setTimeout(12);

                    return $operation($sftp, $ip, $config);
                },
            );
        });
    }

    private function validatePath(string $path): void
    {
        if ($path === '' || strlen($path) > self::MAX_PATH_BYTES || ! str_starts_with($path, '/')
            || ! mb_check_encoding($path, 'UTF-8')
            || preg_match('/[\x00-\x1F\x7F]/', $path) === 1) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    private function validatePrecondition(?int $size, ?int $mtime): void
    {
        if (($size === null) !== ($mtime === null) || ($size !== null && $size < 0)
            || ($mtime !== null && $mtime < 0)) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    /** @return array{size:int,mtime:int} */
    private function stableRegularFile(SFTP $sftp, string $path): array
    {
        $attributes = $sftp->stat($path);
        if (($attributes['type'] ?? null) !== FileType::REGULAR) {
            throw new SshTargetConnectionException('unsupported_file_type');
        }
        if (! isset($attributes['size'], $attributes['mtime'])
            || ! is_int($attributes['size']) || ! is_int($attributes['mtime'])) {
            throw new SshTargetConnectionException('file_unavailable');
        }

        return ['size' => $attributes['size'], 'mtime' => $attributes['mtime']];
    }

    /** @param array<string,mixed> $attributes */
    private function requireVersion(array $attributes, ?int $expectedSize, ?int $expectedMtime): void
    {
        if ($expectedSize !== null && (
            ($attributes['size'] ?? null) !== $expectedSize
            || ($attributes['mtime'] ?? null) !== $expectedMtime
        )) {
            throw new SshTargetConnectionException('source_changed');
        }
    }

    /** @param array<string,mixed> $attributes
     * @return array<string,mixed>
     */
    private function safeAttributes(array $attributes): array
    {
        $type = match ($attributes['type'] ?? null) {
            FileType::REGULAR => 'file',
            FileType::DIRECTORY => 'directory',
            FileType::SYMLINK => 'symlink',
            default => 'other',
        };

        return [
            'type' => $type,
            'size' => isset($attributes['size']) && is_int($attributes['size']) ? $attributes['size'] : null,
            'mtime' => isset($attributes['mtime']) && is_int($attributes['mtime']) ? $attributes['mtime'] : null,
            'mode' => isset($attributes['mode']) && is_int($attributes['mode'])
                ? sprintf('%04o', $attributes['mode'] & 07777) : null,
        ];
    }

    /** @return array<string,mixed> */
    private function context(string $ip, SshTargetConfig $config, string $path): array
    {
        return [
            'connected_ip' => $ip,
            'registered_host' => $config->host,
            'port' => $config->port,
            'username' => $config->username,
            'path' => $path,
        ];
    }
}
