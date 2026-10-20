<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Application\Mcp\McpDispatchAdmission;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\Concerns\StreamsSshFiles;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshFileAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshSubsystemOnlySftp;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Models\User;
use App\Support\OperationDiagnostics;
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
    use StreamsSshFiles;

    private const MAX_PATH_BYTES = 1024;

    private const MAX_LIST_ITEMS = 100;

    public function __construct(
        private SshTargetVault $vault,
        private SshVerifiedTransport $transport,
        private SshFileAdmission $admission,
        private AccessControl $access,
        private OperationalSettings $settings,
        private McpDispatchAdmission $dispatchAdmission,
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
                } catch (FileSystemException $exception) {
                    throw $this->observedSftpFailure($exception);
                } catch (Throwable $exception) {
                    throw $this->unexpectedSftpFailure($exception);
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

        $nameLimit = $this->settings->sshFileLimits()['list_name_bytes'];

        return $this->operate($user, $target, GatewayPermission::SshFileRead,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use ($path, $limit, $nameLimit): array {
                $sftp->disableStatCache();
                $entries = [];
                $nameBytes = 0;
                $onFile = function (string $dir, string $name, array $attributes) use (
                    &$entries, &$nameBytes, $limit, $nameLimit,
                ): void {
                    if ($name === '.' || $name === '..') {
                        return;
                    }
                    $nameBytes += strlen($name);
                    if (count($entries) >= $limit || $nameBytes > $nameLimit
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
                } catch (FileSystemException $exception) {
                    throw $this->observedSftpFailure($exception);
                } catch (Throwable $exception) {
                    throw $this->unexpectedSftpFailure($exception);
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
        ?string $expectedTargetBinding = null,
    ): array {
        $this->validatePath($path);
        $maxReadBytes = $this->settings->sshFileLimits()['read_bytes'];
        if ($expectedTargetBinding !== null) {
            // Internal, original-Target-bound SSH Job output reads use their
            // separately configured per-call window without widening the
            // public ssh-file-read Tool's ceiling.
            $maxReadBytes = max($maxReadBytes, $this->settings->sshJobOutputWindowBytes());
        }
        if ($offset < 0 || $offset > 1099511627776 || $length < 1 || $length > $maxReadBytes) {
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
                } catch (FileSystemException $exception) {
                    throw $this->observedSftpFailure($exception);
                } catch (Throwable $exception) {
                    throw $this->unexpectedSftpFailure($exception);
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
            }, expectedTargetBinding: $expectedTargetBinding);
    }

    /** @return array<string,mixed> */
    public function write(
        User $user, Target $target, string $path, string $contentBase64,
        bool $overwrite = false, ?int $expectedSize = null, ?int $expectedMtime = null,
        ?string $expectedTargetBinding = null,
    ): array {
        $this->validatePath($path);
        if ($path === '/' || str_ends_with($path, '/')
            || strlen($contentBase64) > 4 * intdiv($this->settings->sshFileLimits()['write_bytes'] + 2, 3)) {
            throw new SshTargetConnectionException('invalid_input');
        }
        // Strict decode + canonical re-encoding below is linear and avoids
        // PCRE backtracking-limit failures on valid 512 KiB Base64 inputs.
        $data = base64_decode($contentBase64, true);
        if (! is_string($data) || strlen($data) > $this->settings->sshFileLimits()['write_bytes']
            || base64_encode($data) !== $contentBase64) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $this->validatePrecondition($expectedSize, $expectedMtime);
        if (! $overwrite && $expectedSize !== null) {
            // An expected existing version applies only to replacement.
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->operate($user, $target, GatewayPermission::SshFileWrite,
            function (SFTP $sftp, string $ip, SshTargetConfig $config) use (
                $user, $target, $path, $data, $overwrite, $expectedSize, $expectedMtime,
            ): array {
                $sftp->disableStatCache();
                $existingMode = null;
                try {
                    $existing = $sftp->lstat($path);
                    if (! $overwrite) {
                        throw new SshTargetConnectionException('file_exists');
                    }
                    if (($existing['type'] ?? null) !== FileType::REGULAR) {
                        throw new SshTargetConnectionException('unsupported_file_type');
                    }
                    $this->requireVersion($existing, $expectedSize, $expectedMtime);
                    if (! isset($existing['mode']) || ! is_int($existing['mode'])) {
                        throw new SshTargetConnectionException('file_unavailable');
                    }
                    // Replacing contents must not silently relax permissions
                    // of an already-private remote destination.
                    $existingMode = $existing['mode'] & 0777;
                } catch (SshTargetConnectionException $exception) {
                    throw $exception;
                } catch (FileSystemException $exception) {
                    // An SFTP missing-path status can establish create-only
                    // intent. Other native failures are not source changes.
                    $failure = $this->writePreflightFailure($exception, $overwrite);
                    if ($failure !== null) {
                        throw $failure;
                    }
                } catch (Throwable $exception) {
                    throw $this->unexpectedSftpFailure($exception);
                }

                $parentDir = dirname($path);
                $stagingDir = ($parentDir === '/' ? '' : $parentDir)
                    .'/.gateway-private-'.bin2hex(random_bytes(16));
                $temporary = $stagingDir.'/payload';

                // Creating this initially empty directory is permitted before
                // it becomes 0700. NEVER put confidential bytes inside until
                // verified-private directory + same-owner 0600 inode checks pass.
                // Same-filesystem sibling staging preserves exclusive hardlink.
                try {
                    $this->assertCurrentFileWriteAuthority($user, $target);
                    $sftp->mkdir($stagingDir, 0700);
                    $sftp->clearStatCache();
                    $directory = $sftp->lstat($stagingDir);
                    if (($directory['type'] ?? null) !== FileType::DIRECTORY
                        || ! isset($directory['mode'])
                        || ($directory['mode'] & 0777) !== 0700) {
                        throw new SshTargetConnectionException('staging_not_private');
                    }

                    $sftp->put($temporary, '', SFTP::SOURCE_STRING);
                    $sftp->clearStatCache();
                    $zero = $sftp->lstat($temporary);
                    if (($zero['type'] ?? null) !== FileType::REGULAR
                        || ($zero['size'] ?? null) !== 0
                        || ! isset($zero['mode']) || ! is_int($zero['mode'])
                        || ! $this->sameSftpOwner($directory, $zero, $sftp->getNegotiatedVersion())) {
                        throw new SshTargetConnectionException('staging_not_private');
                    }

                    $publicationMode = $existingMode ?? ($zero['mode'] & 0777);
                    $sftp->chmod($temporary, 0600);
                    $sftp->clearStatCache();
                    $privateZero = $sftp->lstat($temporary);
                    if (($privateZero['type'] ?? null) !== FileType::REGULAR
                        || ($privateZero['size'] ?? null) !== 0
                        || ! isset($privateZero['mode'])
                        || ($privateZero['mode'] & 0777) !== 0600
                        || ! $this->sameSftpOwner($directory, $privateZero, $sftp->getNegotiatedVersion())) {
                        throw new SshTargetConnectionException('staging_not_private');
                    }

                    // The first nonempty payload byte occurs ONLY after the
                    // preceding verified-private directory/inode checks.
                    $this->assertCurrentFileWriteAuthority($user, $target);
                    $sftp->put($temporary, $data, SFTP::SOURCE_STRING);
                    $sftp->clearStatCache();
                    $attributes = $sftp->lstat($temporary);
                    if (($attributes['type'] ?? null) !== FileType::REGULAR
                        || ($attributes['size'] ?? null) !== strlen($data)
                        || ! isset($attributes['mode'])
                        || ($attributes['mode'] & 0777) !== 0600
                        || ! $this->sameSftpOwner($directory, $attributes, $sftp->getNegotiatedVersion())) {
                        throw new SshTargetConnectionException('write_incomplete');
                    }

                    // Check actual remote stored bytes, not just server-reported
                    // size. Small inline payloads fit inside the bounded range.
                    $remote = $data === '' ? '' : $sftp->get($temporary, null, 0, strlen($data));
                    if (! is_string($remote) || strlen($remote) !== strlen($data)
                        || ! hash_equals(hash('sha256', $data), hash('sha256', $remote))) {
                        throw new SshTargetConnectionException('write_unverified');
                    }

                    // Once content is checked, restore the server's default
                    // published permissions inside the still-private directory.
                    $sftp->chmod($temporary, $publicationMode);
                    $sftp->clearStatCache();
                    $beforePublicationDir = $sftp->lstat($stagingDir);
                    $beforePublication = $sftp->lstat($temporary);
                    if (($beforePublicationDir['type'] ?? null) !== FileType::DIRECTORY
                        || (($beforePublicationDir['mode'] ?? 0) & 0777) !== 0700
                        || ! $this->sameSftpOwner($directory, $beforePublicationDir, $sftp->getNegotiatedVersion())
                        || ($beforePublication['type'] ?? null) !== FileType::REGULAR
                        || ($beforePublication['size'] ?? null) !== strlen($data)
                        || (($beforePublication['mode'] ?? -1) & 0777) !== $publicationMode
                        || ! $this->sameSftpOwner($directory, $beforePublication, $sftp->getNegotiatedVersion())) {
                        throw new SshTargetConnectionException('staging_not_private');
                    }

                    if (! $overwrite) {
                        // Recheck current Target/user authority immediately
                        // before this irreversible, exclusive publication.
                        $this->assertCurrentFileWriteAuthority($user, $target);
                        $sftp->hardlink($temporary, $path);
                    } else {
                        // Explicit atomic replacement. Optional size+mtime
                        // checks are best-effort, never a remote CAS lock.
                        $latest = $sftp->lstat($path);
                        if (($latest['type'] ?? null) !== FileType::REGULAR) {
                            throw new SshTargetConnectionException('unsupported_file_type');
                        }
                        $this->requireVersion($latest, $expectedSize, $expectedMtime);
                        $this->assertCurrentFileWriteAuthority($user, $target);
                        $sftp->posix_rename($temporary, $path);
                    }

                    $sftp->clearStatCache();
                    $result = $sftp->lstat($path);
                    if (($result['type'] ?? null) !== FileType::REGULAR
                        || ($result['size'] ?? null) !== strlen($data)
                        || (($result['mode'] ?? -1) & 0777) !== $publicationMode) {
                        throw new SshTargetConnectionException('write_unverified');
                    }
                    if (! $overwrite) {
                        $sftp->delete($temporary, false);
                    }
                    // Successful POSIX rename consumes the staging inode.
                    $sftp->rmdir($stagingDir);
                } catch (Throwable $exception) {
                    // After staging starts, a failed reply or cleanup cannot
                    // prove whether remote bytes were published. Keep that
                    // effect certainty separate from the observed SFTP cause.
                    try {
                        $diagnostics = $this->writeStagingDiagnostics($exception);
                    } catch (Throwable) {
                        // A redaction/diagnostic failure must not skip
                        // cleanup or turn an uncertain remote effect into
                        // a falsely safe/retryable failure response.
                        $diagnostics = [
                            'failure_origin' => 'unknown',
                            'failure_stage' => 'operation',
                            'provider_cause_unknown' => true,
                            'effect_unconfirmed' => true,
                            'retry_safe' => false,
                        ];
                    }
                    $removed = false;
                    $directoryRemoved = false;
                    try {
                        $sftp->delete($temporary, false);
                        $removed = true;
                    } catch (Throwable) {
                        // A partial remote write or already-published rename
                        // may have left no source inode. Do not blindly retry.
                    }
                    try {
                        $sftp->rmdir($stagingDir);
                        $directoryRemoved = true;
                    } catch (Throwable) {
                        // Only a private ephemeral directory may remain.
                    }

                    return [
                        ...$this->context($ip, $config, $path),
                        'status' => 'outcome_unknown',
                        'complete' => false,
                        'possible_remote_effect' => true,
                        'temporary_cleanup_confirmed' => $removed && $directoryRemoved,
                        // Private in-process evidence. Public MCP output MUST
                        // strip it before serialization; ActivityRecorder then
                        // persists only selectively redacted, bounded values.
                        '__diagnostic_context' => $diagnostics,
                    ];
                }

                return [
                    ...$this->context($ip, $config, $path),
                    'status' => 'completed',
                    'complete' => true,
                    'bytes_written' => strlen($data),
                    'submitted_sha256' => hash('sha256', $data),
                    'integrity_check' => 'remote_readback_sha256',
                    'published_mode' => sprintf('%04o', $publicationMode),
                    'atomic_publish' => true,
                    'publish_method' => $overwrite ? 'posix_replace' : 'exclusive_hardlink',
                    'overwrote' => $overwrite,
                ];
            }, expectedTargetBinding: $expectedTargetBinding);
    }

    /** @param Closure(SFTP,string,SshTargetConfig):array<string,mixed> $operation
     * @return array<string,mixed>
     */
    private function operate(
        User $user, Target $target, GatewayPermission $permission,
        Closure $operation, ?int $deadlineNs = null, ?string $expectedTargetBinding = null,
    ): array {
        // This is an end-to-end budget, including admission and credential
        // lookups, not a fresh timeout for each SFTP packet or path operation.
        // Leave a generous margin before the 90-second Target lease expires.
        $deadlineNs ??= hrtime(true) + 55_000_000_000;
        $this->ensureFileDeadline($deadlineNs);
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }

        return $this->admission->run((string) $target->getKey(), function () use (
            $user, $target, $permission, $operation, $deadlineNs, $expectedTargetBinding,
        ): array {
            $this->ensureFileDeadline($deadlineNs);
            $fresh = Target::query()->whereKey($target->getKey())->first();
            if ($fresh instanceof Target && $fresh->operations_paused) {
                throw new SshTargetConnectionException('target_paused');
            }
            $freshUser = User::query()->whereKey($user->getKey())->first();
            // Internal streamed callers do not pass through the public MCP
            // dispatcher. Denied/revoked principals must be rejected BEFORE
            // opening SSH credentials or contacting a remote Target.
            if (! $fresh instanceof Target || $fresh->connector_type !== 'ssh_direct'
                || $fresh->getAttribute('connection_state') !== TargetConnectionState::Connected
                || ! hash_equals((string) $target->target_id, (string) $fresh->target_id)
                || ! $freshUser instanceof User
                || ! $this->access->allows($freshUser, $permission, $fresh)) {
                throw new SshTargetConnectionException('target_not_found');
            }

            $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
            $credential = TargetCredential::query()
                ->where('target_record_id', $target->getKey())
                ->where('connector_type', 'ssh_direct')
                ->where('purpose', SshTargetVault::PURPOSE)->first();
            if (! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
                throw new SshTargetConnectionException('credential_unavailable');
            }
            if ($expectedTargetBinding !== null
                && ! hash_equals($expectedTargetBinding, SshTargetBinding::hash($fresh, $config))) {
                throw new SshTargetConnectionException('target_changed');
            }

            try {
                $material = $this->vault->open($fresh, $config, $credential);
                $pin = SshHostKeyPin::fromLine($config->pinned_host_key);
            } catch (Throwable) {
                throw new SshTargetConnectionException('credential_unavailable');
            }

            $this->ensureFileDeadline($deadlineNs);

            return $this->transport->withAuthenticatedSftpSession(
                $config->endpoint(), $pin, $config->auth_method,
                $material['secret'], $material['passphrase'],
                function (SFTP $sftp, string $ip) use (
                    $user, $target, $permission, $config, $credential, $operation, $deadlineNs, $expectedTargetBinding,
                ): array {
                    $currentTarget = Target::query()->whereKey($target->getKey())->first();
                    if ($currentTarget instanceof Target && $currentTarget->operations_paused) {
                        throw new SshTargetConnectionException('target_paused');
                    }
                    $currentUser = User::query()->whereKey($user->getKey())->first();
                    $currentCredential = TargetCredential::query()->whereKey($credential->getKey())->first();
                    $currentConfig = SshTargetConfig::query()->whereKey($config->getKey())->first();
                    if (! $currentTarget instanceof Target || $currentTarget->connector_type !== 'ssh_direct'
                        || $currentTarget->getAttribute('connection_state') !== TargetConnectionState::Connected
                        || ! hash_equals((string) $target->target_id, (string) $currentTarget->target_id)
                        || ! $currentUser instanceof User || ! $currentCredential instanceof TargetCredential
                        || ! $currentConfig instanceof SshTargetConfig
                        || ! hash_equals((string) $credential->encrypted_payload, (string) $currentCredential->encrypted_payload)
                        || ! hash_equals((string) $config->pinned_host_key, (string) $currentConfig->pinned_host_key)
                        || ! hash_equals((string) $config->host, (string) $currentConfig->host)
                        || $config->port !== $currentConfig->port
                        || ! hash_equals((string) $config->username, (string) $currentConfig->username)
                        || ! hash_equals((string) $config->auth_method, (string) $currentConfig->auth_method)
                        || ($expectedTargetBinding !== null
                            && ! hash_equals($expectedTargetBinding, SshTargetBinding::hash($currentTarget, $currentConfig)))
                        || ! $this->access->allows($currentUser, $permission, $currentTarget)
                        || ! $this->dispatchAdmission->allows($currentUser)) {
                        throw new SshTargetConnectionException('target_changed');
                    }

                    $this->ensureFileDeadline($deadlineNs);
                    $sftp->setTimeout(12);

                    if (! $sftp instanceof SshSubsystemOnlySftp) {
                        throw new SshTargetConnectionException('sftp_unavailable');
                    }

                    return $sftp->withTransferDeadline(
                        $deadlineNs, fn (): array => $operation($sftp, $ip, $config),
                    );
                },
                $deadlineNs,
            );
        });
    }

    /**
     * Do not treat a still-valid OAuth channel (or human session) as a
     * continuing Target-scoped write grant. SFTP staging and verification
     * can outlive an Owner's permission, group, or Pause changes. Re-read
     * both principals and the Target at every write/publication boundary.
     */
    private function assertCurrentFileWriteAuthority(User $user, Target $target): void
    {
        $currentTarget = Target::query()->whereKey($target->getKey())->first();
        if ($currentTarget instanceof Target && $currentTarget->operations_paused) {
            throw new SshTargetConnectionException('target_paused');
        }

        $currentUser = User::query()->whereKey($user->getKey())->first();
        if (! $currentTarget instanceof Target || $currentTarget->connector_type !== 'ssh_direct'
            || $currentTarget->getAttribute('connection_state') !== TargetConnectionState::Connected
            || ! hash_equals((string) $target->target_id, (string) $currentTarget->target_id)
            || ! $currentUser instanceof User
            || ! $this->access->allows($currentUser, GatewayPermission::SshFileWrite, $currentTarget)
            || ! $this->dispatchAdmission->allows($currentUser)) {
            throw new SshTargetConnectionException('forbidden');
        }
    }

    /**
     * The SFTP principal creating the payload must own its 0700 staging dir.
     * Numeric UID for SFTP v3; exact nonempty owner identity for v4+.
     *
     * @param  array<string,mixed>  $directory
     * @param  array<string,mixed>  $candidate
     */
    private function sameSftpOwner(array $directory, array $candidate, int $version): bool
    {
        if ($version <= 3) {
            return isset($directory['uid'], $candidate['uid'])
                && is_int($directory['uid']) && is_int($candidate['uid'])
                && $directory['uid'] === $candidate['uid'];
        }

        return isset($directory['owner'], $candidate['owner'])
            && is_string($directory['owner']) && is_string($candidate['owner'])
            && $directory['owner'] !== ''
            && hash_equals($directory['owner'], $candidate['owner']);
    }

    private function ensureFileDeadline(int $deadlineNs): void
    {
        if (hrtime(true) >= $deadlineNs) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }
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

    /**
     * A native missing path is the only create-only admission case. Overwrite
     * of an absent expected destination is a source change, but an observed
     * permission/transport error must retain its original native identity.
     */
    private function writePreflightFailure(
        FileSystemException $exception, bool $overwrite,
    ): ?SshTargetConnectionException {
        $observed = $this->observedSftpFailure($exception);
        if (! in_array($exception->getCode(), [2, 10], true)) {
            return $observed;
        }

        return $overwrite
            ? new SshTargetConnectionException('source_changed', $observed->diagnostics)
            : null;
    }

    /**
     * Post-staging failures always preserve unknown-effect classification.
     * Native provider codes/messages survive selective credential redaction;
     * no unknown provider cause is invented as a specific SFTP status.
     *
     * @return array<string,mixed>
     */
    private function writeStagingDiagnostics(Throwable $exception): array
    {
        if ($exception instanceof FileSystemException) {
            $details = $this->observedSftpFailure($exception)->diagnostics;
        } elseif ($exception instanceof SshTargetConnectionException) {
            $details = $exception->diagnostics;
            if ($details === []) {
                $details = [
                    'provider_cause_unknown' => true,
                    'gateway_error_message' => 'SFTP write failed during staging: '.$exception->reason,
                ];
            }
        } else {
            $details = $this->unexpectedSftpFailure($exception)->diagnostics;
        }

        return OperationDiagnostics::safeContext([
            'failure_origin' => 'unknown',
            'failure_stage' => 'operation',
            'effect_unconfirmed' => true,
            'retry_safe' => false,
            ...$details,
        ]);
    }

    /**
     * Retain native error evidence only where the SFTP library exposed it.
     * ActivityRecorder selectively redacts the message before persistence.
     */
    private function observedSftpFailure(FileSystemException $exception): SshTargetConnectionException
    {
        return new SshTargetConnectionException('file_unavailable', [
            'failure_origin' => 'unknown',
            'failure_stage' => 'operation',
            'exception_class' => $exception::class,
            'source_error_code' => $exception->getCode(),
            'source_error_message' => $exception->getMessage(),
        ]);
    }

    /** Do not expose generic PHP exception text as an assumed provider error. */
    private function unexpectedSftpFailure(Throwable $exception): SshTargetConnectionException
    {
        return new SshTargetConnectionException('file_unavailable', [
            'failure_origin' => 'unknown',
            'failure_stage' => 'operation',
            'provider_cause_unknown' => true,
            'exception_class' => $exception::class,
            'gateway_error_message' => 'SFTP operation raised an exception without verified provider details.',
        ]);
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
