<?php

namespace App\Infrastructure\Connectors\Relay;

/**
 * The unprivileged Gateway may verify, but cannot create, host retirement
 * evidence. A separate privileged helper must prove that the exact Relay's
 * resources on the Gateway host were retired. Iran reachability is irrelevant.
 */
class ConnectionRelayRetirementEvidence
{
    public const MAX_AGE_SECONDS = 900;

    public function verified(ConnectionRelay $relay): bool
    {
        if (! function_exists('posix_geteuid') || posix_geteuid() < 1 || $relay->enabled) {
            return false;
        }

        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $relay->relay_id) !== 1) {
            return false;
        }

        $directory = $this->evidenceDirectory();
        $path = $directory.'/'.$relay->relay_id.'.retired.json';
        $generationPath = $directory.'/'.$relay->relay_id.'.generation.json';
        foreach (['/etc', '/etc/mcp-gateway', $directory] as $dir) {
            if (! $this->trusted($dir, true)) {
                return false;
            }
        }
        if (! $this->trusted($path, false) || ! $this->trusted($generationPath, false)
            || self::hasActiveHostClaims($directory, $relay->relay_id)) {
            return false;
        }

        $generationBytes = @filesize($generationPath);
        if (! is_int($generationBytes) || $generationBytes < 2 || $generationBytes > 1024) {
            return false;
        }
        $rawGeneration = @file_get_contents($generationPath);
        $hostState = is_string($rawGeneration) ? json_decode($rawGeneration, true, 8) : null;
        if (! is_array($hostState)) {
            return false;
        }

        $bytes = @filesize($path);
        if (! is_int($bytes) || $bytes < 2 || $bytes > 2048) {
            return false;
        }
        $raw = @file_get_contents($path);
        $boot = @file_get_contents('/proc/sys/kernel/random/boot_id');
        $uptime = @file_get_contents('/proc/uptime');
        $bootSeconds = ConnectionRelayHostEvidence::bootSecondsFromUptime(is_string($uptime) ? $uptime : null);
        if (! is_string($raw) || ! is_string($boot) || $bootSeconds === null) {
            return false;
        }
        $document = json_decode($raw, true, 8);

        // Host generation rotates BEFORE any future Setup/Repair. Double-
        // check the generation and active claims to reject stale evidence.
        clearstatcache(true, $generationPath);
        $secondGeneration = @file_get_contents($generationPath);
        if (self::hasActiveHostClaims($directory, $relay->relay_id)
            || ! $this->trusted($generationPath, false)
            || ! is_string($secondGeneration)
            || ! hash_equals($rawGeneration, $secondGeneration)) {
            return false;
        }

        return is_array($document) && self::matches($document, $relay, trim($boot), time(), $bootSeconds, $hostState);
    }

    /**
     * A successful retirement receipt alone is NOT a DB transaction barrier.
     * A root-only operator must first create an irreversible revision/record
     * fence under the SAME flock as prepare-setup. PHP reads this fence but
     * can neither issue nor lift it. The fence therefore remains effective
     * after this method returns and through a subsequent DB COMMIT.
     */
    public function verifiedForDeletion(ConnectionRelay $relay): bool
    {
        return $this->verifiedWithFence($relay, 'delete');
    }

    public function verifiedForRotation(ConnectionRelay $relay): bool
    {
        return $this->verifiedWithFence($relay, 'rotate');
    }

    public function deletionFencePresent(ConnectionRelay $relay): bool
    {
        // Do not offer a misleading Edit action when a permanent deletion
        // fence exists but the short-lived retirement receipt expired.
        return $this->fenceMatchesCurrent($relay, 'delete');
    }

    private function verifiedWithFence(ConnectionRelay $relay, string $intent): bool
    {
        // The immutable fence is the cross-process synchronization barrier;
        // the receipt is the independent, short-lived state evidence.
        return $this->fenceMatchesCurrent($relay, $intent)
            && $this->verified($relay);
    }

    private function fenceMatchesCurrent(ConnectionRelay $relay, string $intent): bool
    {
        $recordId = (string) $relay->getKey();
        if (preg_match('/\A[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}\z/D', $recordId) !== 1) {
            return false;
        }
        $directory = $this->evidenceDirectory();
        $fenceDirectory = $directory.'/.fences';
        $path = $fenceDirectory.'/'.$recordId.'.json';
        $generationPath = $directory.'/'.$relay->relay_id.'.generation.json';
        foreach (['/etc', '/etc/mcp-gateway', $directory, $fenceDirectory] as $parent) {
            if (! $this->trusted($parent, true)) {
                return false;
            }
        }
        if (! $this->trusted($path, false) || ! $this->trusted($generationPath, false)) {
            return false;
        }
        $size = @filesize($path);
        if (! is_int($size) || $size < 2 || $size > 1024) {
            return false;
        }
        $rawFence = @file_get_contents($path);
        $rawGeneration = @file_get_contents($generationPath);
        $fence = is_string($rawFence) ? json_decode($rawFence, true, 8) : null;
        $generation = is_string($rawGeneration) ? json_decode($rawGeneration, true, 8) : null;
        if (! is_array($fence) || ! is_array($generation)
            || ! self::fenceMatches($fence, $relay, $generation, $intent)) {
            return false;
        }

        // A matching root-owned terminal fence cannot be lifted by a
        // legitimate helper after this check, including while PHP commits.
        return true;
    }

    /**
     * @param  array<array-key,mixed>  $fence
     * @param  array<array-key,mixed>  $generation
     */
    public static function fenceMatches(
        array $fence, ConnectionRelay $relay, array $generation, string $intent,
    ): bool {
        $expected = [
            'version', 'relay_record_id', 'relay_id', 'host_fingerprint',
            'configuration_revision', 'host_generation', 'intent',
        ];
        $keys = array_keys($fence);
        sort($keys);
        sort($expected);

        return $keys === $expected
            && $fence['version'] === 1
            && $fence['relay_record_id'] === (string) $relay->getKey()
            && $fence['relay_id'] === $relay->relay_id
            && is_string($fence['host_fingerprint'])
            && hash_equals($relay->hostFingerprint(), $fence['host_fingerprint'])
            && $fence['configuration_revision'] === (int) $relay->configuration_revision
            && $fence['intent'] === $intent
            && is_string($fence['host_generation'])
            && is_string($generation['host_generation'] ?? null)
            && hash_equals($generation['host_generation'], $fence['host_generation'])
            && ($generation['state'] ?? null) === 'retired'
            && ($generation['relay_record_id'] ?? null) === (string) $relay->getKey()
            && ($generation['relay_id'] ?? null) === $relay->relay_id;
    }

    /** @phpstan-impure Reads mutable host filesystem state. */
    public static function hasActiveHostClaims(string $directory, string $relayId): bool
    {
        foreach (['.managed.json', '.policy', '.json'] as $suffix) {
            $path = $directory.'/'.$relayId.$suffix;
            clearstatcache(true, $path);
            if (file_exists($path) || is_link($path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<array-key, mixed>  $document
     * @param  array<array-key, mixed>  $hostState
     */
    public static function matches(
        array $document, ConnectionRelay $relay, string $bootId, int $now, int $bootSeconds,
        array $hostState,
    ): bool {
        $expected = [
            'relay_record_id', 'relay_id', 'host_fingerprint',
            'configuration_revision', 'host_generation', 'verified_boot_id', 'verified_at_unix',
            'verified_at_boot_seconds', 'expires_at_unix',
            'gateway_cleanup_verified',
        ];
        $keys = array_keys($document);
        sort($keys);
        sort($expected);
        if ($keys !== $expected) {
            return false;
        }

        $start = $document['verified_at_unix'];
        $end = $document['expires_at_unix'];
        $startBoot = $document['verified_at_boot_seconds'];

        $stateKeys = array_keys($hostState);
        sort($stateKeys);
        $expectedState = ['version', 'relay_record_id', 'relay_id', 'host_generation', 'state'];
        sort($expectedState);
        if ($stateKeys !== $expectedState
            || $hostState['version'] !== 1
            || $hostState['relay_record_id'] !== (string) $relay->getKey()
            || $hostState['relay_id'] !== $relay->relay_id
            || $hostState['state'] !== 'retired'
            || ! is_string($hostState['host_generation'])
            || preg_match('/\A[a-f0-9]{64}\z/D', $hostState['host_generation']) !== 1) {
            return false;
        }

        return is_string($document['host_generation'])
            && hash_equals($hostState['host_generation'], $document['host_generation'])
            && is_string($document['relay_record_id'])
            && hash_equals((string) $relay->getKey(), $document['relay_record_id'])
            && $document['relay_id'] === $relay->relay_id
            && is_string($document['host_fingerprint'])
            && hash_equals($relay->hostFingerprint(), $document['host_fingerprint'])
            && $document['configuration_revision'] === (int) $relay->configuration_revision
            && preg_match('/\A[a-f0-9-]{36}\z/D', $bootId) === 1
            && $document['verified_boot_id'] === $bootId
            && $document['gateway_cleanup_verified'] === true
            && is_int($start) && is_int($end) && is_int($startBoot)
            && $startBoot >= 0 && $bootSeconds >= $startBoot
            && $bootSeconds - $startBoot < self::MAX_AGE_SECONDS
            && $start <= $now + 30 && $now - $start < self::MAX_AGE_SECONDS
            && abs(($now - $start) - ($bootSeconds - $startBoot)) <= 30
            && $end > $now && $end > $start
            && $end - $start <= self::MAX_AGE_SECONDS;
    }

    /**
     * Fixed production path; test substitutes only a disposable fixture.
     */
    protected function evidenceDirectory(): string
    {
        return '/etc/mcp-gateway/connection-relays';
    }

    /** @phpstan-impure Filesystem ownership and contents can change between checks. */
    protected function trusted(string $path, bool $directory): bool
    {
        clearstatcache(true, $path);
        if (@is_link($path) || ($directory ? ! @is_dir($path) : ! @is_file($path))) {
            return false;
        }

        $owner = @fileowner($path);
        $mode = @fileperms($path);

        return $owner === 0 && is_int($mode) && ($mode & 0022) === 0;
    }
}
