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
