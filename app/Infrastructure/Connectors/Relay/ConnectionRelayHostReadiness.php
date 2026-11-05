<?php

namespace App\Infrastructure\Connectors\Relay;

/**
 * Host evidence is issued and rotated by an independent privileged verifier.
 * A root-owned marker fences stale evidence when managed host policy changes;
 * a boot ID and short lease bound evidence even across untracked host drift.
 * No PHP action can create, modify or renew either root-owned artifact.
 */
class ConnectionRelayHostReadiness
{
    public function ready(ConnectionRelay $relay): bool
    {
        if (! function_exists('posix_geteuid')) {
            return false;
        }
        $uid = posix_geteuid();
        if ($uid < 1) {
            return false;
        }

        // Never derive filesystem paths from an unchecked record/Relay ID.
        if (preg_match('/\A[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}\z/D', (string) $relay->getKey()) !== 1
            || preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\z/D', $relay->relay_id) !== 1) {
            return false;
        }

        $dir = $this->evidenceDirectory();
        $path = $dir.'/'.$relay->relay_id.'.json';
        $policyPath = $dir.'/'.$relay->relay_id.'.policy';
        $generationPath = $dir.'/'.$relay->relay_id.'.generation.json';
        $managedPath = $dir.'/'.$relay->relay_id.'.managed.json';
        if (! $this->trustedParents($dir)) {
            return false;
        }
        // Directory enumeration must prove absence. file_exists()/is_link()
        // both hide EACCES when PHP cannot search a root-owned 0700 directory.
        $fenceBefore = $this->fenceSnapshot($dir, (string) $relay->getKey(), $relay->relay_id);
        if ($fenceBefore === false) {
            return false;
        }
        if (! $this->trusted($path, false)
            || ! $this->trusted($policyPath, false)
            || ! $this->trusted($generationPath, false)
            || ! $this->trusted($managedPath, false)) {
            return false;
        }
        $bytes = @filesize($path);
        $policyBytes = @filesize($policyPath);
        if (! is_int($bytes) || $bytes < 2 || $bytes > 4096
            || ! is_int($policyBytes) || $policyBytes < 64 || $policyBytes > 65) {
            return false;
        }

        $raw = @file_get_contents($path);
        $policy = @file_get_contents($policyPath);
        $boot = @file_get_contents('/proc/sys/kernel/random/boot_id');
        $uptime = @file_get_contents('/proc/uptime');
        $bootSeconds = ConnectionRelayHostEvidence::bootSecondsFromUptime(is_string($uptime) ? $uptime : null);
        if (! is_string($raw) || ! is_string($policy) || ! is_string($boot) || $bootSeconds === null) {
            return false;
        }
        $document = json_decode($raw, true, 8);
        $generationRaw = @file_get_contents($generationPath);
        $generation = $this->readObject($generationPath, 1024);
        $managed = $this->readObject($managedPath, 4096);
        if (! is_array($document) || $generation === null || $managed === null
            || ! ConnectionRelayHostEvidence::matchesLifecycle($generation, $managed, $fenceBefore['fence'], $relay, trim($policy))
            || ! ConnectionRelayHostEvidence::matches(
                $document, $relay, $uid, trim($boot), trim($policy), time(), $bootSeconds,
            )) {
            return false;
        }

        // A concurrent privileged transition must never be accepted on a
        // single stale observation. This bounded reread complements (but does
        // not replace) the host helper's exclusive lifecycle lock.
        $fenceAfter = $this->fenceSnapshot($dir, (string) $relay->getKey(), $relay->relay_id);
        clearstatcache(true, $generationPath);
        $generationAfter = @file_get_contents($generationPath);
        $policyAfter = @file_get_contents($policyPath);

        return $fenceAfter !== false && $fenceAfter === $fenceBefore
            && is_string($generationAfter) && is_string($policyAfter)
            && $generationAfter === $generationRaw && $policyAfter === $policy;
    }

    /**
     * Return false for ambiguous paths/permissions, and an explicit null
     * fence value only when trusted directory inventories prove absence.
     * The serialized fence is checked again before accepting readiness.
     *
     * @return array{fence: array<array-key,mixed>|null, raw: string|null}|false
     */
    private function fenceSnapshot(string $dir, string $recordId, string $relayId): array|false
    {
        $baseEntries = $this->trustedEntries($dir);
        if ($baseEntries === false || in_array($relayId.'.retired.json', $baseEntries, true)) {
            return false;
        }
        if (! in_array('.fences', $baseEntries, true)) {
            return ['fence' => null, 'raw' => null];
        }
        $fenceDir = $dir.'/.fences';
        $fenceEntries = $this->trustedEntries($fenceDir);
        if ($fenceEntries === false) {
            return false;
        }
        $file = $recordId.'.json';
        if (! in_array($file, $fenceEntries, true)) {
            return ['fence' => null, 'raw' => null];
        }
        $path = $fenceDir.'/'.$file;
        if (! $this->trusted($path, false)) {
            return false;
        }
        $size = @filesize($path);
        if (! is_int($size) || $size < 2 || $size > 1024) {
            return false;
        }
        $raw = @file_get_contents($path);
        $value = is_string($raw) ? json_decode($raw, true, 8) : null;

        return is_array($value) ? ['fence' => $value, 'raw' => $raw] : false;
    }

    /** @return list<string>|false */
    private function trustedEntries(string $directory): array|false
    {
        if (! $this->trusted($directory, true)) {
            return false;
        }
        $entries = @scandir($directory);

        return is_array($entries) ? $entries : false;
    }

    /** The deployment path is fixed; test fixtures override only in Dev/CI. */
    protected function evidenceDirectory(): string
    {
        return '/etc/mcp-gateway/connection-relays';
    }

    private function trustedParents(string $directory): bool
    {
        if (! str_starts_with($directory, '/') || str_contains($directory, '//')
            || str_contains($directory, '/./') || str_contains($directory, '/../')) {
            return false;
        }
        $path = $directory;
        while ($path !== '/') {
            if (! $this->trusted($path, true)) {
                return false;
            }
            $path = dirname($path);
        }

        return $this->trusted('/', true);
    }

    /** @return array<array-key,mixed>|null */
    private function readObject(string $path, int $limit): ?array
    {
        $size = @filesize($path);
        if (! is_int($size) || $size < 2 || $size > $limit) {
            return null;
        }
        $raw = @file_get_contents($path);
        if (! is_string($raw)) {
            return null;
        }
        $value = json_decode($raw, true, 8);

        return is_array($value) ? $value : null;
    }

    private function trusted(string $path, bool $directory): bool
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
