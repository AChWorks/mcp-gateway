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

        $dir = '/etc/mcp-gateway/connection-relays';
        $path = $dir.'/'.$relay->relay_id.'.json';
        $policyPath = $dir.'/'.$relay->relay_id.'.policy';
        if (! $this->trusted('/etc', true)
            || ! $this->trusted('/etc/mcp-gateway', true)
            || ! $this->trusted($dir, true)
            || ! $this->trusted($path, false)
            || ! $this->trusted($policyPath, false)) {
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

        return is_array($document)
            && ConnectionRelayHostEvidence::matches(
                $document, $relay, $uid, trim($boot), trim($policy), time(), $bootSeconds,
            );
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
