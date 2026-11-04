<?php

namespace App\Infrastructure\Connectors\Relay;

/**
 * Operator-provisioned attestation, not a privilege escalation facility.
 *
 * The Gateway PHP process may read but never write the root-owned file.
 * Before approving it, the host operator must prove that the Gateway PHP
 * UID is dedicated and SOCKS loopback access is denied to unrelated UIDs.
 * A configured relay is not automatically a connected relay.
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
        if (! $this->trusted('/etc', true)
            || ! $this->trusted('/etc/mcp-gateway', true)
            || ! $this->trusted($dir, true) || ! $this->trusted($path, false)) {
            return false;
        }
        $bytes = @filesize($path);
        if (! is_int($bytes) || $bytes < 2 || $bytes > 4096) {
            return false;
        }

        $raw = @file_get_contents($path);
        $document = is_string($raw) ? json_decode($raw, true, 8) : null;

        return is_array($document)
            && count($document) === 6
            && ($document['relay_id'] ?? null) === $relay->relay_id
            && ($document['host_fingerprint'] ?? null) === $relay->hostFingerprint()
            && ($document['gateway_php_uid'] ?? null) === $uid
            && ($document['dedicated_php_uid_verified'] ?? null) === true
            && ($document['socks_access_acl_verified'] ?? null) === true
            && ($document['relay_egress_verified'] ?? null) === true;
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
