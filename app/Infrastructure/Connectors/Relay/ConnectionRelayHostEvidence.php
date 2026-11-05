<?php

namespace App\Infrastructure\Connectors\Relay;

/**
 * Pure validation of an operator's bounded, boot-scoped host evidence.
 *
 * Root ownership and trusted path checks belong to ConnectionRelayHostReadiness.
 * PHP does not attest to the actual firewall/SSH/FPM state: an independent
 * privileged verifier must rotate the policy generation before host changes
 * and renew evidence after evaluating the effective controls.
 */
final class ConnectionRelayHostEvidence
{
    public const MAX_AGE_SECONDS = 86400;

    /** @param array<array-key,mixed> $document */
    public static function matches(
        array $document, ConnectionRelay $relay, int $uid,
        string $bootId, string $policyGeneration, int $now, int $nowBootSeconds,
    ): bool {
        $expected = [
            'relay_id', 'host_fingerprint', 'gateway_php_uid',
            'dedicated_php_uid_verified', 'socks_access_acl_verified',
            'relay_egress_verified', 'verified_boot_id',
            'policy_generation', 'verified_at_unix', 'expires_at_unix',
            'verified_at_boot_seconds',
        ];
        $keys = array_keys($document);
        sort($keys);
        sort($expected);
        if ($keys !== $expected) {
            return false;
        }

        $verifiedAt = $document['verified_at_unix'];
        $expiresAt = $document['expires_at_unix'];
        $verifiedAtBoot = $document['verified_at_boot_seconds'];

        return $uid > 0
            && preg_match('/\A[a-f0-9-]{36}\z/D', $bootId) === 1
            && preg_match('/\A[a-f0-9]{64}\z/D', $policyGeneration) === 1
            && is_int($verifiedAt) && is_int($expiresAt) && is_int($verifiedAtBoot)
            && $nowBootSeconds >= 0 && $verifiedAtBoot >= 0
            && $verifiedAtBoot <= $nowBootSeconds
            && $nowBootSeconds - $verifiedAtBoot < self::MAX_AGE_SECONDS
            // Fail closed on clock steps, not just on the monotonic age bound.
            && abs(($now - $verifiedAt) - ($nowBootSeconds - $verifiedAtBoot)) <= 60
            && $verifiedAt <= $now + 60
            && $verifiedAt > $now - self::MAX_AGE_SECONDS
            && $expiresAt > $now
            && $expiresAt > $verifiedAt
            && $expiresAt - $verifiedAt <= self::MAX_AGE_SECONDS
            && $document['relay_id'] === $relay->relay_id
            && is_string($document['host_fingerprint'])
            && hash_equals($relay->hostFingerprint(), $document['host_fingerprint'])
            && $document['gateway_php_uid'] === $uid
            && $document['dedicated_php_uid_verified'] === true
            && $document['socks_access_acl_verified'] === true
            && $document['relay_egress_verified'] === true
            && $document['verified_boot_id'] === $bootId
            && $document['policy_generation'] === $policyGeneration;
    }

    /**
     * Linux /proc/uptime includes suspend time and is boot-relative, unlike
     * Unix wall time. Use whole seconds conservatively for bounded leases.
     */
    public static function bootSecondsFromUptime(?string $contents): ?int
    {
        if (! is_string($contents)
            || preg_match('/\A([0-9]+)\.[0-9]+[[:space:]]+[0-9]+\.[0-9]+[[:space:]]*\z/D', $contents, $matches) !== 1) {
            return null;
        }

        $seconds = filter_var($matches[1], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);

        return is_int($seconds) ? $seconds : null;
    }
}
