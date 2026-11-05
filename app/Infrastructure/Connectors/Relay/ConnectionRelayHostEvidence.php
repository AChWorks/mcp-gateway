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
     * Refuse a readable readiness lease unless the independent privileged
     * operator has also completed the exact resource-generation claim. This
     * closes the gap between prepare-setup (which revokes old host state) and
     * later provisioning: an old 11-field lease cannot cross that barrier or
     * be replayed against a new database ULID with the same Relay ID.
     *
     * @param  array<array-key,mixed>  $generation
     * @param  array<array-key,mixed>  $managed
     * @param  array<array-key,mixed>|null  $fence
     */
    public static function matchesLifecycle(
        array $generation, array $managed, ?array $fence,
        ConnectionRelay $relay, string $policyGeneration,
    ): bool {
        if (preg_match('/\A[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}\z/D', (string) $relay->getKey()) !== 1
            || preg_match('/\A[a-f0-9]{64}\z/D', $policyGeneration) !== 1) {
            return false;
        }

        $recordId = $relay->getKey();
        $generationKeys = ['version', 'relay_record_id', 'relay_id', 'host_generation', 'state'];
        $managedKeys = [
            'version', 'relay_record_id', 'relay_id', 'service_unit', 'firewall_table',
            'local_socks_port', 'host_fingerprint', 'configuration_revision',
            'host_generation', 'unit_sha256', 'unit_exec_sha256', 'firewall_sha256',
        ];
        if (! self::exactKeys($generation, $generationKeys)
            || ! self::exactKeys($managed, $managedKeys)
            || $generation['version'] !== 1 || $generation['relay_record_id'] !== $recordId
            || $generation['relay_id'] !== $relay->relay_id
            || $generation['state'] !== 'provisioning'
            || $generation['host_generation'] !== $policyGeneration
            || $managed['version'] !== 2 || $managed['relay_record_id'] !== $recordId
            || $managed['relay_id'] !== $relay->relay_id
            || $managed['service_unit'] !== 'mcp-gateway-relay-'.$relay->relay_id.'.service'
            || $managed['firewall_table'] !== 'mcp_gateway_relay_'.substr(hash('sha256', $recordId), 0, 12)
            || $managed['local_socks_port'] !== (int) $relay->local_socks_port
            || $managed['host_fingerprint'] !== $relay->hostFingerprint()
            || $managed['configuration_revision'] !== (int) $relay->configuration_revision
            || $managed['host_generation'] !== $policyGeneration) {
            return false;
        }
        foreach (['unit_sha256', 'unit_exec_sha256', 'firewall_sha256'] as $digest) {
            if (! is_string($managed[$digest]) || preg_match('/\A[a-f0-9]{64}\z/D', $managed[$digest]) !== 1) {
                return false;
            }
        }
        if ($fence === null) {
            return true;
        }
        $fenceKeys = [
            'version', 'relay_record_id', 'relay_id', 'host_fingerprint',
            'configuration_revision', 'host_generation', 'intent',
        ];

        return self::exactKeys($fence, $fenceKeys)
            && $fence['version'] === 1 && $fence['relay_record_id'] === $recordId
            && $fence['relay_id'] === $relay->relay_id
            && in_array($fence['intent'], ['rotate'], true)
            && is_int($fence['configuration_revision'])
            && $fence['configuration_revision'] >= 1
            && $fence['configuration_revision'] < (int) $relay->configuration_revision
            && is_string($fence['host_fingerprint'])
            && preg_match('/\A[a-f0-9]{64}\z/D', $fence['host_fingerprint']) === 1
            && is_string($fence['host_generation'])
            && preg_match('/\A[a-f0-9]{64}\z/D', $fence['host_generation']) === 1
            && $fence['host_generation'] !== $policyGeneration;
    }

    /**
     * @param  array<array-key,mixed>  $document
     * @param  list<string>  $keys
     */
    private static function exactKeys(array $document, array $keys): bool
    {
        $actual = array_keys($document);
        sort($actual);
        sort($keys);

        return $actual === $keys;
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
