<?php

namespace Tests\Unit\Infrastructure\Connectors\Relay;

use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostEvidence;
use PHPUnit\Framework\TestCase;

final class ConnectionRelayHostEvidenceTest extends TestCase
{
    private const BOOT = 'b108d668-e0e2-4c0f-b7bc-ec7a26893627';

    public function test_only_fresh_boot_and_policy_bound_evidence_is_accepted(): void
    {
        $relay = new ConnectionRelay([
            'relay_id' => 'iran-1',
            'control_host' => '192.0.2.25',
            'control_port' => 22,
            'control_user' => 'relay-user',
            'control_host_key' => 'ssh-ed25519 fixture',
            'local_socks_port' => 46081,
        ]);
        $relay->setAttribute('configuration_revision', 3);
        $now = 1793822741;
        $policy = str_repeat('a', 64);
        $manifest = [
            'relay_id' => $relay->relay_id,
            'host_fingerprint' => $relay->hostFingerprint(),
            'gateway_php_uid' => 1005,
            'dedicated_php_uid_verified' => true,
            'socks_access_acl_verified' => true,
            'relay_egress_verified' => true,
            'verified_boot_id' => self::BOOT,
            'policy_generation' => $policy,
            'verified_at_unix' => $now - 60,
            'expires_at_unix' => $now + 3600,
        ];
        $check = static fn (array $doc, string $boot = self::BOOT, ?string $generation = null, ?int $clock = null): bool => ConnectionRelayHostEvidence::matches($doc, $relay, 1005, $boot, $generation ?? $policy, $clock ?? $now);

        self::assertTrue($check($manifest));
        self::assertFalse($check($manifest, 'f8b11ba1-39a3-4a1c-aa7d-cbb6ecf3c050'));
        self::assertFalse($check($manifest, generation: str_repeat('b', 64)));
        self::assertFalse($check($manifest, clock: $now + 3601));
        self::assertFalse($check([...$manifest, 'expires_at_unix' => $now + 100000]));
        self::assertFalse($check([...$manifest, 'verified_at_unix' => $now + 100]));
        self::assertFalse($check([...$manifest, 'verified_at_unix' => $now - 86401]));
        self::assertFalse($check([...$manifest, 'gateway_php_uid' => 1000]));
        self::assertFalse($check([...$manifest, 'socks_access_acl_verified' => 1]));
        self::assertFalse($check([...$manifest, 'unknown_key' => true]));

        $relay->setAttribute('configuration_revision', 4);
        self::assertFalse($check($manifest), 'Lifecycle disable invalidates old attestation fingerprint.');
    }
}
