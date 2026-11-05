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
        $nowBootSeconds = 100000;
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
            'verified_at_boot_seconds' => $nowBootSeconds - 60,
            'expires_at_unix' => $now + 3600,
        ];
        $check = static fn (array $doc, string $boot = self::BOOT, ?string $generation = null, ?int $clock = null, ?int $uptime = null): bool => ConnectionRelayHostEvidence::matches($doc, $relay, 1005, $boot, $generation ?? $policy, $clock ?? $now, $uptime ?? $nowBootSeconds);

        self::assertTrue($check($manifest));
        self::assertFalse($check($manifest, 'f8b11ba1-39a3-4a1c-aa7d-cbb6ecf3c050'));
        self::assertFalse($check($manifest, generation: str_repeat('b', 64)));
        self::assertFalse($check($manifest, clock: $now + 3601));
        self::assertFalse($check([...$manifest, 'expires_at_unix' => $now + 100000]));
        self::assertFalse($check([...$manifest, 'verified_at_unix' => $now + 100]));
        self::assertFalse($check([...$manifest, 'verified_at_unix' => $now - 86401]));
        self::assertFalse($check([...$manifest, 'verified_at_boot_seconds' => $nowBootSeconds + 1]));
        self::assertFalse($check($manifest, uptime: $nowBootSeconds - 61));
        self::assertFalse($check($manifest, clock: $now - 300), 'Backward wall-clock steps cannot extend evidence.');
        self::assertFalse($check($manifest, clock: $now + 300), 'Forward wall-clock steps invalidate inconsistent evidence.');
        self::assertFalse($check([
            ...$manifest,
            'verified_at_unix' => $now,
            'verified_at_boot_seconds' => $nowBootSeconds,
            'expires_at_unix' => $now + 86400,
        ], clock: $now + 86000, uptime: $nowBootSeconds + 86401), 'Time rollback cannot extend a 24-hour lease.');
        self::assertFalse($check([...$manifest, 'verified_at_boot_seconds' => '99940']));
        self::assertFalse($check([...$manifest, 'verified_at_boot_seconds' => -1]));
        $legacy = $manifest;
        unset($legacy['verified_at_boot_seconds']);
        self::assertFalse($check($legacy), 'Old evidence schemas fail closed.');
        self::assertFalse($check([...$manifest, 'gateway_php_uid' => 1000]));
        self::assertFalse($check([...$manifest, 'socks_access_acl_verified' => 1]));
        self::assertFalse($check([...$manifest, 'unknown_key' => true]));

        $relay->setAttribute('configuration_revision', 4);
        self::assertFalse($check($manifest), 'Lifecycle disable invalidates old attestation fingerprint.');
    }

    public function test_live_readiness_must_match_the_exact_root_owned_host_generation_and_record(): void
    {
        $relay = new ConnectionRelay([
            'relay_id' => 'iran-1',
            'control_host' => '192.0.2.25',
            'control_port' => 22,
            'control_user' => 'relay-user',
            'control_host_key' => 'ssh-ed25519 fixture',
            'local_socks_port' => 46081,
        ]);
        $relay->setAttribute('id', '01JAE000000000000000000001');
        $relay->setAttribute('configuration_revision', 3);
        $policy = str_repeat('a', 64);
        $generation = [
            'version' => 1,
            'relay_record_id' => $relay->getKey(),
            'relay_id' => 'iran-1',
            'host_generation' => $policy,
            'state' => 'provisioning',
        ];
        $managed = [
            'version' => 2,
            'relay_record_id' => $relay->getKey(),
            'relay_id' => 'iran-1',
            'service_unit' => 'mcp-gateway-relay-iran-1.service',
            'firewall_table' => 'mcp_gateway_relay_'.substr(hash('sha256', $relay->getKey()), 0, 12),
            'local_socks_port' => 46081,
            'host_fingerprint' => $relay->hostFingerprint(),
            'configuration_revision' => 3,
            'host_generation' => $policy,
            'unit_sha256' => str_repeat('b', 64),
            'unit_exec_sha256' => str_repeat('c', 64),
            'firewall_sha256' => str_repeat('d', 64),
        ];
        $check = static fn (array $gen, array $claim, ?array $fence = null, ?string $marker = null): bool => ConnectionRelayHostEvidence::matchesLifecycle($gen, $claim, $fence, $relay, $marker ?? $policy);

        self::assertTrue($check($generation, $managed));
        self::assertFalse($check($generation, $managed, marker: str_repeat('e', 64)));
        self::assertFalse($check([...$generation, 'state' => 'retired'], $managed));
        self::assertFalse($check([...$generation, 'host_generation' => str_repeat('f', 64)], $managed));
        self::assertFalse($check([...$generation, 'relay_record_id' => '01JAE000000000000000000002'], $managed));
        self::assertFalse($check($generation, [...$managed, 'relay_record_id' => '01JAE000000000000000000002']));
        self::assertFalse($check($generation, [...$managed, 'configuration_revision' => 2]));
        self::assertFalse($check($generation, [...$managed, 'host_fingerprint' => str_repeat('0', 64)]));
        self::assertFalse($check($generation, [...$managed, 'local_socks_port' => 46082]));
        self::assertFalse($check($generation, [...$managed, 'unit_exec_sha256' => str_repeat('Z', 64)]));
        self::assertFalse($check($generation, [...$managed, 'unexpected' => true]));
        self::assertFalse($check([...$generation, 'extra' => true], $managed));
        $fence = [
            'version' => 1,
            'relay_record_id' => $relay->getKey(),
            'relay_id' => 'iran-1',
            'host_fingerprint' => str_repeat('e', 64),
            'configuration_revision' => 2,
            'host_generation' => str_repeat('f', 64),
            'intent' => 'rotate',
        ];
        self::assertTrue($check($generation, $managed, $fence), 'A newer revision may follow an old rotation fence.');
        self::assertFalse($check($generation, $managed, [...$fence, 'intent' => 'delete']), 'A permanent deletion fence is terminal.');
        self::assertFalse($check($generation, $managed, [...$fence, 'configuration_revision' => 3]));
        self::assertFalse($check($generation, $managed, [...$fence, 'host_generation' => $policy]));
        self::assertFalse($check($generation, $managed, [...$fence, 'relay_id' => 'iran-2']));
        $relay->setAttribute('id', '01JAE000000000000000000002');
        self::assertFalse($check($generation, $managed), 'Reusing the same human Relay ID must not reuse a previous record proof.');
    }

    public function test_linux_proc_uptime_parser_is_strict_and_fails_closed(): void
    {
        self::assertSame(100000, ConnectionRelayHostEvidence::bootSecondsFromUptime("100000.65 21000.91\n"));
        self::assertSame(0, ConnectionRelayHostEvidence::bootSecondsFromUptime("0.00 0.00\n"));
        foreach ([null, '', 'not-a-number', '-1.00 0.00', '1.00', '1.00 garbage', '1e99 2.00', '99999999999999999999999999.0 2.00'] as $invalid) {
            self::assertNull(ConnectionRelayHostEvidence::bootSecondsFromUptime($invalid));
        }
    }
}
