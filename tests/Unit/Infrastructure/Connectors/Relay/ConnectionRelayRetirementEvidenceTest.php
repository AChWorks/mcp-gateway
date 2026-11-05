<?php

namespace Tests\Unit\Infrastructure\Connectors\Relay;

use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRetirementEvidence;
use PHPUnit\Framework\TestCase;

final class ConnectionRelayRetirementEvidenceTest extends TestCase
{
    public function test_local_retirement_receipt_binds_exact_record_configuration_and_boot_without_iran_dependency(): void
    {
        $relay = new ConnectionRelay;
        $relay->setRawAttributes([
            'id' => '01JAE000000000000000000001',
            'relay_id' => 'iran-1',
            'display_name' => 'Iran',
            'control_host' => '198.51.100.41',
            'control_port' => 22,
            'control_user' => 'relay-control',
            'control_host_key' => 'ssh-ed25519 test-public-key-only',
            'local_socks_port' => 46081,
            'configuration_revision' => 4,
            'enabled' => false,
        ], true);
        $boot = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        $time = 1800000100;
        $uptime = 20000;
        $proof = [
            'relay_record_id' => $relay->getKey(),
            'relay_id' => $relay->relay_id,
            'host_fingerprint' => $relay->hostFingerprint(),
            'configuration_revision' => 4,
            'verified_boot_id' => $boot,
            'verified_at_unix' => $time - 50,
            'verified_at_boot_seconds' => $uptime - 50,
            'expires_at_unix' => $time + 500,
            'gateway_cleanup_verified' => true,
        ];

        self::assertTrue(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time, $uptime));

        foreach ([
            ['gateway_cleanup_verified', false],
            ['relay_record_id', '01JAE000000000000000000002'],
            ['relay_id', 'iran-2'],
            ['configuration_revision', 3],
            ['host_fingerprint', str_repeat('0', 64)],
            ['verified_boot_id', 'aaaaaaaa-bbbb-cccc-dddd-ffffffffffff'],
            ['verified_at_unix', $time + 500],
            ['verified_at_boot_seconds', $uptime + 50],
            ['expires_at_unix', $time + 1000],
            ['expires_at_unix', $time],
        ] as [$field, $value]) {
            $bad = $proof;
            $bad[$field] = $value;
            self::assertFalse(
                ConnectionRelayRetirementEvidence::matches($bad, $relay, $boot, $time, $uptime),
                'Rejected invalid retirement evidence for '.$field,
            );
        }

        $extra = $proof;
        $extra['opaque_signature'] = 'not-authorized';
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($extra, $relay, $boot, $time, $uptime));

        // An Iran cleanup claim is not part of local retirement evidence,
        // and its absence must never block removal from Gateway.
        $unrelatedRemote = $proof;
        $unrelatedRemote['iran_cleanup_verified'] = false;
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($unrelatedRemote, $relay, $boot, $time, $uptime));
        unset($proof['gateway_cleanup_verified']);
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time, $uptime));
    }
}
