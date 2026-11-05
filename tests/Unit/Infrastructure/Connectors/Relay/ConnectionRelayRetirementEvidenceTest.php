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
        $generation = str_repeat('c', 64);
        $state = [
            'version' => 1,
            'relay_record_id' => $relay->getKey(),
            'relay_id' => $relay->relay_id,
            'host_generation' => $generation,
            'state' => 'retired',
        ];
        $proof = [
            'host_generation' => $generation,
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

        self::assertTrue(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time, $uptime, $state));
        $fence = [
            'version' => 1,
            'relay_record_id' => $relay->getKey(),
            'relay_id' => $relay->relay_id,
            'host_fingerprint' => $relay->hostFingerprint(),
            'configuration_revision' => 4,
            'host_generation' => $generation,
            'intent' => 'delete',
        ];
        self::assertTrue(ConnectionRelayRetirementEvidence::fenceMatches($fence, $relay, $state, 'delete'));
        self::assertFalse(ConnectionRelayRetirementEvidence::fenceMatches($fence, $relay, $state, 'rotate'));
        foreach ([
            ['relay_record_id', '01JAE000000000000000000002'],
            ['relay_id', 'iran-2'],
            ['host_fingerprint', str_repeat('f', 64)],
            ['configuration_revision', 3],
            ['host_generation', str_repeat('d', 64)],
            ['intent', 'rotate'],
            ['version', 2],
        ] as [$field, $value]) {
            $invalid = $fence;
            $invalid[$field] = $value;
            self::assertFalse(ConnectionRelayRetirementEvidence::fenceMatches($invalid, $relay, $state, 'delete'), $field);
        }
        $unexpected = $fence;
        $unexpected['unknown'] = true;
        self::assertFalse(ConnectionRelayRetirementEvidence::fenceMatches($unexpected, $relay, $state, 'delete'));
        $differentGeneration = $state;
        $differentGeneration['host_generation'] = str_repeat('d', 64);
        self::assertFalse(ConnectionRelayRetirementEvidence::fenceMatches($fence, $relay, $differentGeneration, 'delete'));
        $differentGeneration['host_generation'] = $generation;
        $differentGeneration['state'] = 'provisioning';
        self::assertFalse(ConnectionRelayRetirementEvidence::fenceMatches($fence, $relay, $differentGeneration, 'delete'));

        foreach ([
            ['gateway_cleanup_verified', false],
            ['relay_record_id', '01JAE000000000000000000002'],
            ['relay_id', 'iran-2'],
            ['configuration_revision', 3],
            ['host_fingerprint', str_repeat('0', 64)],
            ['host_generation', str_repeat('a', 64)],
            ['verified_boot_id', 'aaaaaaaa-bbbb-cccc-dddd-ffffffffffff'],
            ['verified_at_unix', $time + 500],
            ['verified_at_boot_seconds', $uptime + 50],
            ['expires_at_unix', $time + 1000],
            ['expires_at_unix', $time],
        ] as [$field, $value]) {
            $bad = $proof;
            $bad[$field] = $value;
            self::assertFalse(
                ConnectionRelayRetirementEvidence::matches($bad, $relay, $boot, $time, $uptime, $state),
                'Rejected invalid retirement evidence for '.$field,
            );
        }

        $rotated = $state;
        $rotated['host_generation'] = str_repeat('e', 64);
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time, $uptime, $rotated));

        $pending = $state;
        $pending['state'] = 'provisioning';
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time, $uptime, $pending));

        $unknownState = $state;
        $unknownState['extra'] = true;
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time, $uptime, $unknownState));

        $differentBoot = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($proof, $relay, $differentBoot, $time, $uptime, $state));
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time + 1000, $uptime + 1000, $state));

        $extra = $proof;
        $extra['opaque_signature'] = 'not-authorized';
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($extra, $relay, $boot, $time, $uptime, $state));

        // An Iran cleanup claim is not part of local retirement evidence,
        // and its absence must never block removal from Gateway.
        $unrelatedRemote = $proof;
        $unrelatedRemote['iran_cleanup_verified'] = false;
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($unrelatedRemote, $relay, $boot, $time, $uptime, $state));
        unset($proof['gateway_cleanup_verified']);
        self::assertFalse(ConnectionRelayRetirementEvidence::matches($proof, $relay, $boot, $time, $uptime, $state));
    }

    public function test_valid_proof_is_rejected_when_managed_claim_reappears_without_db_change(): void
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

        $directory = sys_get_temp_dir().'/relay-proof-test-'.bin2hex(random_bytes(8));
        mkdir($directory, 0700);
        try {
            $evidence = new class($directory) extends ConnectionRelayRetirementEvidence
            {
                public function __construct(private readonly string $directory) {}

                protected function evidenceDirectory(): string
                {
                    return $this->directory;
                }

                protected function trusted(string $path, bool $directory): bool
                {
                    // The fixture is deliberately not root-owned; production
                    // uses the inherited owner=0 and no-symlink checks.
                    if ($directory && $path !== $this->directory) {
                        return true; // trusted /etc parents exist on production only
                    }

                    return ! is_link($path) && ($directory ? is_dir($path) : is_file($path));
                }
            };
            $boot = trim((string) file_get_contents('/proc/sys/kernel/random/boot_id'));
            $uptime = (int) floor((float) explode(' ', trim((string) file_get_contents('/proc/uptime')))[0]);
            $timestamp = time();
            $generation = str_repeat('a', 64);
            $state = [
                'version' => 1,
                'relay_record_id' => $relay->getKey(),
                'relay_id' => $relay->relay_id,
                'host_generation' => $generation,
                'state' => 'retired',
            ];
            $proof = [
                'relay_record_id' => $relay->getKey(),
                'relay_id' => $relay->relay_id,
                'host_fingerprint' => $relay->hostFingerprint(),
                'configuration_revision' => 4,
                'host_generation' => $generation,
                'verified_boot_id' => $boot,
                'verified_at_unix' => $timestamp,
                'verified_at_boot_seconds' => $uptime,
                'expires_at_unix' => $timestamp + 600,
                'gateway_cleanup_verified' => true,
            ];
            $retired = $directory.'/iran-1.retired.json';
            $hostState = $directory.'/iran-1.generation.json';
            $claim = $directory.'/iran-1.managed.json';
            file_put_contents($retired, json_encode($proof, JSON_THROW_ON_ERROR));
            file_put_contents($hostState, json_encode($state, JSON_THROW_ON_ERROR));
            self::assertTrue($evidence->verified($relay), 'Original receipt should be valid with no active resources.');

            // Exactly the reviewer's stale-proof failure: the same DB record
            // and unexpired receipt, but a new root-managed host claim.
            file_put_contents($claim, '{"version":2}');
            self::assertTrue(ConnectionRelayRetirementEvidence::hasActiveHostClaims($directory, 'iran-1'));
            self::assertFalse($evidence->verified($relay), 'Delete must refuse after reprovisioning.');
            unlink($claim);
            $state['state'] = 'provisioning';
            $state['host_generation'] = str_repeat('b', 64);
            file_put_contents($hostState, json_encode($state, JSON_THROW_ON_ERROR));
            self::assertFalse($evidence->verified($relay), 'Generation rotation invalidates old proof.');

            // A new privileged local cleanup/reverification could generate
            // an exact fresh retired generation and matching proof.
            $state['state'] = 'retired';
            $state['host_generation'] = str_repeat('d', 64);
            $proof['host_generation'] = $state['host_generation'];
            file_put_contents($hostState, json_encode($state, JSON_THROW_ON_ERROR));
            file_put_contents($retired, json_encode($proof, JSON_THROW_ON_ERROR));
            self::assertTrue($evidence->verified($relay));
            $relay->configuration_revision = 5;
            self::assertFalse($evidence->verified($relay));
        } finally {
            foreach (glob($directory.'/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($directory);
        }
    }
}
