<?php

/**
 * Disposable root-owned evidence fixture, exercised by a genuinely non-root
 * PHP process in CI. This never provisions a real Relay or attests host policy.
 */

require dirname(__DIR__, 2).'/vendor/autoload.php';

use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostEvidence;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostReadiness;

$action = $argv[1] ?? '';
$root = $argv[2] ?? '';
$argument = $argv[3] ?? '';
if (preg_match('#\A/run/mcp-relay-readiness-test-[A-Za-z0-9]{8}\z#D', $root) !== 1
    || ! is_dir($root) || is_link($root) || fileowner($root) !== 0) {
    fwrite(STDERR, "Refuse non-disposable or unowned fixture root.\n");
    exit(2);
}
$dir = $root.'/connection-relays';
$relay = new ConnectionRelay([
    'relay_id' => 'iran-1',
    'control_host' => '192.0.2.25',
    'control_port' => 22,
    'control_user' => 'relay-user',
    'control_host_key' => 'ssh-ed25519 non-secret-fixture',
    'local_socks_port' => 46081,
]);
$relay->setAttribute('id', '01JAE000000000000000000001');
$relay->setAttribute('configuration_revision', 2);
$recordId = (string) $relay->getKey();
$fenceDir = $dir.'/.fences';
$fenceFile = $fenceDir.'/'.$recordId.'.json';
$marker = str_repeat('a', 64);
$write = static function (string $path, array $data): void {
    if (is_link($path)) {
        unlink($path);
    }
    file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)."\n");
    chmod($path, 0644);
};

if ($action === 'init') {
    if (posix_geteuid() !== 0 || file_exists($dir)) {
        exit(2);
    }
    mkdir($dir, 0755);
    chmod($dir, 0755);
    $generation = [
        'version' => 1, 'relay_record_id' => $recordId, 'relay_id' => 'iran-1',
        'host_generation' => $marker, 'state' => 'provisioning',
    ];
    $managed = [
        'version' => 2, 'relay_record_id' => $recordId, 'relay_id' => 'iran-1',
        'service_unit' => 'mcp-gateway-relay-iran-1.service',
        'firewall_table' => 'mcp_gateway_relay_'.substr(hash('sha256', $recordId), 0, 12),
        'local_socks_port' => 46081,
        'host_fingerprint' => $relay->hostFingerprint(), 'configuration_revision' => 2,
        'host_generation' => $marker, 'unit_sha256' => str_repeat('b', 64),
        'unit_exec_sha256' => str_repeat('c', 64), 'firewall_sha256' => str_repeat('d', 64),
    ];
    $uptime = file_get_contents('/proc/uptime');
    $seconds = ConnectionRelayHostEvidence::bootSecondsFromUptime(is_string($uptime) ? $uptime : null);
    if ($seconds === null) {
        exit(2);
    }
    $evidence = [
        'relay_id' => 'iran-1', 'host_fingerprint' => $relay->hostFingerprint(),
        'gateway_php_uid' => posix_getpwnam('nobody')['uid'],
        'dedicated_php_uid_verified' => true, 'socks_access_acl_verified' => true,
        'relay_egress_verified' => true,
        'verified_boot_id' => trim(file_get_contents('/proc/sys/kernel/random/boot_id')),
        'policy_generation' => $marker,
        'verified_at_unix' => time(), 'verified_at_boot_seconds' => $seconds,
        'expires_at_unix' => time() + 600,
    ];
    $write($dir.'/iran-1.generation.json', $generation);
    $write($dir.'/iran-1.managed.json', $managed);
    $write($dir.'/iran-1.json', $evidence);
    file_put_contents($dir.'/iran-1.policy', $marker."\n");
    chmod($dir.'/iran-1.policy', 0644);
    exit(0);
}

if ($action === 'mutate') {
    if (posix_geteuid() !== 0 || ! is_dir($dir)) {
        exit(2);
    }
    if (! is_dir($fenceDir)) {
        mkdir($fenceDir, 0755);
    }
    chmod($dir, 0755);
    chmod($fenceDir, 0755);
    if (is_link($fenceFile) || is_file($fenceFile)) {
        unlink($fenceFile);
    }
    @unlink($dir.'/iran-1.retired.json');
    $fence = [
        'version' => 1, 'relay_record_id' => $recordId, 'relay_id' => 'iran-1',
        'host_fingerprint' => str_repeat('e', 64), 'configuration_revision' => 1,
        'host_generation' => str_repeat('f', 64), 'intent' => 'rotate',
    ];
    switch ($argument) {
        case 'missing':
            break;
        case 'directory-0700':
            chmod($fenceDir, 0700);
            break;
        case 'deletion-0700':
            $fence['intent'] = 'delete';
            $write($fenceFile, $fence);
            chmod($fenceDir, 0700);
            break;
        case 'deletion-0755':
            $fence['intent'] = 'delete';
            $write($fenceFile, $fence);
            break;
        case 'rotate-valid':
            $write($fenceFile, $fence);
            break;
        case 'rotate-stale':
            $fence['configuration_revision'] = 2;
            $write($fenceFile, $fence);
            break;
        case 'corrupt':
            file_put_contents($fenceFile, '{invalid');
            chmod($fenceFile, 0644);
            break;
        case 'symlink':
            symlink('/etc/passwd', $fenceFile);
            break;
        case 'base-0700':
            chmod($dir, 0700);
            break;
        case 'retired':
            $write($dir.'/iran-1.retired.json', ['retired' => true]);
            break;
        default:
            fwrite(STDERR, "Unknown test state.\n");
            exit(2);
    }
    exit(0);
}

if ($action === 'check') {
    if (posix_geteuid() !== posix_getpwnam('nobody')['uid']) {
        fwrite(STDERR, "The PHP reader must run with the real non-root nobody UID.\n");
        exit(2);
    }
    $readiness = new class($dir) extends ConnectionRelayHostReadiness
    {
        public function __construct(private string $testDirectory) {}

        protected function evidenceDirectory(): string
        {
            return $this->testDirectory;
        }
    };
    $actual = $readiness->ready($relay);
    $expected = $argument === 'ready';
    if ($actual !== $expected) {
        fwrite(STDERR, 'Unexpected readiness: actual='.(int) $actual.' expected='.(int) $expected."\n");
        exit(1);
    }
    echo 'PASS: '.($expected ? 'ready' : 'fail-closed')." under real non-root PHP / root-owned filesystem.\n";
    exit(0);
}

fwrite(STDERR, "Unknown fixture action.\n");
exit(2);
