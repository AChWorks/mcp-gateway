<?php

declare(strict_types=1);

use GuzzleHttp\Client as Http;
use Illuminate\Support\Str;
use Mcp\Client;
use Mcp\Client\Transport\HttpTransport;

$root = (string) getenv('MIXED_ROOT');
require $root.'/gateway/vendor/autoload.php';
$state = json_decode((string) file_get_contents($root.'/secrets/state.json'), true, 512, JSON_THROW_ON_ERROR);
$mode = $argv[1] ?? '';
$id = $argv[2] ?? '';
$account = (string) getenv('MIXED_SSH_USER');
$check = static function (bool $condition, string $message): void {
    if (! $condition) {
        throw new RuntimeException($message);
    }
};
$check(preg_match('/^mcpac[0-9]+$/D', $account) === 1, 'Expected disposable SSH account.');
$dir = '/home/'.$account.'/mixed-concurrent';
$owner = in_array($mode, ['queue', 'status', 'interrupt-queue', 'interrupt-status'], true);
$wp = in_array($mode, ['wp-denied', 'wp-queue', 'wp-status'], true);
$token = $state[$owner ? 'owner_token' : ($wp ? 'operator_token' : 'capacity_token')];
$client = Client::builder()->setClientInfo('installed-concurrent-'.$mode, '1')
    ->setInitTimeout(8)->setRequestTimeout(30)->setMaxRetries(0)->build();
$http = new Http(['verify' => $root.'/secrets/tls.crt', 'proxy' => '', 'http_errors' => false, 'timeout' => 35]);
$latencies = [];
$call = static function (string $name, array $args) use ($client, &$latencies): array {
    $start = hrtime(true);
    $reply = $client->callTool($name, $args);
    $latencies[$name][] = round((hrtime(true) - $start) / 1000000, 2);

    return $reply->structuredContent ?? [];
};
$queue = static function (array $args, bool $wordpress = false) use ($call, $check): array {
    $prefix = $wordpress ? 'wordpress-bridge-batch' : 'ssh-batch';
    $preview = $call($prefix.'-preview', $args);
    $check(($preview['ok'] ?? false) && ($preview['eligible_count'] ?? null) === count($args['target_ids']),
        'Batch preview not eligible: '.($preview['error']['code'] ?? 'eligibility'));
    $request = $args + ['request_id' => (string) Str::uuid(), 'preview_token' => $preview['preview_token']];
    $tool = $prefix.($wordpress ? '-read' : '-run');
    $created = $call($tool, $request);
    $check(($created['ok'] ?? false) && ($created['status'] ?? null) === 'queued', 'Batch not queued: '.($created['error']['code'] ?? 'status mismatch'));
    $again = $call($tool, $request);
    $check(($again['batch_id'] ?? null) === $created['batch_id'], 'Stable request did not deduplicate.');

    return ['batch_id' => $created['batch_id'], 'request_deduplicated' => true];
};
$start = hrtime(true);
try {
    $client->connect(new HttpTransport(endpoint: 'https://11.22.33.45/mcp',
        headers: ['Authorization' => 'Bearer '.$token], httpClient: $http));
    $direct = $state['ssh_target'];
    $relay = $state['relay_ssh_target'];
    $result = match ($mode) {
        'queue' => $queue(['target_ids' => [$direct, $relay], 'parallelism' => 2, 'timeout_seconds' => 50,
            'command' => 'set -eu; mktemp '.escapeshellarg($dir.'/active.XXXXXX').'; '
                .'for i in $(seq 1 400); do if [ -f '.escapeshellarg($dir.'/release').' ]; then printf concurrent-done; exit 0; fi; sleep 0.1; done; exit 73']),
        'interrupt-queue' => $queue(['target_ids' => [$direct], 'timeout_seconds' => 30,
            'command' => 'set -eu; mktemp '.escapeshellarg($dir.'/interrupted.XXXXXX').'; sleep 20']),
        'cancel-queue' => $queue(['target_ids' => [$direct], 'command' => 'touch '.escapeshellarg($dir.'/unexpected-cancel')]),
        'wp-queue', 'capacity-wp-queue' => $queue(['target_ids' => [$state['wp_target']]], true),
        'status', 'wp-status', 'interrupt-status', 'cancel-status', 'foreign' => $call('target-batch-status', ['batch_id' => $id]),
        'cancel', 'capacity-wp-cancel' => $call('target-batch-cancel', ['batch_id' => $id]),
        'busy', 'recovered' => $call('ssh-command-run', ['target_id' => $direct,
            'command' => $mode === 'busy' ? 'touch '.escapeshellarg($dir.'/unexpected-busy') : 'printf lease-released']),
        'wp', 'wp-denied' => $call('wordpress-ability-execute', ['target_id' => $state['wp_target'],
            'ability' => 'gateway-mixed-test/digest-read', 'input' => ['payload' => str_repeat('w', 262144)]]),
        'sftp' => $call('ssh-file-read', ['target_id' => $relay, 'path' => $dir.'/payload', 'length' => 524288]),
        default => throw new RuntimeException('Unknown concurrent fixture operation.'),
    };
    $error = $result['error']['code'] ?? null;
    switch ($mode) {
        case 'queue':
        case 'interrupt-queue':
        case 'cancel-queue':
        case 'wp-queue':
        case 'capacity-wp-queue':
            break;
        case 'status':
            $check(($result['status'] ?? null) === 'completed' && ($result['counts']['completed'] ?? null) === 2,
                'Distinct Target Batch children did not both complete.');
            foreach ($result['items'] as $item) {
                $check(($item['result']['result']['exit_code'] ?? null) === 0
                    && str_ends_with((string) ($item['result']['result']['stdout'] ?? ''), 'concurrent-done'),
                    'Missing native Batch completion marker.');
            }
            $result = ['status' => 'completed', 'children' => 2];
            break;
        case 'wp-status':
            $check(($result['status'] ?? null) === 'completed' && ($result['counts']['completed'] ?? null) === 1,
                'Native WordPress Batch did not complete: '.($result['items'][0]['error_code'] ?? 'status mismatch'));
            $result = ['status' => 'completed', 'children' => 1];
            break;
        case 'cancel':
        case 'capacity-wp-cancel':
        case 'cancel-status':
            $check(($result['status'] ?? null) === 'canceled' && ($result['counts']['canceled'] ?? null) === 1,
                'Queued Batch cancellation did not settle.');
            $result = ['status' => 'canceled', 'children' => 1];
            break;
        case 'interrupt-status':
            $check(($result['status'] ?? null) === 'outcome_unknown'
                && ($result['items'][0]['error_code'] ?? null) === 'dispatch_lease_expired',
                'Interrupted admitted Batch must remain unknown, not replayable.');
            $result = ['status' => 'outcome_unknown', 'error_code' => 'dispatch_lease_expired'];
            break;
        case 'foreign':
            $check(($result['ok'] ?? true) === false && $error === 'batch_not_admitted', 'Foreign client read another client history.');
            $result = ['error_code' => $error];
            break;
        case 'busy':
            $check(($result['ok'] ?? true) === false && $error === 'connection_busy', 'Same-Target command was not rejected as busy: '.($error ?? 'unexpected success'));
            $result = ['error_code' => $error];
            break;
        case 'recovered':
            $check(($result['ok'] ?? false) && ($result['result']['stdout'] ?? null) === 'lease-released'
                && ($result['result']['exit_code'] ?? null) === 0, 'Normal lease did not release.');
            $result = ['status' => 'completed', 'lease_released' => true];
            break;
        case 'wp':
            $digest = hash('sha256', str_repeat('w', 262144));
            $check(($result['ok'] ?? false) && ($result['result']['bytes'] ?? null) === 262144
                && ($result['result']['sha256'] ?? null) === $digest, 'Concurrent WP provider read failed: '.($error ?? 'result mismatch'));
            $check(($result['result']['principal_id'] ?? null) === 1, 'Unexpected native WordPress principal.');
            $result = ['bytes' => 262144, 'sha256' => $digest, 'principal_id' => 1];
            break;
        case 'wp-denied':
            // Released Bridge catalogs third-party native Abilities as
            // native_abilities, not ability_specific. An Operator has no
            // Unclassified grant; the Owner/second client can execute it.
            $check(($result['ok'] ?? true) === false && $error === 'forbidden',
                'Unclassified native Ability must not be granted to the Operator: '.($error ?? 'unexpected success'));
            $result = ['error_code' => $error];
            break;
        case 'sftp':
            $bytes = base64_decode($result['result']['data'] ?? '', true);
            $check(($result['ok'] ?? false) && is_string($bytes) && strlen($bytes) === 524288
                && hash_equals((string) getenv('MIXED_EXPECTED_SFTP_SHA'), hash('sha256', $bytes))
                && ($result['result']['end_of_file'] ?? false) === true, 'Concurrent native SFTP receipt failed: '.($error ?? 'size/digest mismatch'));
            $result = ['bytes' => strlen($bytes), 'sha256' => hash('sha256', $bytes)];
            break;
    }
} finally {
    $client->disconnect();
}
echo json_encode($result + ['wall_ms' => round((hrtime(true) - $start) / 1000000, 2),
    'tool_ms' => $latencies, 'client_peak_bytes' => memory_get_peak_usage(true)], JSON_THROW_ON_ERROR)."\n";
