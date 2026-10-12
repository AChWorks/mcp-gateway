<?php

declare(strict_types=1);
use GuzzleHttp\Client as Http;
use Mcp\Client;
use Mcp\Client\Transport\HttpTransport;

$root = (string) getenv('MIXED_ROOT');
require $root.'/gateway/vendor/autoload.php';
$state = json_decode((string) file_get_contents($root.'/secrets/state.json'), true, 512, JSON_THROW_ON_ERROR);
$http = new Http(['verify' => $root.'/secrets/tls.crt', 'proxy' => '', 'http_errors' => false, 'timeout' => 30]);
$endpoint = 'https://11.22.33.45/mcp';
$connect = static fn (string $token): HttpTransport => new HttpTransport(endpoint: $endpoint, headers: ['Authorization' => 'Bearer '.$token], httpClient: $http);
$client = Client::builder()->setClientInfo('installed-mixed-standalone-sdk', '1.0')
    ->setInitTimeout(8)->setRequestTimeout(30)->setMaxRetries(0)->build();
$check = static function (bool $ok, string $message): void {
    if (! $ok) {
        throw new RuntimeException($message);
    }
};
$status = static function (string $token) use ($http, $endpoint): int {
    return $http->post($endpoint, [
        'headers' => ['Authorization' => 'Bearer '.$token, 'Accept' => 'application/json, text/event-stream',
            'MCP-Protocol-Version' => '2025-11-25'],
        'json' => ['jsonrpc' => '2.0', 'id' => 50, 'method' => 'tools/list'],
    ])->getStatusCode();
};
if (($argv[1] ?? '') === 'revoked') {
    $check($status($state['owner_token']) === 401, 'Disabled owner still authenticated.');
    echo "PASS existing signed bearer for disabled owner rejected HTTP 401\n";
    exit(0);
}
$check($status('invalid-bearer') === 401, 'Invalid bearer accepted.');
$check($status($state['disabled_profile_token']) === 401, 'Disabled client profile previously signed bearer accepted.');
$check(($state['never_granted_mint_denied'] ?? false) === true, 'Never-granted OAuth client was not rejected during bearer issuance.');
$timings = [];
$call = static function (Client $c, string $name, array $args, string $label) use (&$timings): array {
    $start = hrtime(true);
    $result = $c->callTool($name, $args);
    $timings[$label] = round((hrtime(true) - $start) / 1000000, 2);

    return $result->structuredContent ?? [];
};
try {
    $client->connect($connect($state['owner_token']));
    $tools = array_map(static fn ($t) => $t->name, $client->listTools()->tools);
    foreach (['targets-list', 'wordpress-abilities-read', 'wordpress-ability-execute',
        'ssh-command-run', 'ssh-file-write', 'ssh-file-stat', 'ssh-file-read'] as $tool) {
        $check(in_array($tool, $tools, true), 'Missing official SDK tool '.$tool);
    }
    $targets = $call($client, 'targets-list', ['limit' => 10], 'targets');
    $ids = array_column($targets['targets'] ?? [], 'target_id');
    $check(($targets['ok'] ?? false) &&
        in_array($state['wp_target'], $ids, true) &&
        in_array($state['ssh_target'], $ids, true), 'Real shared Gateway did not expose both Targets.');
    $existing = 'wp-ai-bridge/bridge-info';
    $catalog = $call($client, 'wordpress-abilities-read', [
        'target_id' => $state['wp_target'], 'ability' => $existing], 'wp_catalog');
    $check(($catalog['catalog']['items'][0]['name'] ?? null) === $existing,
        'Real WordPress existing Ability not discovered. Sanitized tool response: '.json_encode([
            'ok' => $catalog['ok'] ?? null, 'error' => $catalog['error'] ?? null,
            'catalog_items' => array_column($catalog['catalog']['items'] ?? [], 'name'),
            'catalog_keys' => array_keys($catalog['catalog'] ?? []),
        ], JSON_THROW_ON_ERROR));
    $run = $call($client, 'wordpress-ability-execute', [
        'target_id' => $state['wp_target'], 'ability' => $existing, 'input' => (object) []], 'wp_execute');
    $check($run['ok'] ?? false, 'Real installed WordPress existing Ability failed.');
    $dir = $root.'/wp/wp-content/mu-plugins';
    if (! is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $check(copy($root.'/client/dynamic-ability.php', $dir.'/mixed-ability.php'),
        'Could not register a new on-disk WP native Ability.');
    $novel = 'gateway-mixed-test/dynamic-read';
    $new = $call($client, 'wordpress-abilities-read', [
        'target_id' => $state['wp_target'], 'ability' => $novel], 'wp_dynamic_catalog');
    $check(($new['catalog']['items'][0]['name'] ?? null) === $novel,
        'New WordPress Ability not dynamically discoverable without Gateway edits.');
    $out = $call($client, 'wordpress-ability-execute', [
        'target_id' => $state['wp_target'], 'ability' => $novel, 'input' => (object) []], 'wp_dynamic_execute');
    $check(($out['result']['origin'] ?? null) === 'installed-wordpress',
        'New provider read did not actually execute in WordPress.');
    $denied = $call($client, 'wordpress-ability-execute', [
        'target_id' => $state['wp_target'], 'ability' => 'gateway-mixed-test/denied-read',
        'input' => (object) []], 'wp_denied');
    $check(! ($denied['ok'] ?? false) && ($denied['error']['code'] ?? null) === 'downstream_rejected',
        'WordPress provider denial must be classified as downstream_rejected, not transport failure.');
    // Test the merged Bridge (not published v0.5.1) 128 KiB-capable
    // UTF-8/window source contract through actual Adapter JSON-RPC wrapping.
    // The test verifies complete client receipt, not merely provider staging.
    $bridgeText = null;
    if (getenv('MIXED_BRIDGE_PROFILE') === 'merged-main-c522ae9') {
        $fixture = json_decode((string) file_get_contents($root.'/secrets/large-content.json'),
            true, 512, JSON_THROW_ON_ERROR);
        $source = '';
        $offset = 0;
        $expected = null;
        $windows = 0;
        $maxWindowBytes = 0;
        $largestResultBytes = 0;
        do {
            $input = ['action' => 'get', 'id' => (int) $fixture['post_id'],
                'content_offset' => $offset, 'content_max_bytes' => 131072];
            if ($expected !== null) {
                $input['expected_content_hash'] = $expected;
            }
            $response = $call($client, 'wordpress-ability-execute', [
                'target_id' => $state['wp_target'],
                'ability' => 'wp-ai-bridge/content-read',
                'input' => $input,
            ], 'wp_unicode_window_'.$windows);
            $check(($response['ok'] ?? false) === true,
                'New Bridge Unicode window not executable through Gateway: '.
                json_encode($response['error'] ?? [], JSON_THROW_ON_ERROR));
            $item = $response['result']['items'][0] ?? null;
            $check(is_array($item), 'Missing native WordPress content-read item.');
            $chunk = $item['content'] ?? null;
            $next = $item['content_next_offset'] ?? null;
            $hash = $item['content_hash'] ?? null;
            $check(is_string($chunk) && is_int($next) && is_string($hash)
                && $next > $offset && $next <= (int) $fixture['bytes']
                && strlen($chunk) === $next - $offset
                && preg_match('//u', $chunk) === 1, 'Truncated/invalid UTF-8 continuation.');
            if ($expected === null) {
                $expected = $hash;
            }
            $check(hash_equals($expected, $hash), 'Provider content changed during continuation.');
            $source .= $chunk;
            $maxWindowBytes = max($maxWindowBytes, strlen($chunk));
            $largestResultBytes = max($largestResultBytes,
                strlen(json_encode($response, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE)));
            $offset = $next;
            $windows++;
            $check($windows < 64, 'No bounded source-read progress.');
            $complete = $item['content_complete'] ?? false;
        } while (! $complete);
        $check($offset === (int) $fixture['bytes']
            && strlen($source) === (int) $fixture['bytes']
            && hash_equals((string) $fixture['sha256'], hash('sha256', $source))
            && hash_equals($expected, hash('sha256', $source)),
            'External SDK did not receive exact complete Unicode document.');
        $stale = $call($client, 'wordpress-ability-execute', [
            'target_id' => $state['wp_target'], 'ability' => 'wp-ai-bridge/content-read',
            'input' => ['action' => 'get', 'id' => (int) $fixture['post_id'],
                'content_offset' => 1, 'content_max_bytes' => 4096,
                'expected_content_hash' => str_repeat('0', 64)],
        ], 'wp_stale_source_denial');
        $check(! ($stale['ok'] ?? false), 'Wrong hash continuation was incorrectly accepted.');
        $bridgeText = [
            'source_sha' => 'c522ae99bd11926eb74c007d187354013202fc4c',
            'whole_utf8_bytes' => strlen($source),
            'sha256' => hash('sha256', $source),
            'windows' => $windows,
            'max_decoded_window_bytes' => $maxWindowBytes,
            'max_gateway_result_json_bytes' => $largestResultBytes,
            'wrong_source_hash_denied' => true,
        ];
    }
    $ssh = $call($client, 'ssh-command-run', [
        'target_id' => $state['ssh_target'], 'command' => "printf 'installed-ssh-ok'"], 'ssh_command');
    $check(($ssh['result']['stdout'] ?? null) === 'installed-ssh-ok', 'Host-key verified SSH failed.');
    $bytes = "\x00\xff\x02".random_bytes(8044)."\x00x";
    $file = '/home/'.getenv('MIXED_SSH_USER').'/mixed-'.bin2hex(random_bytes(8)).'.bin';
    try {
        $write = $call($client, 'ssh-file-write', [
            'target_id' => $state['ssh_target'], 'path' => $file, 'content_base64' => base64_encode($bytes)], 'sftp_write');
        $check(($write['result']['bytes_written'] ?? null) === strlen($bytes), 'Binary write count wrong.');
        $stat = $call($client, 'ssh-file-stat', [
            'target_id' => $state['ssh_target'], 'path' => $file], 'sftp_stat');
        $check(($stat['result']['file']['size'] ?? null) === strlen($bytes), 'Binary stat size wrong.');
        $read = $call($client, 'ssh-file-read', [
            'target_id' => $state['ssh_target'], 'path' => $file], 'sftp_read');
        $back = base64_decode($read['result']['data'] ?? '', true);
        $check(is_string($back) && hash_equals($bytes, $back)
            && hash_equals(hash('sha256', $bytes), hash('sha256', $back)), 'Binary SFTP roundtrip wrong.');
    } finally {
        $cleanup = $call($client, 'ssh-command-run', [
            'target_id' => $state['ssh_target'], 'command' => 'rm -f -- '.escapeshellarg($file)], 'sftp_cleanup');
        $check($cleanup['ok'] ?? false, 'SFTP disposable payload not removed.');
    }
    $deniedPath = $call($client, 'ssh-file-read', [
        'target_id' => $state['ssh_target'], 'path' => '/root/mixed-not-authorized'], 'ssh_path_denied');
    $check(! ($deniedPath['ok'] ?? false) && ($deniedPath['error']['code'] ?? null) === 'file_unavailable',
        'Denied SSH filesystem path must be classified as file_unavailable.');
    $cross = $call($client, 'ssh-file-read', [
        'target_id' => $state['wp_target'], 'path' => '/tmp/wrong-connector'], 'cross_target_denied');
    $check(! ($cross['ok'] ?? false) && ($cross['error']['code'] ?? null) === 'target_not_found',
        'Cross-connector lookup must fail as target_not_found before network access.');
    $operator = Client::builder()->setClientInfo('mixed-scoped-operator', '1')
        ->setInitTimeout(8)->setRequestTimeout(30)->setMaxRetries(0)->build();
    try {
        $operator->connect($connect($state['operator_token']));
        $view = $call($operator, 'targets-list', ['limit' => 10], 'operator_targets');
        $check(($view['ok'] ?? false) &&
            array_column($view['targets'] ?? [], 'target_id') === [$state['wp_target']],
            'Operator visibility escaped permitted WordPress Target.');
        $hidden = $call($operator, 'ssh-command-run', [
            'target_id' => $state['ssh_target'], 'command' => 'printf should-not-run'], 'operator_denied_ssh');
        $check(! ($hidden['ok'] ?? false) && ($hidden['error']['code'] ?? null) === 'target_not_found',
            'Default-deny operator must receive target_not_found for hidden SSH.');
        $wp = $call($operator, 'wordpress-abilities-read', [
            'target_id' => $state['wp_target'], 'ability' => $existing], 'operator_wp');
        $check($wp['ok'] ?? false, 'Authorized operator could not use WordPress.');
    } finally {
        $operator->disconnect();
    }
    echo json_encode([
        'outcome' => 'PASS',
        'transport' => 'standalone official PHP MCP SDK, real HTTPS network socket',
        'installed_wp_existing' => $existing, 'installed_wp_new' => $novel,
        'downstream_wp_denial' => true, 'ssh_host_identity_verified' => true,
        'binary_sftp_bytes' => strlen($bytes), 'binary_sftp_sha256' => hash('sha256', $bytes),
        'invalid_token' => 'HTTP 401', 'disabled_client_profile' => 'HTTP 401',
        'never_granted_client_profile' => 'token issuance denied',
        'operator_wp_only' => true, 'cross_target_denied' => true,
        'merged_bridge_unicode' => $bridgeText,
        'client_peak_memory_bytes' => memory_get_peak_usage(true),
        'latency_ms' => $timings,
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT)."\n";
} finally {
    $client->disconnect();
}
