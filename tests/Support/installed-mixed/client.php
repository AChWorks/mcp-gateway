<?php

declare(strict_types=1);
use GuzzleHttp\Client as Http;
use GuzzleHttp\TransferStats;
use Mcp\Client;
use Mcp\Client\Transport\HttpTransport;

$root = (string) getenv('MIXED_ROOT');
require $root.'/gateway/vendor/autoload.php';
require __DIR__.'/wp-parity.php';
$state = json_decode((string) file_get_contents($root.'/secrets/state.json'), true, 512, JSON_THROW_ON_ERROR);
$longSeconds = (int) (getenv('MIXED_SSH_LONG_SECONDS') ?: 0);
$longTimeout = (int) (getenv('MIXED_SSH_LONG_TIMEOUT') ?: 0);
$httpExchanges = [];
$http = new Http(['verify' => $root.'/secrets/tls.crt', 'proxy' => '', 'http_errors' => false, 'timeout' => $longTimeout > 0 ? $longTimeout + 30 : 30,
    'on_stats' => static function (TransferStats $stats) use (&$httpExchanges): void {
        $native = $stats->getHandlerStats();
        $httpExchanges[] = [
            'uploaded_bytes' => isset($native['size_upload']) ? (int) $native['size_upload'] : null,
            'downloaded_bytes' => isset($native['size_download']) ? (int) $native['size_download'] : null,
            'status' => $stats->getResponse()?->getStatusCode(),
            'method' => $stats->getRequest()->getMethod(),
            'decoded_response_bytes' => $stats->getResponse()?->getBody()->getSize(),
            'content_type' => $stats->getResponse()?->getHeaderLine('Content-Type'),
        ];
    },
]);
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
$wire = [];
$toolErrors = [];
$call = static function (Client $c, string $name, array $args, string $label, ?float $timeout = null) use (&$timings, &$wire, &$httpExchanges, &$toolErrors): array {
    $before = count($httpExchanges);
    $start = hrtime(true);
    $result = $c->callTool($name, $args, timeoutSeconds: $timeout);
    $timings[$label] = round((hrtime(true) - $start) / 1000000, 2);
    $wire[$label] = array_slice($httpExchanges, $before);
    $toolErrors[$label] = $result->isError;

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
    // The actual pinned released Bridge supports source-bound UTF-8 windows.
    // Check complete client receipt, not merely provider staging.
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
        'whole_utf8_bytes' => strlen($source),
        'sha256' => hash('sha256', $source),
        'windows' => $windows,
        'max_decoded_window_bytes' => $maxWindowBytes,
        'max_gateway_result_json_bytes' => $largestResultBytes,
        'wrong_source_hash_denied' => true,
    ];
    // Compare native Adapter and Gateway responses using the SAME ephemeral
    // WordPress OAuth grant (not a different WordPress account or ChatGPT).
    $direct = Client::builder()->setClientInfo('installed-mixed-direct-bridge', '1.0')
        ->setInitTimeout(8)->setRequestTimeout(30)->setMaxRetries(0)->build();
    try {
        $direct->connect(new HttpTransport(
            endpoint: $state['wp_direct']['resource'],
            headers: ['Authorization' => 'Bearer '.$state['wp_direct']['access_token']],
            httpClient: $http,
        ));
        $ability = 'gateway-mixed-test/digest-read';
        $directCatalog = $call($direct, 'mcp-adapter-execute-ability', [
            'ability_name' => 'wp-ai-bridge/abilities-read',
            'parameters' => ['action' => 'get', 'name' => $ability],
        ], 'wp_direct_catalog');
        $gatewayCatalog = $call($client, 'wordpress-abilities-read', [
            'target_id' => $state['wp_target'], 'ability' => $ability,
        ], 'wp_digest_catalog');
        $check(($directCatalog['success'] ?? false) === true
            && ($directCatalog['data']['items'][0]['name'] ?? null) === $ability
            && $directCatalog['data'] === ($gatewayCatalog['catalog'] ?? null),
            'Direct-vs-Gateway digest Ability catalog differs.');
        $payload = str_repeat('x', 1000000);
        $directResult = $call($direct, 'mcp-adapter-execute-ability', [
            'ability_name' => $ability, 'parameters' => ['payload' => $payload],
        ], 'wp_direct_near_mib_input');
        $routedResult = $call($client, 'wordpress-ability-execute', [
            'target_id' => $state['wp_target'], 'ability' => $ability,
            'input' => ['payload' => $payload],
        ], 'wp_routed_near_mib_input');
        $expectedDigest = ['bytes' => strlen($payload), 'sha256' => hash('sha256', $payload), 'principal_id' => 1];
        $check(($directResult['success'] ?? false) === true && ($routedResult['ok'] ?? false) === true
            && ($directResult['data'] ?? null) === $expectedDigest && ($routedResult['result'] ?? null) === $expectedDigest,
            'Near-1-MiB WordPress input or same-principal result parity failed. Routed error: '.
            json_encode($routedResult['error'] ?? [], JSON_THROW_ON_ERROR));
        $wpInput = $expectedDigest;
        unset($payload, $directResult, $routedResult);
        $wpParity = qualifyWordpressMutationAndTransfer($root, $state, $direct, $client, $connect, $call, $check, $wire, $toolErrors);
    } finally {
        $direct->disconnect();
    }
    $ssh = $call($client, 'ssh-command-run', [
        'target_id' => $state['ssh_target'], 'command' => "printf 'installed-ssh-ok'"], 'ssh_command');
    $check(($ssh['result']['stdout'] ?? null) === 'installed-ssh-ok', 'Host-key verified SSH failed.');
    // A configured input maximum is not a promise that a native SSH exec
    // request fits the server packet limit or its login shell's argv limit.
    // Use a harmless unique marker AFTER the padding; measure, never replay.
    $commandInputs = [];
    foreach ([65536, 131071, 131072, 524288] as $size) {
        $marker = 'exec-input-'.$size;
        $tail = "\nprintf '".$marker."'; exit 7";
        $command = '# '.str_repeat('x', $size - 2 - strlen($tail)).$tail;
        $reply = $call($client, 'ssh-command-run', [
            'target_id' => $state['ssh_target'], 'command' => $command,
        ], 'ssh_input_'.$size);
        $result = $reply['result'] ?? [];
        $exact = ($reply['ok'] ?? false) === true && ($result['status'] ?? null) === 'completed'
            && ($result['stdout'] ?? null) === $marker && ($result['exit_code'] ?? null) === 7;
        if ($size === 65536) {
            $check($exact, '64 KiB positive native command-input control failed.');
        }
        if (($result['status'] ?? null) === 'outcome_unknown') {
            $check(($reply['ok'] ?? true) === false && ($result['complete'] ?? true) === false
                && array_key_exists('exit_code', $result) && $result['exit_code'] === null,
                'Unknown native exec outcome must not invent completion or exit evidence.');
        }
        $commandInputs[] = [
            'input_bytes' => strlen($command),
            'exact_marker_and_exit' => $exact,
            'ok' => $reply['ok'] ?? null,
            'status' => $result['status'] ?? null,
            'exit_code' => $result['exit_code'] ?? null,
            'error_code' => $reply['error']['code'] ?? null,
            'argument_list_too_long' => str_contains((string) ($result['stderr'] ?? ''), 'Argument list too long'),
            'diagnostic_reference' => $reply['error']['diagnostic_reference'] ?? null,
        ];
    }
    // This is a measured compatibility matrix, not a passing claim for
    // unsupported sizes. Confirm the ordinary native path still works.
    $afterInput = $call($client, 'ssh-command-run', [
        'target_id' => $state['ssh_target'], 'command' => "printf 'after-input-probe'",
    ], 'ssh_after_input_probe');
    $check(($afterInput['result']['stdout'] ?? null) === 'after-input-probe'
        && ($afterInput['result']['exit_code'] ?? null) === 0, 'Native command after input probe failed.');
    // Same admitted byte ceiling, explicitly staged instead of native argv.
    $tail = "\n".'printf "staged-512k-ok"; printf "staged-512k-err" >&2; exit 7';
    $script = '# '.str_repeat('x', 524288 - 2 - strlen($tail)).$tail;
    $staged = $call($client, 'ssh-script-run', [
        'target_id' => $state['ssh_target'], 'script' => $script, 'interpreter' => '/bin/sh',
    ], 'ssh_staged_512k');
    $stageResult = $staged['result'] ?? [];
    $check(($staged['ok'] ?? false) === true && ($stageResult['status'] ?? null) === 'completed'
        && ($stageResult['script_bytes'] ?? null) === 524288
        && ($stageResult['script_staging_verified'] ?? false) === true
        && ($stageResult['script_launch_attempted'] ?? false) === true
        && ($stageResult['stdout'] ?? null) === 'staged-512k-ok'
        && ($stageResult['stderr'] ?? null) === 'staged-512k-err'
        && ($stageResult['exit_code'] ?? null) === 7
        && ($stageResult['temporary_cleanup_confirmed'] ?? false) === true,
        'Verified 512 KiB staged synchronous script failed: '.json_encode($staged, JSON_THROW_ON_ERROR));
    $stageEvidence = [
        'input_bytes' => strlen($script), 'interpreter' => '/bin/sh',
        'script_staging_verified' => $stageResult['script_staging_verified'],
        'script_launch_attempted' => $stageResult['script_launch_attempted'],
        'stdout' => $stageResult['stdout'], 'stderr' => $stageResult['stderr'],
        'exit_code' => $stageResult['exit_code'], 'temporary_cleanup_confirmed' => $stageResult['temporary_cleanup_confirmed'],
        'duration_ms' => $stageResult['duration_ms'],
    ];
    unset($script, $staged, $stageResult);
    $bytes = random_bytes(524288);
    $file = '/home/'.getenv('MIXED_SSH_USER').'/mixed-'.bin2hex(random_bytes(8)).'.bin';
    try {
        $write = $call($client, 'ssh-file-write', [
            'target_id' => $state['ssh_target'], 'path' => $file, 'content_base64' => base64_encode($bytes)], 'sftp_write');
        $check(($write['result']['bytes_written'] ?? null) === strlen($bytes)
            && ($write['result']['integrity_check'] ?? null) === 'remote_readback_sha256', 'Binary write integrity/count wrong.');
        $stat = $call($client, 'ssh-file-stat', [
            'target_id' => $state['ssh_target'], 'path' => $file], 'sftp_stat');
        $check(($stat['result']['file']['size'] ?? null) === strlen($bytes), 'Binary stat size wrong.');
        $read = $call($client, 'ssh-file-read', [
            'target_id' => $state['ssh_target'], 'path' => $file, 'length' => strlen($bytes)], 'sftp_read');
        $back = base64_decode($read['result']['data'] ?? '', true);
        $check(is_string($back) && ($read['result']['end_of_file'] ?? false) === true && hash_equals($bytes, $back)
            && hash_equals(hash('sha256', $bytes), hash('sha256', $back)), 'Binary SFTP roundtrip wrong.');
    } finally {
        $cleanup = $call($client, 'ssh-command-run', [
            'target_id' => $state['ssh_target'], 'command' => 'rm -f -- '.escapeshellarg($file)], 'sftp_cleanup');
        $check($cleanup['ok'] ?? false, 'SFTP disposable payload not removed.');
    }
    $streams = $call($client, 'ssh-command-run', [
        'target_id' => $state['ssh_target'],
        'command' => "head -c 524289 /dev/zero | tr '\\000' x; head -c 524288 /dev/zero | tr '\\000' e >&2; exit 7",
    ], 'ssh_independent_output_windows')['result'] ?? [];
    $check(($streams['stdout'] ?? null) === str_repeat('x', 524288)
        && ($streams['stderr'] ?? null) === str_repeat('e', 524288)
        && ($streams['stdout_total_bytes'] ?? null) === 524289 && ($streams['stderr_total_bytes'] ?? null) === 524288
        && ($streams['stdout_truncated'] ?? null) === true && ($streams['stderr_truncated'] ?? null) === false
        && ($streams['exit_code'] ?? null) === 7, '512 KiB independent stdout/stderr client receipt or exit differs.');
    $streamEvidence = ['stdout_bytes' => $streams['stdout_bytes'], 'stderr_bytes' => $streams['stderr_bytes'],
        'stdout_total_bytes' => $streams['stdout_total_bytes'], 'stderr_total_bytes' => $streams['stderr_total_bytes'],
        'stdout_truncated' => $streams['stdout_truncated'], 'stderr_truncated' => $streams['stderr_truncated'],
        'exit_code' => $streams['exit_code']];
    unset($streams);
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
    $extended = null;
    if ($longTimeout > 0) {
        // Only an explicitly selected isolated qualification, never the
        // routine PR lane. No client retry or implicit Job conversion.
        $marker = 'long-exec-'.$longSeconds;
        $long = $call($client, 'ssh-command-run', [
            'target_id' => $state['ssh_target'],
            'command' => 'sleep '.$longSeconds."; printf '".$marker."'; exit 7",
            'timeout_seconds' => $longTimeout,
        ], 'ssh_extended_'.$longSeconds, $longTimeout + 30);
        $result = $long['result'] ?? [];
        $check(($long['ok'] ?? false) === true && ($result['status'] ?? null) === 'completed'
            && ($result['stdout'] ?? null) === $marker && ($result['exit_code'] ?? null) === 7
            && ($result['complete'] ?? false) === true
            && ($result['duration_ms'] ?? 0) >= $longSeconds * 1000
            && $timings['ssh_extended_'.$longSeconds] >= $longSeconds * 1000,
            'Extended native command did not return proven completion and duration.');
        $extended = [
            'requested_sleep_seconds' => $longSeconds, 'selected_timeout_seconds' => $longTimeout,
            'exit_code' => 7, 'gateway_duration_ms' => $result['duration_ms'],
            'client_duration_ms' => $timings['ssh_extended_'.$longSeconds],
        ];
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
        'released_bridge_unicode' => $bridgeText,
        'wp_same_grant_direct_routed_input' => $wpInput,
        'wp_mutation_transfer_parity' => $wpParity,
        'ssh_command_output_windows' => $streamEvidence,
        'ssh_command_input_measurements' => $commandInputs,
        'ssh_staged_script' => $stageEvidence,
        'ssh_extended_duration' => $extended,
        'http_wire_measurements' => $wire,
        'client_peak_memory_bytes' => memory_get_peak_usage(true),
        'latency_ms' => $timings,
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT)."\n";
} finally {
    $client->disconnect();
}
