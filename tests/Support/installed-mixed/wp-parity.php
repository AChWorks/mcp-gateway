<?php

declare(strict_types=1);

use Mcp\Client;

/**
 * Extend the existing same-grant SDK comparator, without adding a second
 * installation, provider mock, or Gateway per-Ability authorization rule.
 */
function qualifyWordpressMutationAndTransfer(
    string $root,
    array $state,
    Client $direct,
    Client $gateway,
    Closure $connect,
    Closure $call,
    Closure $check,
    array &$wire,
    array &$toolErrors,
): array {
    $prefix = 'mixed-parity-'.bin2hex(random_bytes(8));
    $run = static function (array $command, string $mode) use ($root): array {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root.'/gateway');
        if (! is_resource($process)) {
            throw new RuntimeException('Could not start disposable native observation.');
        }
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        // Native CLI output can contain private paths; never publish it.
        stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $status = proc_close($process);
        if ($status !== 0) {
            throw new RuntimeException('Disposable native observation failed: '.$mode.' (exit '.$status.').');
        }

        return json_decode((string) $stdout, true, 512, JSON_THROW_ON_ERROR);
    };
    $native = static fn (string $mode, string ...$args): array => $run([
        PHP_BINARY, $root.'/wp-cli.phar', '--path='.$root.'/wp', '--user=mixedadmin',
        'eval-file', $root.'/gateway/tests/Support/installed-mixed/wp-parity-native.php', $mode, $prefix, ...$args,
    ], $mode);
    $setting = static fn (string $mode, string ...$args): array => $run([
        'env', 'MIXED_STATE_FILE='.$root.'/secrets/state.json', PHP_BINARY,
        $root.'/gateway/tests/Support/installed-mixed/seed.php', 'wp-parity', $mode, ...$args,
    ], $mode);
    $invoke = static function (string $route, string $ability, array $input, string $label, ?Client $actor = null) use ($direct, $gateway, $state, $call): array {
        return $route === 'direct'
            ? $call($direct, 'mcp-adapter-execute-ability', ['ability_name' => $ability, 'parameters' => $input], $label)
            : $call($actor ?? $gateway, 'wordpress-ability-execute', ['target_id' => $state['wp_target'], 'ability' => $ability, 'input' => $input], $label);
    };
    $success = static function (string $route, string $ability, array $input, string $label) use ($invoke, $check): array {
        $reply = $invoke($route, $ability, $input, $label);
        $check(($reply[$route === 'direct' ? 'success' : 'ok'] ?? false) === true,
            'Positive WordPress parity case failed: '.$label.' ('.($reply['error']['code'] ?? 'provider result').').');
        $data = $reply[$route === 'direct' ? 'data' : 'result'] ?? null;
        $check(is_array($data), 'Missing WordPress parity result: '.$label);

        return $data;
    };
    $denial = static function (string $route, string $ability, array $input, string $label, string $code = 'downstream_rejected', ?Client $actor = null) use ($invoke, $check, &$toolErrors): array {
        $reply = $invoke($route, $ability, $input, $label, $actor);
        if ($route === 'direct') {
            $check(($toolErrors[$label] ?? false) === true && ($reply['success'] ?? false) !== true,
                'Direct provider did not reject '.$label);
        } else {
            $check(($reply['ok'] ?? true) === false && ($reply['error']['code'] ?? null) === $code,
                'Unexpected routed denial '.$label.' ('.($reply['error']['code'] ?? 'missing code').').');
        }

        return ['rejected' => true, 'gateway_code' => $route === 'routed' ? $code : null,
            'diagnostic_reference' => $reply['error']['diagnostic_reference'] ?? null];
    };
    $upsert = 'wp-ai-bridge/content-upsert';
    $read = 'wp-ai-bridge/content-read';
    $transfer = 'wp-ai-bridge/private-transfer';
    $export = 'wp-ai-bridge/transfer-media-export';
    $routes = ['direct', 'routed'];
    $check(($setting('grant')['same_downstream_grant'] ?? false) === true, 'Initial downstream grant differs.');
    $policy = $native('policy');
    $check($policy === ['response_bytes' => 512 * 1024, 'request_bytes' => 1024 * 1024], 'Provider policy mismatch.');
    $check($native('lease-inventory')['lease_files'] === 0, 'Unexpected baseline transfer inventory.');
    $create = ['action' => 'create', 'post_type' => 'post', 'status' => 'draft',
        'title' => 'Installed parity draft', 'content' => 'Initial stored draft'];
    $denials = [];
    foreach ($routes as $route) {
        $denials[$route.'_builder_create'] = $denial($route, $upsert, $create + [
            'slug' => $prefix.'-denied', 'operation_id' => $prefix.'-denied-'.$route,
        ], $route.'_builder_create_denied');
        $denials[$route.'_builder_stage'] = $denial($route, $transfer, [
            'action' => 'begin', 'purpose' => 'text', 'total_bytes' => 0, 'sha256' => hash('sha256', ''),
        ], $route.'_builder_stage_denied');
    }
    $check($native('lease-inventory')['lease_files'] === 0, 'Denied staging created a lease.');
    $check($native('post', 'denied') === [], 'Provider denied creation nevertheless stored a draft.');
    $check($native('builder-on')['builder_write'] === 1, 'Builder grant not enabled in disposable WP.');
    $catalogs = [];
    foreach ([$upsert => false, $transfer => true, $export => false] as $ability => $destructive) {
        $d = $call($direct, 'mcp-adapter-execute-ability', ['ability_name' => 'wp-ai-bridge/abilities-read',
            'parameters' => ['action' => 'get', 'name' => $ability]], 'parity_direct_catalog_'.$ability);
        $g = $call($gateway, 'wordpress-abilities-read', ['target_id' => $state['wp_target'], 'ability' => $ability], 'parity_routed_catalog_'.$ability);
        $item = $d['data']['items'][0] ?? null;
        $check(($d['success'] ?? false) === true && ($g['ok'] ?? false) === true && is_array($item)
            && ($item['name'] ?? null) === $ability && ($item['annotations']['readonly'] ?? null) === false
            && ($item['annotations']['destructive'] ?? null) === $destructive
            && $d['data'] === ($g['catalog'] ?? null), 'Effect/catalog parity failed for '.$ability);
        $catalogs[$ability] = $destructive ? 'destructive' : 'mutating';
    }
    $observeDraft = static function (string $route, int $id, string $body, string $phase) use ($success, $native, $check, $read, $routes): array {
        $observed = [];
        foreach ($routes as $reader) {
            $result = $success($reader, $read, ['action' => 'get', 'id' => $id], $route.'_'.$phase.'_'.$reader.'_readback');
            $observed[$reader] = $result['items'][0] ?? [];
        }
        $row = $native('post', $route);
        $item = $observed['direct'];
        $check($observed['direct'] === $observed['routed'] && ($item['id'] ?? null) === $id
            && ($item['status'] ?? null) === 'draft' && ($item['content'] ?? null) === $body
            && ($item['content_complete'] ?? false) === true && ($item['content_hash'] ?? null) === hash('sha256', $body)
            && is_string($item['modified_gmt'] ?? null) && strlen($item['state_hash'] ?? '') === 64
            && $row === [['id' => $id, 'principal_id' => 1, 'status' => 'draft', 'title' => 'Installed parity draft',
                'content_sha256' => hash('sha256', $body), 'content_bytes' => strlen($body)]],
            'Actual stored draft or cross-route readback differs: '.$route.' '.$phase);

        return $item;
    };
    $drafts = [];
    $ids = [];
    foreach ($routes as $route) {
        $created = $success($route, $upsert, $create + [
            'slug' => $prefix.'-'.$route, 'operation_id' => $prefix.'-'.$route,
        ], $route.'_draft_create');
        $id = $created['id'] ?? 0;
        $check(is_int($id) && $id > 0 && ! in_array($id, $ids, true), 'Missing/distinct create identity.');
        $ids[] = $id;
        $before = $observeDraft($route, $id, $create['content'], 'created');
        $update = ['action' => 'update', 'id' => $id, 'content' => 'Updated stored draft — سلام',
            'expected_modified_gmt' => $before['modified_gmt'], 'expected_state_hash' => $before['state_hash']];
        $updated = $success($route, $upsert, $update, $route.'_draft_update');
        $check(($updated['id'] ?? null) === $id, 'Updated different post.');
        $after = $observeDraft($route, $id, $update['content'], 'updated');
        $check($after['state_hash'] !== $before['state_hash'], 'Stored update identity did not change.');
        $stale = array_replace($update, ['content' => 'Must not overwrite']);
        foreach ($routes as $writer) {
            $denials[$route.'_stale_'.$writer] = $denial($writer, $upsert, $stale, $route.'_stale_'.$writer);
        }
        $check($observeDraft($route, $id, $update['content'], 'after_stale') === $after, 'Stale mutation changed stored state.');
        $drafts[$route] = ['created' => true, 'updated' => true, 'stored_principal_id' => 1,
            'content_sha256' => $after['content_hash'], 'stale_rejected_unchanged' => true];
        $check($native('builder-off')['builder_write'] === 0, 'Could not revoke Builder in fixture.');
        $fresh = array_replace($update, ['expected_modified_gmt' => $after['modified_gmt'],
            'expected_state_hash' => $after['state_hash'], 'content' => 'Must not update without Builder']);
        foreach ($routes as $writer) {
            $denials[$route.'_revoked_'.$writer] = $denial($writer, $upsert, $fresh, $route.'_revoked_'.$writer);
        }
        $check($observeDraft($route, $id, $update['content'], 'after_denial') === $after, 'Permission-denied mutation changed stored state.');
        $check($native('builder-on')['builder_write'] === 1, 'Could not restore disposable Builder grant.');
    }
    $limits = [];
    foreach ($routes as $route) {
        $limits[$route] = $success($route, $transfer, ['action' => 'limits'], $route.'_transfer_limits');
    }
    $check($limits['direct'] === $limits['routed'], 'Provider transfer policy differs by route.');
    $chunk = $limits['direct']['max_chunk_bytes'] ?? 0;
    $check(is_int($chunk) && $chunk > 0 && $chunk <= $limits['direct']['request_bytes'] && $limits['direct']['request_bytes'] === $policy['request_bytes'], 'Invalid advertised transfer window.');
    $cancel = static function (string $route, string $id, string $label) use ($success, $denial, $native, $check, $transfer): void {
        $receipt = $success($route, $transfer, ['action' => 'cancel', 'transfer_id' => $id], $label.'_cancel');
        $check(($receipt['state'] ?? null) === 'cancelled' && ($receipt['transfer_id'] ?? null) === $id, 'Cancellation receipt differs.');
        $denial($route, $transfer, ['action' => 'status', 'transfer_id' => $id], $label.'_cancelled_status');
        $check($native('lease', $id) === ['files' => 0, 'bytes' => null, 'sha256' => null], 'Private lease files survived cancellation.');
    };
    $inputs = [];
    $payload = random_bytes($chunk * 2 + 17);
    foreach ($routes as $route) {
        foreach (['empty' => '', 'multi' => $payload] as $kind => $bytes) {
            $label = $route.'_input_'.$kind;
            $hash = hash('sha256', $bytes);
            $begin = $success($route, $transfer, ['action' => 'begin', 'purpose' => 'text',
                'total_bytes' => strlen($bytes), 'sha256' => $hash], $label.'_begin');
            $id = $begin['transfer_id'] ?? '';
            $check(preg_match('/^[a-f0-9]{64}$/D', $id) === 1 && ($begin['received_bytes'] ?? null) === 0, 'Missing input lease identity.');
            $offset = 0;
            $windows = 0;
            if ($bytes !== '') {
                $denial($route, $transfer, ['action' => 'append', 'transfer_id' => $id, 'offset' => 1,
                    'content_base64' => base64_encode('gap')], $label.'_wrong_offset');
                $status = $success($route, $transfer, ['action' => 'status', 'transfer_id' => $id], $label.'_after_gap');
                $check(($status['received_bytes'] ?? null) === 0, 'Rejected append changed received offset.');
            }
            while ($offset < strlen($bytes)) {
                $part = substr($bytes, $offset, $chunk);
                $receipt = $success($route, $transfer, ['action' => 'append', 'transfer_id' => $id,
                    'offset' => $offset, 'content_base64' => base64_encode($part)], $label.'_append_'.$windows);
                $offset += strlen($part);
                $windows++;
                $check(($receipt['received_bytes'] ?? null) === $offset, 'Input append did not preserve exact offset.');
            }
            $verified = $success($route, $transfer, ['action' => 'verify', 'transfer_id' => $id], $label.'_verify');
            $stored = $native('lease', $id);
            $check(($verified['state'] ?? null) === 'verified' && ($verified['complete'] ?? false) === true
                && ($verified['total_bytes'] ?? null) === strlen($bytes) && ($verified['sha256'] ?? null) === $hash
                && $stored['bytes'] === strlen($bytes) && $stored['sha256'] === $hash, 'Input lease integrity differs from native storage.');
            $denial($route, $transfer, ['action' => 'read', 'transfer_id' => $id, 'offset' => 0, 'max_bytes' => 1], $label.'_input_is_not_output');
            $cancel($route, $id, $label);
            $inputs[$label] = ['bytes' => strlen($bytes), 'sha256' => $hash, 'windows' => $windows,
                'verified_native_storage' => true, 'input_read_denied' => true, 'cancelled_and_removed' => true];
        }
    }
    $media = $native('media');
    $output = [];
    $measurements = [];
    $operator = Client::builder()->setClientInfo('mixed-parity-scoped-operator', '1')
        ->setInitTimeout(8)->setRequestTimeout(30)->setMaxRetries(0)->build();
    $operator->connect($connect($state['operator_token']));
    try {
        foreach ($routes as $route) {
            $snapshot = $success($route, $export, ['media_id' => $media['media_id']], $route.'_media_export');
            $id = $snapshot['transfer_id'] ?? '';
            $stored = $native('lease', $id);
            $check(($snapshot['state'] ?? null) === 'verified' && ($snapshot['media_id'] ?? null) === $media['media_id']
                && ($snapshot['total_bytes'] ?? null) === $media['bytes'] && ($snapshot['sha256'] ?? null) === $media['sha256']
                && $stored['bytes'] === $media['bytes'] && $stored['sha256'] === $media['sha256'], 'Actual Media snapshot differs from source.');
            $readInput = ['action' => 'read', 'transfer_id' => $id, 'offset' => 0, 'max_bytes' => 1];
            $denials[$route.'_operator_mixed_read'] = $denial('routed', $transfer, $readInput, $route.'_operator_mixed_read', 'forbidden', $operator);
            $denials[$route.'_operator_mixed_cancel'] = $denial('routed', $transfer, ['action' => 'cancel', 'transfer_id' => $id],
                $route.'_operator_mixed_cancel', 'forbidden', $operator);
            if ($route === 'direct') {
                // Measure the actual decoded JSON-RPC body, including Adapter
                // text/structured duplication, before deciding whether a
                // Gateway rejection is expected at its independent budget.
                foreach (['fixture' => 96 * 1024, 'default' => 64 * 1024] as $profile => $budget) {
                    $actual = $setting($profile);
                    $check(($actual['response_bytes'] ?? null) === $budget && ($actual['readonly_bytes'] ?? null) === 512 * 1024,
                        'Gateway effective budget differs from selected test profile.');
                    foreach (array_unique([min($chunk, 48 * 1024), min($chunk, 32 * 1024), min($chunk, 16 * 1024)]) as $size) {
                        $label = 'mixed_window_'.$profile.'_'.$size;
                        $input = array_replace($readInput, ['offset' => $profile === 'default' ? 1 : 0, 'max_bytes' => $size]);
                        $data = $success('direct', $transfer, $input, $label.'_direct');
                        $http = array_values(array_filter($wire[$label.'_direct'] ?? [], static fn (array $x): bool => $x['method'] === 'POST' && $x['status'] === 200));
                        $decoded = $http[0]['decoded_response_bytes'] ?? null;
                        $check(count($http) === 1 && is_int($decoded) && $decoded > 0 && $decoded <= $policy['response_bytes']
                            && str_contains((string) ($http[0]['content_type'] ?? ''), 'application/json'), 'Actual decoded provider JSON envelope unavailable.');
                        $raw = base64_decode($data['content_base64'] ?? '', true);
                        $check(is_string($raw) && hash('sha256', $raw) === ($data['chunk_sha256'] ?? null), 'Measured direct window failed integrity.');
                        if ($decoded > $budget) {
                            $rejected = $denial('routed', $transfer, $input, $label.'_routed', 'outcome_unknown');
                            $diagnostic = $setting('diagnostic', $rejected['diagnostic_reference'] ?? '');
                            $check($diagnostic === ['outcome' => 'unknown', 'error_code' => 'outcome_unknown',
                                'failure_origin' => 'gateway_response', 'limit_bytes' => $budget, 'retry_safe' => false],
                                'Gateway did not retain the actual response-bound/unknown-effect evidence.');
                        } else {
                            $routed = $success('routed', $transfer, $input, $label.'_routed');
                            $check($routed === $data, 'Fitting direct/routed transfer windows differ.');
                        }
                        $measurements[] = ['profile' => $profile, 'gateway_budget_bytes' => $budget, 'requested_raw_bytes' => $size,
                            'received_raw_bytes' => strlen($raw), 'provider_decoded_mcp_bytes' => $decoded,
                            'gateway_result' => $decoded > $budget ? 'outcome_unknown' : 'exact'];
                    }
                }
            }
            // Independent whole-byte digest via both paths; request a
            // supported smaller window, never reinterpret mixed effects.
            foreach ($routes as $reader) {
                $offset = 0;
                $windows = 0;
                $hash = hash_init('sha256');
                do {
                    $data = $success($reader, $transfer, array_replace($readInput, [
                        'offset' => $offset, 'max_bytes' => min($chunk, 16 * 1024),
                    ]), $route.'_output_'.$reader.'_'.$windows);
                    $raw = base64_decode($data['content_base64'] ?? '', true);
                    $next = $data['read_next_offset'] ?? null;
                    $check(is_string($raw) && ($data['read_offset'] ?? null) === $offset && is_int($next)
                        && $next > $offset && $next <= $media['bytes'] && strlen($raw) === $next - $offset
                        && hash('sha256', $raw) === ($data['chunk_sha256'] ?? null)
                        && ($data['sha256'] ?? null) === $media['sha256'], 'Output continuation integrity/offset differs.');
                    hash_update($hash, $raw);
                    $offset = $next;
                    $windows++;
                } while (($data['read_complete'] ?? false) !== true && $offset < $media['bytes']);
                $digest = hash_final($hash);
                $check(($data['read_complete'] ?? false) === true && $offset === $media['bytes'] && $digest === $media['sha256'],
                    'External SDK did not receive complete output digest.');
                $output[$route.'_export_'.$reader.'_read'] = ['bytes' => $offset, 'windows' => $windows, 'sha256' => $digest,
                    'gateway_budget_bytes' => ($route === 'direct' ? 64 : 96) * 1024];
            }
            // v0.7.4 reserves release for native-effect receipts; a verified
            // immutable export is disposed by cancel, not release.
            $denials[$route.'_verified_export_release'] = $denial($route, $transfer, ['action' => 'release', 'transfer_id' => $id], $route.'_verified_export_release');
            $cancel($route, $id, $route.'_export');
            $denial($route, $transfer, $readInput, $route.'_export_after_cancel');
            if ($route === 'direct') {
                $check($setting('fixture')['response_bytes'] === 96 * 1024, 'Could not restore fixture response budget.');
            }
        }
    } finally {
        $operator->disconnect();
    }
    $check($native('builder-off')['builder_write'] === 0, 'Could not restore baseline Builder policy.');
    $check($native('lease-inventory')['lease_files'] === 0, 'Owned transfer inventory not empty after cleanup.');
    $cleanup = $native('cleanup', (string) $media['media_id']);
    $check($cleanup === ['drafts_removed' => 2, 'media_removed' => true], 'Native fixture cleanup was not verified.');
    $check(($setting('grant')['same_downstream_grant'] ?? false) === true, 'Downstream grant changed during parity comparison.');

    foreach ($denials as &$entry) {
        unset($entry['diagnostic_reference']);
    }
    unset($entry);

    return ['same_downstream_grant' => true, 'catalog_effects' => $catalogs, 'drafts' => $drafts, 'denials' => $denials,
        'provider_response_bytes' => $policy['response_bytes'],
        'provider_transfer_policy' => array_intersect_key($limits['direct'], array_flip(['max_chunk_bytes', 'request_bytes', 'max_file_bytes', 'max_active_bytes', 'max_sessions', 'lease_seconds'])),
        'input_staging' => $inputs, 'output_exports' => $output, 'decoded_response_budget_measurements' => $measurements,
        'cleanup' => $cleanup + ['all_owned_leases_cancelled_and_removed' => true, 'builder_grant_restored' => true]];
}
