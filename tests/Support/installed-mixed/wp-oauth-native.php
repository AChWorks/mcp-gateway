<?php

declare(strict_types=1);

use WP_AI_Bridge\Auth\OAuth_Store;

// A pinned, disposable provider fixture, not a production token-management
// command. Only existing authenticated artifacts may be aged or revoked.
// Tokens cross this private process boundary via stdin, never argv or evidence.
if (! defined('WP_CLI') || ! WP_CLI || ! defined('WP_TEMP_DIR')
    || ! is_dir((string) WP_TEMP_DIR)
    || realpath((string) WP_TEMP_DIR) !== realpath(dirname(ABSPATH, 1).'/wp-private-tmp')
    || ! str_starts_with(basename(dirname(ABSPATH, 1)), 'mcp-gateway-installed-112-')) {
    throw new RuntimeException('Expected the owned disposable WordPress fixture.');
}
$input = json_decode((string) stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
$mode = $input['mode'] ?? '';
$client = $input['client_id'] ?? '';
$resource = $input['resource_url'] ?? '';
if ($client !== 'https://11.22.33.45/oauth/client.json'
    || ! is_string($resource) || ! str_starts_with($resource, 'https://11.22.33.44/')) {
    throw new RuntimeException('Unexpected disposable OAuth grant binding.');
}

$store = new OAuth_Store;
$artifacts = [
    OAuth_Store::TYPE_ACCESS => $input['access_token'] ?? null,
    OAuth_Store::TYPE_REFRESH => $input['refresh_token'] ?? null,
];
$observe = static function () use ($artifacts, $store, $client, $resource): array {
    $result = [];
    foreach ($artifacts as $type => $token) {
        $claims = $store->read($type, $token, false, $client);
        if ($claims === false) {
            $result[$type] = null;

            continue;
        }
        if ((int) ($claims['user_id'] ?? 0) !== 1
            || ($claims['client_id'] ?? null) !== $client
            || ($claims['resource'] ?? null) !== $resource
            || ! is_string($claims['scope'] ?? null)) {
            throw new RuntimeException('Native OAuth grant identity differs.');
        }
        $result[$type] = ['expires_at' => (int) $claims['expires_at'],
            'principal_id' => (int) $claims['user_id'], 'scopes' => explode(' ', $claims['scope']),
            'client_revision' => (int) ($claims['client_revision'] ?? 0)];
    }

    return $result;
};
$before = $observe();
if ($mode === 'age') {
    // Shift absolute expiry in the exact two records, not global time or
    // provider code. Keep the original secret hash, identity and grant.
    $age = $input['seconds'] ?? null;
    if (! is_int($age) || $age < 1 || $before['access'] === null || $before['refresh'] === null
        || $before['refresh']['expires_at'] - $age <= time()) {
        throw new RuntimeException('Invalid simulated age for a still renewable disposable grant.');
    }
    foreach ($artifacts as $type => $token) {
        $prefix = $type === OAuth_Store::TYPE_ACCESS ? 'wpai_a' : 'wpai_r';
        if (! is_string($token) || ! preg_match('/^'.$prefix.'\.([A-Za-z0-9_-]{20,40})\.[A-Za-z0-9_-]{40,80}$/D', $token, $match)) {
            throw new RuntimeException('Unexpected pinned OAuth artifact format.');
        }
        $key = 'wpai_oauth_'.$type.'_'.$match[1];
        $refresh = $type === OAuth_Store::TYPE_REFRESH;
        $record = $refresh ? get_option($key, false) : get_transient($key);
        if (! is_array($record) || (int) ($record['expires_at'] ?? 0) !== $before[$type]['expires_at']) {
            throw new RuntimeException('Authenticated native artifact storage differs.');
        }
        $oldExpiry = (int) $record['expires_at'];
        $record['expires_at'] = $oldExpiry - $age;
        if ($refresh) {
            if (! update_option($key, $record, false)) {
                throw new RuntimeException('Could not age the exact native refresh record.');
            }
            // Keep the provider's native cleanup event aligned with its aged
            // record. No unrelated event or token is modified.
            wp_unschedule_event($oldExpiry + MINUTE_IN_SECONDS, 'wpai_oauth_cleanup_refresh_artifact', [$key, $oldExpiry]);
            if (! wp_schedule_single_event($record['expires_at'] + MINUTE_IN_SECONDS, 'wpai_oauth_cleanup_refresh_artifact', [$key, $record['expires_at']])) {
                throw new RuntimeException('Could not align disposable refresh cleanup event.');
            }
        } elseif (! set_transient($key, $record, max(1, $record['expires_at'] - time()))) {
            throw new RuntimeException('Could not age the exact native access record.');
        }
    }
} elseif ($mode === 'revoke-refresh') {
    if ($before['refresh'] === null || ! $store->revoke($artifacts[OAuth_Store::TYPE_REFRESH], $client)) {
        throw new RuntimeException('Could not revoke the exact disposable native refresh grant.');
    }
} elseif ($mode !== 'observe') {
    throw new RuntimeException('Unsupported native OAuth fixture operation.');
}

echo json_encode($observe(), JSON_THROW_ON_ERROR)."\n";
