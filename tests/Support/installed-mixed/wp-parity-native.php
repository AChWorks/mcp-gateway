<?php

declare(strict_types=1);
use WP_AI_Bridge\Support\Payload_Settings;
use WP_AI_Bridge\Support\Transfer_Settings;

// CLI-only observations and setup inside the existing disposable installation.
// Never expose private paths or lease identities in retained test evidence.
if (! defined('WP_CLI') || ! WP_CLI || ! defined('WP_TEMP_DIR')
    || ! is_dir((string) WP_TEMP_DIR)
    || realpath((string) WP_TEMP_DIR) !== realpath(dirname(ABSPATH, 1).'/wp-private-tmp')
    || ! str_starts_with(basename(dirname(ABSPATH, 1)), 'mcp-gateway-installed-112-')) {
    throw new RuntimeException('Expected the owned disposable WordPress fixture.');
}
wp_set_current_user(1);
$mode = $args[0] ?? '';
$prefix = $args[1] ?? '';
if (! preg_match('/^mixed-parity-[a-f0-9]{16}$/D', $prefix)) {
    throw new RuntimeException('Invalid disposable parity identity.');
}
$observe = static function (string $slug): array {
    // Inspect persisted native fields, independently of either MCP response.
    global $wpdb;
    $rows = $wpdb->get_results($wpdb->prepare(
        "SELECT ID, post_author, post_status, post_title, post_content FROM {$wpdb->posts} WHERE post_type = 'post' AND post_name = %s",
        $slug,
    ), ARRAY_A);
    if (! is_array($rows)) {
        throw new RuntimeException('Could not observe stored draft.');
    }

    return array_map(static fn (array $row): array => [
        'id' => (int) $row['ID'], 'principal_id' => (int) $row['post_author'],
        'status' => $row['post_status'], 'title' => $row['post_title'],
        'content_sha256' => hash('sha256', $row['post_content']),
        'content_bytes' => strlen($row['post_content']),
    ], $rows);
};
$slug = static function (string $suffix) use ($prefix): string {
    if (! in_array($suffix, ['denied', 'direct', 'routed'], true)) {
        throw new RuntimeException('Invalid owned post suffix.');
    }

    return $prefix.'-'.$suffix;
};
switch ($mode) {
    case 'builder-on':
    case 'builder-off':
        $before = get_option('wp_ai_bridge_settings');
        if (! is_array($before) || ! isset($before['site_read'], $before['native_abilities'])) {
            throw new RuntimeException('Unexpected baseline Bridge policy.');
        }
        $before['builder_write'] = $mode === 'builder-on' ? 1 : 0;
        update_option('wp_ai_bridge_settings', $before);
        $result = ['builder_write' => (int) get_option('wp_ai_bridge_settings')['builder_write']];
        break;
    case 'policy':
        $payload = (new Payload_Settings)->all();
        $transfer = (new Transfer_Settings)->all();
        $result = ['response_bytes' => $payload['response_kib'] * 1024,
            'request_bytes' => $transfer['request_kib'] * 1024];
        break;
    case 'lease-inventory':
        $files = glob(realpath((string) WP_TEMP_DIR).'/wpai-transfer-*/*');
        if ($files === false) {
            throw new RuntimeException('Could not inspect fixture transfer inventory.');
        }
        $result = ['lease_files' => count(array_filter($files, static fn (string $path): bool => preg_match('/^[a-f0-9]{64}\./D', basename($path)) === 1))];
        break;
    case 'post':
        $result = $observe($slug($args[2] ?? ''));
        break;
    case 'media':
        $bytes = base64_encode(random_bytes(131072));
        $upload = wp_upload_bits($prefix.'.txt', null, $bytes);
        if (! empty($upload['error']) || ! is_file($upload['file'] ?? '')) {
            throw new RuntimeException('Native disposable Media source creation failed.');
        }
        $id = wp_insert_attachment([
            'post_title' => $prefix, 'post_mime_type' => 'text/plain',
            'post_status' => 'inherit', 'post_author' => 1,
        ], $upload['file'], 0, true);
        if (is_wp_error($id) || (int) $id < 1 || get_attached_file((int) $id) !== $upload['file']) {
            throw new RuntimeException('Native Media attachment was not persisted.');
        }
        $result = ['media_id' => (int) $id, 'bytes' => filesize($upload['file']),
            'sha256' => hash_file('sha256', $upload['file'])];
        break;
    case 'lease':
        $id = $args[2] ?? '';
        if (! preg_match('/^[a-f0-9]{64}$/D', $id)) {
            throw new RuntimeException('Invalid private lease identity.');
        }
        $base = realpath((string) WP_TEMP_DIR);
        $roots = glob($base.'/wpai-transfer-*', GLOB_ONLYDIR);
        if (! is_array($roots) || count($roots) !== 1 || is_link($roots[0])) {
            throw new RuntimeException('Private provider storage escaped its fixture or was ambiguous.');
        }
        $files = glob($roots[0].'/'.$id.'.*');
        if ($files === false) {
            throw new RuntimeException('Could not inspect exact owned transfer.');
        }
        $payload = $roots[0].'/'.$id.'.bytes';
        $result = ['files' => count($files), 'bytes' => is_file($payload) ? filesize($payload) : null,
            'sha256' => is_file($payload) ? hash_file('sha256', $payload) : null];
        break;
    case 'cleanup':
        $removed = 0;
        foreach (['direct', 'routed'] as $suffix) {
            $rows = $observe($slug($suffix));
            if (count($rows) !== 1 || $rows[0]['status'] !== 'draft' || $rows[0]['principal_id'] !== 1
                || ! wp_delete_post($rows[0]['id'], true) || $observe($slug($suffix)) !== []) {
                throw new RuntimeException('Native owned draft cleanup failed.');
            }
            $removed++;
        }
        $id = (int) ($args[2] ?? 0);
        $attachment = get_post($id);
        if (! $attachment || $attachment->post_type !== 'attachment' || $attachment->post_title !== $prefix) {
            throw new RuntimeException('Unexpected native Media cleanup identity.');
        }
        $path = get_attached_file($id);
        if (! is_string($path) || ! is_file($path) || ! wp_delete_attachment($id, true)
            || get_post($id) || file_exists($path)) {
            throw new RuntimeException('Native owned Media cleanup failed.');
        }
        $result = ['drafts_removed' => $removed, 'media_removed' => true];
        break;
    default:
        throw new RuntimeException('Unsupported native parity fixture operation.');
}
echo json_encode($result, JSON_THROW_ON_ERROR)."\n";
