<?php


// WP-CLI only, disposable fixture; no production plugin/provider mutation.
// WordPress itself stores the large source so client tests use genuine
// Bridge content-read through the real Adapter -> Gateway -> external MCP SDK.
if (! defined('WP_CLI') || ! WP_CLI) {
    throw new RuntimeException('This fixture requires isolated WP-CLI.');
}
$path = getenv('MIXED_LARGE_POST_FILE');
if (! is_string($path) || $path === '' || ! is_dir(dirname($path))) {
    throw new RuntimeException('Missing owned fixture output path.');
}
wp_set_current_user(1);
$body = str_repeat("سلام به دنیای آزاد 🌍🧪 — Gateway 128 KiB UTF-8\n", 6000);
$id = wp_insert_post([
    'post_title' => 'Gateway source-bound Unicode interoperability fixture',
    'post_content' => $body,
    'post_type' => 'post',
    'post_status' => 'publish',
    'post_author' => 1,
], true);
if (is_wp_error($id) || (int) $id < 1) {
    throw new RuntimeException('Could not persist the isolated post.');
}
$stored = get_post((int) $id);
if (! $stored || strlen($stored->post_content) < 131072) {
    throw new RuntimeException('Stored Unicode fixture does not cross the 128 KiB boundary.');
}
file_put_contents($path, json_encode([
    'post_id' => (int) $id,
    'bytes' => strlen($stored->post_content),
    'sha256' => hash('sha256', $stored->post_content),
], JSON_THROW_ON_ERROR));
