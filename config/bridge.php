<?php

$baseUrl = rtrim((string) env('APP_URL', 'http://127.0.0.1:8000'), '/');
$resolvePath = static function (string $path): string {
    if (preg_match('~^(?:[A-Za-z]:[\\\\/]|/)~', $path) === 1) {
        return $path;
    }

    return base_path($path);
};

return [
    'connector_type' => 'wp_ai_bridge',
    'client' => [
        'id' => $baseUrl.'/oauth/client.json',
        'name' => (string) env('APP_NAME', 'MCP Gateway'),
        'redirect_uri' => $baseUrl.'/oauth/targets/callback',
        'jwks_uri' => $baseUrl.'/oauth/jwks.json',
        'assertion_ttl_seconds' => (int) env('BRIDGE_CLIENT_ASSERTION_TTL_SECONDS', 300),
    ],
    'keys' => [
        'private' => $resolvePath((string) env('BRIDGE_CLIENT_PRIVATE_KEY_PATH', 'storage/app/private/bridge-client/private.key')),
        'public' => $resolvePath((string) env('BRIDGE_CLIENT_PUBLIC_KEY_PATH', 'storage/app/private/bridge-client/public.key')),
    ],
    'oauth' => [
        'scope' => 'mcp:use',
        'offline_scope' => 'offline_access',
        'flow_ttl_seconds' => (int) env('BRIDGE_OAUTH_FLOW_TTL_SECONDS', 600),
    ],
    'http' => [
        'connect_timeout_seconds' => (int) env('BRIDGE_REMOTE_CONNECT_TIMEOUT_SECONDS', 2),
        'request_timeout_seconds' => (int) env('BRIDGE_REMOTE_REQUEST_TIMEOUT_SECONDS', 5),
        'max_response_bytes' => (int) env('BRIDGE_REMOTE_MAX_RESPONSE_BYTES', 65536),
        // Readonly tools can legitimately return larger structured results than OAuth/metadata.
        // SafeHttpClient always clamps both limits to its absolute decoded-body ceiling.
        'readonly_tool_max_response_bytes' => (int) env('BRIDGE_REMOTE_READONLY_TOOL_MAX_RESPONSE_BYTES', 262144),
    ],
    // Optional request-local timings on Activity; off until explicitly enabled.
    // Only slow successes and failures are retained; no new log store or daemon.
    'timing' => [
        'enabled' => filter_var(env('BRIDGE_TIMING_ENABLED', false), FILTER_VALIDATE_BOOLEAN),
        'minimum_ms' => (int) env('BRIDGE_TIMING_MINIMUM_MS', 1500),
    ],
    // Optional host-specific FileParams discovery plus per-WordPress signed-file
    // staging limits, separate from existing SSH whole-file and JSON paths.
    'file_input' => [
        // Park native ChatGPT FileParams until real host-provided ingress is verified.
        // Default OFF only hides these client-specific MCP tools; the existing
        // SSH browser, binary HTTP sidecar and bounded SFTP tools are unaffected.
        'enabled' => filter_var(env('CHATGPT_FILEPARAMS_ENABLED', false), FILTER_VALIDATE_BOOLEAN),
        'max_bytes' => (int) env('CHATGPT_WP_FILE_MAX_BYTES', 8388608),
        'max_seconds' => (int) env('CHATGPT_WP_FILE_MAX_SECONDS', 120),
        // Shared, DB-serialized admission: local spool(s) are reserved
        // before any signed ChatGPT URL is fetched.
        'capacity' => [
            'max_active' => (int) env('CHATGPT_FILE_MAX_ACTIVE', 4),
            'max_reserved_bytes' => (int) env('CHATGPT_FILE_MAX_RESERVED_BYTES', 134217728),
            'wordpress_max_active' => (int) env('CHATGPT_FILE_WP_MAX_ACTIVE', 2),
            'ssh_max_active' => (int) env('CHATGPT_FILE_SSH_MAX_ACTIVE', 2),
        ],
    ],
    'health' => [
        'stale_after_hours' => 24,
    ],
];
