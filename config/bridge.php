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
        'redirect_uri' => $baseUrl.'/oauth/sites/callback',
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
    ],
    'health' => [
        'stale_after_hours' => 24,
    ],
];
