<?php

$issuer = rtrim((string) env('APP_URL', 'http://127.0.0.1:8000'), '/');
$resolvePath = static function (string $path): string {
    if (preg_match('~^(?:[A-Za-z]:[\\\\/]|/)~', $path) === 1) {
        return $path;
    }

    return base_path($path);
};

return [
    'issuer' => $issuer,
    'resource' => $issuer.'/mcp',
    'scope' => 'mcp',
    'offline_scope' => 'offline_access',
    'scopes' => ['mcp', 'offline_access'],

    'client' => [
        'id' => 'https://chatgpt.com/oauth/client.json',
        'metadata_cache_seconds' => (int) env('OAUTH_CLIENT_METADATA_CACHE_SECONDS', 300),
        'connect_timeout_seconds' => (int) env('OAUTH_REMOTE_CONNECT_TIMEOUT_SECONDS', 2),
        'request_timeout_seconds' => (int) env('OAUTH_REMOTE_REQUEST_TIMEOUT_SECONDS', 5),
        'max_response_bytes' => (int) env('OAUTH_REMOTE_MAX_RESPONSE_BYTES', 65536),
    ],

    'keys' => [
        'private' => $resolvePath((string) env('OAUTH_PRIVATE_KEY_PATH', 'storage/app/private/oauth/private.key')),
        'public' => $resolvePath((string) env('OAUTH_PUBLIC_KEY_PATH', 'storage/app/private/oauth/public.key')),
    ],

    'ttl' => [
        'authorization_code_seconds' => (int) env('OAUTH_AUTH_CODE_TTL_SECONDS', 600),
        'access_token_seconds' => (int) env('OAUTH_ACCESS_TOKEN_TTL_SECONDS', 3600),
        'refresh_token_seconds' => (int) env('OAUTH_REFRESH_TOKEN_TTL_SECONDS', 2592000),
        'client_assertion_seconds' => (int) env('OAUTH_CLIENT_ASSERTION_MAX_SECONDS', 300),
    ],

    'refresh_recovery' => [
        'seconds' => max(5, min(60, (int) env('OAUTH_REFRESH_RECOVERY_SECONDS', 30))),
        'max_records' => max(100, min(10000, (int) env('OAUTH_REFRESH_RECOVERY_MAX_RECORDS', 1000))),
    ],

    'mcp' => [
        'max_body_bytes' => (int) env('MCP_MAX_BODY_BYTES', 1048576),
        'session_ttl_seconds' => (int) env('MCP_SESSION_TTL_SECONDS', 3600),
    ],
];
