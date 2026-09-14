<?php

return [
    'bootstrap_fixture' => [
        'enabled' => (bool) env('MCP_BOOTSTRAP_FIXTURE_ENABLED', false),
        'token' => env('MCP_BOOTSTRAP_FIXTURE_TOKEN'),
    ],

    'server' => [
        'session_ttl_seconds' => (int) env('MCP_SESSION_TTL_SECONDS', 3600),
    ],

    'client' => [
        'connect_timeout_seconds' => (int) env('MCP_CLIENT_CONNECT_TIMEOUT_SECONDS', 2),
        'request_timeout_seconds' => (int) env('MCP_CLIENT_REQUEST_TIMEOUT_SECONDS', 5),
    ],
];
