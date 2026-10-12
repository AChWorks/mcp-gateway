<?php

return [
    // DRAFT #147: opt-in only in disposable acceptance, not approved as a public API.
    // These are SSH file-data-plane budgets, never WordPress/MCP frame limits.
    'file_transfer' => [
        'enabled' => (bool) env('SSH_FILE_TRANSFER_ENABLED', false),
        'max_bytes' => (int) env('SSH_FILE_TRANSFER_MAX_BYTES', 8388608),
        'max_seconds' => (int) env('SSH_FILE_TRANSFER_MAX_SECONDS', 30),
    ],
    'verification' => [
        // Per Target. Values are clamped in SshConnectionAdmission so zero or
        // extreme environment values cannot disable or unbound protection.
        'max_attempts_per_minute' => (int) env('SSH_VERIFY_MAX_ATTEMPTS_PER_MINUTE', 6),
        'decay_seconds' => (int) env('SSH_VERIFY_DECAY_SECONDS', 60),
        'lease_seconds' => (int) env('SSH_VERIFY_LEASE_SECONDS', 30),
    ],
];
