<?php

return [
    // Fresh installs explicitly set SSH_FILE_TRANSFER_ENABLED=true in their .env.
    // Keep the absent-key fallback OFF for older installations whose private
    // .env files are preserved during upgrades. SSH-only, never WordPress.
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
    // Explicit per-Target, per-loopback-port, per-tunnel-identity allowlist
    // configured by the NL operator, not editable through a Target form.
    // JSON object: {"target-id":{"port":22023,"tunnel_identity":"owner-approved-id"}}
    // Missing/invalid/multi-owner allowlists fail closed. No secret in this key.
    'reverse_approved_routes' => (string) env('SSH_REVERSE_APPROVED_ROUTES', ''),
    // Fixed private path provisioned once by an independently authorized
    // host installer. Never interpreted as a per-Target arbitrary file path.
    'managed_reverse' => [
        'authorized_keys_file' => storage_path('app/private/ssh-reverse/authorized_keys'),
        'host_manifest_file' => '/etc/mcp-gateway-reverse/manifest.json',
        'installer_path' => base_path('bin/managed-reverse-target.sh'),
        // Committed digest from the exact installer delivered by the package.
        // The release/distribution process must independently verify this.
        'installer_sha256' => '7dfea60fa001c737bb4d6c9e6dd2a4960d9e0f629a7b240f7e8d4be485c0bf91',
    ],
];
