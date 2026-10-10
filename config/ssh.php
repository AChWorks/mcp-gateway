<?php

return [
    'verification' => [
        // Per Target. Values are clamped in SshConnectionAdmission so zero or
        // extreme environment values cannot disable or unbound protection.
        'max_attempts_per_minute' => (int) env('SSH_VERIFY_MAX_ATTEMPTS_PER_MINUTE', 6),
        'decay_seconds' => (int) env('SSH_VERIFY_DECAY_SECONDS', 60),
        'lease_seconds' => (int) env('SSH_VERIFY_LEASE_SECONDS', 30),
    ],
];
