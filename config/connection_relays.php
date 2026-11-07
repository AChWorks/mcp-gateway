<?php

// This is a source/release identity pin, not a host readiness attestation.
// The root-owned installed helper must be checked independently by the operator.
return [
    'gateway_retirement_helper_sha256' => 'f10ce7fd9d75d16fcaed9736db7263355d949b8611a269d78350db7f8f6c42f0',
    // Exact preceding merged source helper (PR #296). Upgrade requires explicit
    // Owner authorization; unknown installed binaries remain untouched.
    'gateway_retirement_helper_upgrade_from_sha256' => 'a6125a1fc7e8fb61e858fdb4fbba51158abb0964109da84371e1b80bb0542bd7',
];
