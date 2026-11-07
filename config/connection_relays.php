<?php

// This is a source/release identity pin, not a host readiness attestation.
// The root-owned installed helper must be checked independently by the operator.
return [
    'gateway_retirement_helper_sha256' => '82c5431243f9c7bc71a9918a5c80aade584e3d60d5d082618d99b63ddf847d3d',
    // Exact preceding merged source helper (PR #296). Upgrade requires explicit
    // Owner authorization; unknown installed binaries remain untouched.
    'gateway_retirement_helper_upgrade_from_sha256' => 'a6125a1fc7e8fb61e858fdb4fbba51158abb0964109da84371e1b80bb0542bd7',
];
