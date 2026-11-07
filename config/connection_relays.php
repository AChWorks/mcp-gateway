<?php

// This is a source/release identity pin, not a host readiness attestation.
// The root-owned installed helper must be checked independently by the operator.
return [
    'gateway_retirement_helper_sha256' => 'a6125a1fc7e8fb61e858fdb4fbba51158abb0964109da84371e1b80bb0542bd7',
    // Exact preceding merged source helper (PR #294). Upgrade requires explicit
    // Owner authorization; unknown installed binaries remain untouched.
    'gateway_retirement_helper_upgrade_from_sha256' => '1658e749005dfc1e28d89d4ec127a4faef592d6a6c1bd6148943b4c5ba87bba4',
];
