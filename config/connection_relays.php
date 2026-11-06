<?php

// This is a source/release identity pin, not a host readiness attestation.
// The root-owned installed helper must be checked independently by the operator.
return [
    'gateway_retirement_helper_sha256' => '1658e749005dfc1e28d89d4ec127a4faef592d6a6c1bd6148943b4c5ba87bba4',
    // Exact preceding merged source helper (PR #293). Upgrade requires explicit
    // Owner authorization; unknown installed binaries remain untouched.
    'gateway_retirement_helper_upgrade_from_sha256' => '886f727e1dc85ab2ed32dd59c6f82d7177686752d27694f8d22350abbe8da360',
];
