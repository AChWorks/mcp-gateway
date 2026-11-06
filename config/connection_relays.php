<?php

// This is a source/release identity pin, not a host readiness attestation.
// The root-owned installed helper must be checked independently by the operator.
return [
    'gateway_retirement_helper_sha256' => '7e6a408f9e963f10ca9440bf97f1fab6dc51cef2f4143aae6729594143bd269c',
    // Exact previous helper from merged PR #290. Explicit upgrade only;
    // unknown installed binaries are never replaced or adopted.
    'gateway_retirement_helper_upgrade_from_sha256' => 'e329acf8076dade75696791c3a1d002b018612b2cd7155c2c09bbf95d0b84911',
];
