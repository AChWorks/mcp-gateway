<?php

// This is a source/release identity pin, not a host readiness attestation.
// The root-owned installed helper must be checked independently by the operator.
return [
    'gateway_retirement_helper_sha256' => 'e0810d480ef43e278924422d9f478b804359313883fa4ec2abe8ca7fffb00efd',
    // Exact previously shipped helper from merged PR #286/#287. Explicit upgrade only;
    // unknown installed binaries are never replaced or adopted.
    'gateway_retirement_helper_upgrade_from_sha256' => '369fe2369c23d19a3fc62ccf494cba3ff7bb91109fa14e92783873904a2d5364',
];
