<?php

// This is a source/release identity pin, not a host readiness attestation.
// The root-owned installed helper must be checked independently by the operator.
return [
    'gateway_retirement_helper_sha256' => '1e0f841fd69e98aee28b20ed00e1d5c86d3b91eb574aef0c214667f27097da11',
    // Exact previous helper from merged PR #289. Explicit upgrade only;
    // unknown installed binaries are never replaced or adopted.
    'gateway_retirement_helper_upgrade_from_sha256' => 'e0810d480ef43e278924422d9f478b804359313883fa4ec2abe8ca7fffb00efd',
];
