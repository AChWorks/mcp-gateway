<?php

/*
 * MCP Gateway is direct-ingress by default. Only explicitly named reverse
 * proxy IPs may supply X-Forwarded-For/X-Forwarded-Proto; never trust '*' or
 * the incoming REMOTE_ADDR as an implicitly trusted proxy.
 */
$trusted = trim((string) env('GATEWAY_TRUSTED_PROXIES', ''));

$addresses = $trusted === '' ? [] : array_map(trim(...), explode(',', $trusted));
if (count($addresses) > 64) {
    throw new RuntimeException('Trusted proxy allowlist exceeds the supported bound.');
}
foreach ($addresses as $address) {
    if (! is_string($address) || $address === ''
        || ! filter_var($address, FILTER_VALIDATE_IP)
        || in_array($address, ['0.0.0.0', '::'], true)) {
        throw new RuntimeException('Trusted proxy allowlist must contain exact IPv4/IPv6 addresses.');
    }
}

return [
    // An explicit empty array also prevents Laravel's host-name-based proxy
    // auto-trust heuristic from activating due to an attacker-supplied Host.
    'proxies' => array_values(array_unique($addresses)),
];
