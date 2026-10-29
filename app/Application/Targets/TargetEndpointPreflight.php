<?php

namespace App\Application\Targets;

use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Http\OutboundTargetPolicy;

/**
 * One transport-aware read-only preflight used by implemented Target connectors.
 *
 * Never contacts the Target, stores credentials, certifies its remote identity,
 * or makes the resolved addresses a reusable dispatch grant.
 */
final readonly class TargetEndpointPreflight
{
    private const DNS_BUDGET_NS = 8_000_000_000;

    public function __construct(
        private OutboundTargetPolicy $https,
        private SshDialAddressPolicy $ssh,
    ) {}

    public function publicHttpsOrigin(string $url): TargetPreflightResult
    {
        // One bounded policy lookup, not an unbounded preliminary DNS query.
        // The 1024-byte limit matches HTTPS registration's canonical base URL.
        $checked = $this->https->validate($url, 1024, hrtime(true) + self::DNS_BUDGET_NS);

        return new TargetPreflightResult(
            __('Gateway resolved this public HTTPS destination to: :addresses.', [
                'addresses' => implode(', ', $checked->addresses),
            ]),
            __('DNS and public-IP policy only. This does not verify TLS, the remote service, its authentication, or a future connection. Registration and dispatch check again.'),
        );
    }

    public function publicSshTcpEndpoint(string $host, int $port): TargetPreflightResult
    {
        // SshRegisteredEndpoint requires a syntactically valid OS username.
        // This non-secret placeholder is never used for authentication; the
        // result depends only on the host, port and actual SSH dial policy.
        $endpoint = SshRegisteredEndpoint::fromInput($host, $port, 'preflight');
        $addresses = $this->ssh->approvedDialAddresses($endpoint, hrtime(true) + self::DNS_BUDGET_NS);

        return new TargetPreflightResult(
            __('Gateway approved these public SSH TCP destination addresses: :addresses.', [
                'addresses' => implode(', ', $addresses),
            ]),
            __('DNS/TCP destination policy only. This does not connect, verify the SSH host key, authenticate, or grant trust. Every actual SSH connection rechecks and verifies its pinned host key.'),
        );
    }
}
