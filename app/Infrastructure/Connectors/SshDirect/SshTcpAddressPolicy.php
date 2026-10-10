<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\PublicIpAddressPolicy;
use RuntimeException;

/**
 * Resolve an operator-registered SSH endpoint to bounded public numeric peers.
 *
 * This is only a TCP dialing precondition, NOT evidence of an authenticated or
 * pinned-host-key-verified SSH server. A later SSH adapter must connect to one
 * of these exact numeric addresses, confirm its actual TCP peer, then verify
 * the independently trusted server host key BEFORE transmitting credentials.
 *
 * Registered private/VPN endpoints require a future explicit, Target-scoped
 * owner policy and must never become reachable via a permissive fallback.
 */
final class SshTcpAddressPolicy
{
    private const MAX_DNS_ADDRESSES = 16;

    public function __construct(
        private readonly DnsResolver $dns,
        private readonly PublicIpAddressPolicy $publicIps,
    ) {}

    /** @return non-empty-list<string> Canonical, policy-approved numeric TCP peer candidates. */
    public function approvedDialAddresses(SshRegisteredEndpoint $endpoint): array
    {
        $literal = $endpoint->configuredIp();
        // A canonical registered DNS hostname is displayed without its root
        // dot, but must always resolve as an absolute FQDN. Otherwise the
        // system resolver may append search domains and authorize a different
        // (even publicly addressed) destination.
        $answers = $literal === null ? $this->dns->resolve($endpoint->host.'.') : [$literal];

        if ($answers === [] || count($answers) > self::MAX_DNS_ADDRESSES) {
            throw new RuntimeException('SSH destination has no bounded approved DNS address set.');
        }

        $approved = [];
        foreach ($answers as $address) {
            $packed = @inet_pton($address);
            if ($packed === false || ! $this->publicIps->isPublic($address)) {
                // Reject the entire candidate set; never silently pick public
                // answers out of a mixed private/public DNS response.
                throw new RuntimeException('SSH destination includes an unapproved TCP address.');
            }

            $canonical = inet_ntop($packed);
            if ($canonical === false) {
                throw new RuntimeException('SSH destination includes an invalid TCP address.');
            }

            $approved[$canonical] = true;
        }

        /** @var non-empty-list<string> $addresses */
        $addresses = array_keys($approved);

        return $addresses;
    }
}
