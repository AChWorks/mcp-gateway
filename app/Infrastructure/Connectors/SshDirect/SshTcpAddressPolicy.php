<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\PublicIpAddressPolicy;
use App\Infrastructure\Http\UnsafeOutboundTarget;

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
final class SshTcpAddressPolicy implements SshDialAddressPolicy
{
    private const MAX_DNS_ADDRESSES = 16;

    private readonly SshDeadlineDnsResolver $boundedDns;

    public function __construct(
        private readonly DnsResolver $dns,
        private readonly PublicIpAddressPolicy $publicIps,
        ?SshDeadlineDnsResolver $boundedDns = null,
    ) {
        $this->boundedDns = $boundedDns ?? new SshDeadlineDnsResolver;
    }

    /** @return non-empty-list<string> Canonical, policy-approved numeric TCP peer candidates. */
    public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
    {
        $literal = $endpoint->configuredIp();
        // Absolute registered FQDN; no search suffixes. SFTP uses an async
        // DNS query sharing its whole-operation monotonic deadline. Commands
        // retain the existing system resolver and the same public-IP policy.
        $answers = $literal !== null ? [$literal] : ($deadlineNs === null
            ? $this->dns->resolve($endpoint->host.'.')
            : $this->boundedDns->resolveBeforeDeadline($endpoint->host.'.', $deadlineNs));

        if ($answers === []) {
            throw new UnsafeOutboundTarget('SSH destination has no DNS address.', 'dns_no_address');
        }
        if (count($answers) > self::MAX_DNS_ADDRESSES) {
            throw new UnsafeOutboundTarget('SSH destination exceeds the approved DNS address count.', 'dns_too_many_addresses');
        }

        $approved = [];
        foreach ($answers as $address) {
            $packed = @inet_pton($address);
            if ($packed === false) {
                throw new UnsafeOutboundTarget('SSH DNS returned an invalid numeric address.', 'dns_invalid_address');
            }
            if (! $this->publicIps->isPublic($address)) {
                // Reject the entire candidate set; never silently pick public
                // answers out of a mixed private/public DNS response.
                throw new UnsafeOutboundTarget('SSH destination includes an unapproved TCP address.', 'dns_non_public', $address, $literal !== null ? 'literal' : 'dns');
            }

            $canonical = inet_ntop($packed);
            if ($canonical === false) {
                throw new UnsafeOutboundTarget('SSH destination includes an invalid TCP address.', 'dns_invalid_address');
            }

            $approved[$canonical] = true;
        }

        /** @var non-empty-list<string> $addresses */
        $addresses = array_keys($approved);

        return $addresses;
    }
}
