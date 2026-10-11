<?php

namespace App\Infrastructure\Http;

use RuntimeException;

final class SystemDnsResolver implements DnsResolver
{
    public function __construct(private readonly ?DeadlineDnsLookup $boundedLookup = null) {}

    public function resolve(string $host, ?int $deadlineNs = null): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        if ($deadlineNs !== null) {
            try {
                return ($this->boundedLookup ?? new DeadlineDnsLookup)
                    ->resolveBeforeDeadline(rtrim($host, '.').'.', $deadlineNs);
            } catch (DnsLookupDeadlineExceeded) {
                throw new OutboundRequestException('network_failure', 'Outbound DNS resolution timed out.', [], true);
            } catch (RuntimeException) {
                throw new OutboundRequestException('network_failure', 'Outbound DNS resolution failed.', [], true);
            }
        }

        // Preserve native system resolution in registration and SSH command
        // paths with no request-scoped monotonic deadline.
        $records = dns_get_record($host, DNS_A | DNS_AAAA);
        if ($records === false) {
            return [];
        }

        $addresses = [];
        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($address) && filter_var($address, FILTER_VALIDATE_IP) !== false) {
                $addresses[] = $address;
            }
        }

        return array_values(array_unique($addresses));
    }
}
