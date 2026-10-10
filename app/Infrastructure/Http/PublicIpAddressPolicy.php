<?php

namespace App\Infrastructure\Http;

final class PublicIpAddressPolicy
{
    /** @var list<string> */
    private const BLOCKED_IPV4 = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
    ];

    /** @var list<string> */
    private const BLOCKED_IPV6 = [
        '::/128',
        '::1/128',
        '64:ff9b::/96',
        // IANA IPv6 special-purpose registry: globally reachable = false.
        // PHP 8.4's FILTER_FLAG_GLOBAL_RANGE alone still accepts these
        // newer prefixes; keep explicit policy denies even with that flag.
        '64:ff9b:1::/48',   // RFC 8215: local-use IPv4/IPv6 translation
        '100::/64',
        '100:0:0:1::/64',   // RFC 9780: dummy IPv6 prefix
        '2001::/23',
        '2001:db8::/32',
        '2002::/16',
        '3fff::/20',       // RFC 9637: documentation
        '5f00::/16',       // RFC 9602: SRv6 SIDs
        'fc00::/7',
        'fec0::/10',
        'fe80::/10',
        'ff00::/8',
    ];

    public function isPublic(string $address): bool
    {
        $packed = @inet_pton($address);
        if ($packed === false) {
            return false;
        }

        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\x00", 10)."\xff\xff") {
            $mapped = inet_ntop(substr($packed, 12));

            return is_string($mapped) && $this->isPublic($mapped);
        }

        $blocked = strlen($packed) === 4 ? self::BLOCKED_IPV4 : self::BLOCKED_IPV6;
        foreach ($blocked as $cidr) {
            if ($this->matchesCidr($packed, $cidr)) {
                return false;
            }
        }

        return filter_var(
            $address,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_GLOBAL_RANGE | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }

    private function matchesCidr(string $packedAddress, string $cidr): bool
    {
        [$network, $prefix] = explode('/', $cidr, 2);
        $packedNetwork = inet_pton($network);
        if ($packedNetwork === false || strlen($packedNetwork) !== strlen($packedAddress)) {
            return false;
        }

        $bits = (int) $prefix;
        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        if ($wholeBytes > 0 && substr($packedAddress, 0, $wholeBytes) !== substr($packedNetwork, 0, $wholeBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;

        return (ord($packedAddress[$wholeBytes]) & $mask) === (ord($packedNetwork[$wholeBytes]) & $mask);
    }
}
