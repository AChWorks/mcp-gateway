<?php

namespace Tests\Unit\Infrastructure\Http;

use App\Infrastructure\Http\PublicIpAddressPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PublicIpAddressPolicyTest extends TestCase
{
    #[DataProvider('blockedAddresses')]
    public function test_non_public_addresses_are_rejected(string $address): void
    {
        self::assertFalse((new PublicIpAddressPolicy)->isPublic($address));
    }

    #[DataProvider('publicAddresses')]
    public function test_public_addresses_are_allowed(string $address): void
    {
        self::assertTrue((new PublicIpAddressPolicy)->isPublic($address));
    }

    /** @return array<string, array{string}> */
    public static function blockedAddresses(): array
    {
        return [
            'unspecified' => ['0.0.0.0'],
            'rfc1918-10' => ['10.20.30.40'],
            'shared-address-space' => ['100.64.0.1'],
            'loopback' => ['127.0.0.1'],
            'metadata-link-local' => ['169.254.169.254'],
            'rfc1918-172' => ['172.16.0.1'],
            'rfc1918-192' => ['192.168.1.1'],
            'benchmark' => ['198.18.0.1'],
            'documentation' => ['203.0.113.1'],
            'multicast' => ['224.0.0.1'],
            'ipv6-unspecified' => ['::'],
            'ipv6-loopback' => ['::1'],
            'ipv6-ula' => ['fd00::1'],
            'ipv6-link-local' => ['fe80::1'],
            'ipv6-multicast' => ['ff02::1'],
            'ipv6-6to4' => ['2002:0a00:0001::1'],
            'ipv4-mapped-private' => ['::ffff:127.0.0.1'],
        ];
    }

    /** @return array<string, array{string}> */
    public static function publicAddresses(): array
    {
        return [
            'cloudflare-v4' => ['1.1.1.1'],
            'google-v4' => ['8.8.8.8'],
            'cloudflare-v6' => ['2606:4700:4700::1111'],
        ];
    }
}
