<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshTcpAddressPolicy;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\PublicIpAddressPolicy;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class SshTcpAddressPolicyTest extends TestCase
{
    public function test_registered_public_literal_never_triggers_a_dns_lookup(): void
    {
        $resolver = new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                throw new RuntimeException('Numeric registered endpoints must not be re-resolved.');
            }
        };

        $policy = new SshTcpAddressPolicy($resolver, new PublicIpAddressPolicy);

        self::assertSame(['8.8.8.8'],
            $policy->approvedDialAddresses(SshRegisteredEndpoint::fromInput('8.8.8.8', 22, 'deploy')));
        self::assertSame(['2606:4700:4700::1111'],
            $policy->approvedDialAddresses(SshRegisteredEndpoint::fromInput('[2606:4700:4700::1111]', 2222, 'root')));
    }

    public function test_hostname_resolves_to_bounded_public_numeric_candidates_only(): void
    {
        $policy = $this->policy([
            'prod.example.test' => ['1.1.1.1', '8.8.8.8', '1.1.1.1'],
        ]);
        $endpoint = SshRegisteredEndpoint::fromInput('PROD.example.test', 2202, 'deploy');

        self::assertSame(['1.1.1.1', '8.8.8.8'], $policy->approvedDialAddresses($endpoint));
        self::assertNull($endpoint->configuredIp());
        self::assertSame('deploy@prod.example.test:2202', $endpoint->destinationLabel());
    }

    public function test_mixed_public_and_private_dns_is_rejected_instead_of_partially_trusted(): void
    {
        foreach ([
            ['1.1.1.1', '127.0.0.1'],
            ['8.8.8.8', '10.1.2.3'],
            ['1.1.1.1', '::ffff:192.168.1.1'],
            ['1.1.1.1', 'fe80::1'],
            ['8.8.8.8', 'not-a-numeric-address'],
            ['1.1.1.1', '203.0.113.10'],
        ] as $answers) {
            $this->expectUnsafe($this->policy(['prod.example.test' => $answers]),
                SshRegisteredEndpoint::fromInput('prod.example.test', 22, 'deploy'));
        }
    }

    public function test_non_public_registered_literals_cannot_bypass_the_default_tcp_policy(): void
    {
        foreach (['127.0.0.1', '10.0.0.1', '192.168.1.9', '::1', 'fd00::1', '203.0.113.10'] as $address) {
            $this->expectUnsafe($this->policy([]),
                SshRegisteredEndpoint::fromInput($address, 22, 'root'));
        }
    }

    public function test_empty_or_unbounded_dns_response_fails_closed(): void
    {
        $endpoint = SshRegisteredEndpoint::fromInput('prod.example.test', 22, 'deploy');

        $this->expectUnsafe($this->policy(['prod.example.test' => []]), $endpoint);
        $this->expectUnsafe($this->policy([
            'prod.example.test' => array_fill(0, 17, '8.8.8.8'),
        ]), $endpoint);
    }

    /** @param array<string, list<string>> $answers */
    private function policy(array $answers): SshTcpAddressPolicy
    {
        $resolver = new class($answers) implements DnsResolver
        {
            /** @param array<string, list<string>> $answers */
            public function __construct(private readonly array $answers) {}

            public function resolve(string $host): array
            {
                return $this->answers[$host] ?? [];
            }
        };

        return new SshTcpAddressPolicy($resolver, new PublicIpAddressPolicy);
    }

    private function expectUnsafe(SshTcpAddressPolicy $policy, SshRegisteredEndpoint $endpoint): void
    {
        try {
            $policy->approvedDialAddresses($endpoint);
            self::fail('An unsafe SSH TCP destination was approved.');
        } catch (RuntimeException) {
            self::assertTrue(true);
        }
    }
}
