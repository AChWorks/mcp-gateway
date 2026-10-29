<?php

namespace Tests\Unit\Application\Targets;

use App\Application\Targets\TargetEndpointPreflight;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\PublicIpAddressPolicy;
use RuntimeException;
use Tests\TestCase;

final class TargetEndpointPreflightTest extends TestCase
{
    public function test_https_and_ssh_share_one_read_only_service_with_distinct_trust_policies(): void
    {
        $dns = new class implements DnsResolver
        {
            public int $calls = 0;

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                $this->calls++;
                TestCase::assertSame('generic-service.example.test', $host);
                TestCase::assertNotNull($deadlineNs);
                TestCase::assertGreaterThan(hrtime(true), $deadlineNs);

                return ['1.1.1.1', '8.8.8.8'];
            }
        };
        $ssh = new class implements SshDialAddressPolicy
        {
            public int $calls = 0;

            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                $this->calls++;
                TestCase::assertSame('generic-ssh.example.test', $endpoint->host);
                TestCase::assertSame(2222, $endpoint->port);
                TestCase::assertNotNull($deadlineNs);
                TestCase::assertGreaterThan(hrtime(true), $deadlineNs);

                return ['9.9.9.9'];
            }
        };

        $service = new TargetEndpointPreflight(
            new OutboundTargetPolicy($dns, new PublicIpAddressPolicy),
            $ssh,
        );
        $https = $service->publicHttpsOrigin('https://generic-service.example.test/');
        self::assertStringContainsString('1.1.1.1, 8.8.8.8', $https->message);
        self::assertStringContainsString('does not verify TLS', $https->limitation);
        self::assertSame(1, $dns->calls);
        self::assertSame('https://generic-service.example.test/', $https->checkedSubject);
        self::assertSame(['base_url' => 'https://generic-service.example.test/'], $https->checkedFields);

        $tcp = $service->publicSshTcpEndpoint('generic-ssh.example.test', 2222);
        self::assertStringContainsString('9.9.9.9', $tcp->message);
        self::assertStringContainsString('host key', $tcp->limitation);
        self::assertSame(1, $ssh->calls);
        self::assertSame('generic-ssh.example.test:2222', $tcp->checkedSubject);
        self::assertSame(['ssh_host' => 'generic-ssh.example.test', 'ssh_port' => '2222'], $tcp->checkedFields);
        self::assertSame(1, $dns->calls, 'SSH must not inherit HTTP DNS policy.');
    }

    public function test_https_preflight_never_uses_an_unbounded_resolver_or_a_later_trust_grant(): void
    {
        $dns = new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                if ($deadlineNs === null) {
                    throw new RuntimeException('Unbounded HTTPS preflight lookup is forbidden.');
                }

                return ['1.1.1.1'];
            }
        };
        $ssh = new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new RuntimeException('SSH must not be called for HTTPS.');
            }
        };

        $result = (new TargetEndpointPreflight(
            new OutboundTargetPolicy($dns, new PublicIpAddressPolicy), $ssh,
        ))->publicHttpsOrigin('https://generic-service.example.test');
        self::assertStringContainsString('1.1.1.1', $result->message);
    }
}
