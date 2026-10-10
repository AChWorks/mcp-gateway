<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class SshRegisteredEndpointTest extends TestCase
{
    public function test_registered_ipv4_and_ipv6_are_canonical_and_visibly_distinguishable(): void
    {
        $ipv4 = SshRegisteredEndpoint::fromInput(' 203.0.113.10 ', 22, 'deploy');
        self::assertSame('203.0.113.10', $ipv4->host);
        self::assertSame('203.0.113.10', $ipv4->configuredIp());
        self::assertSame('deploy@203.0.113.10:22', $ipv4->destinationLabel());
        self::assertSame('Production — deploy@203.0.113.10:22 — prod-ssh',
            $ipv4->targetLabel('Production', 'prod-ssh'));

        $ipv6 = SshRegisteredEndpoint::fromInput('[2001:0DB8:0000:0000:0000:0000:0000:0010]', 2202, 'root');
        self::assertSame('2001:db8::10', $ipv6->host);
        self::assertSame('2001:db8::10', $ipv6->configuredIp());
        self::assertSame('root@[2001:db8::10]:2202', $ipv6->destinationLabel());
        self::assertSame('Maintenance — root@[2001:db8::10]:2202 — maintenance-ssh',
            $ipv6->targetLabel('Maintenance', 'maintenance-ssh'));

        $unbracketed = SshRegisteredEndpoint::fromInput('2001:db8::10', 2202, 'root');
        self::assertSame($ipv6->destinationLabel(), $unbracketed->destinationLabel());
    }

    public function test_hostname_remains_registered_and_never_fabricates_a_verified_peer_ip(): void
    {
        $endpoint = SshRegisteredEndpoint::fromInput('PROD.Example.TEST.', 2222, 'operator');
        self::assertSame('prod.example.test', $endpoint->host);
        self::assertNull($endpoint->configuredIp());
        self::assertSame('operator@prod.example.test:2222', $endpoint->destinationLabel());
        self::assertSame(
            'Production — operator@prod.example.test:2222 — prod-ssh (IP not yet verified)',
            $endpoint->targetLabel('Production', 'prod-ssh'),
        );

        $idn = SshRegisteredEndpoint::fromInput('XN--BCHER-KVA.example', 22, 'deploy');
        self::assertSame('xn--bcher-kva.example', $idn->host);
        self::assertNull($idn->configuredIp());
    }

    public function test_same_ip_different_users_ports_and_target_ids_remain_distinct(): void
    {
        $first = SshRegisteredEndpoint::fromInput('203.0.113.10', 22, 'deploy');
        $second = SshRegisteredEndpoint::fromInput('203.0.113.10', 22, 'root');
        $third = SshRegisteredEndpoint::fromInput('203.0.113.10', 2222, 'deploy');

        self::assertNotSame($first->destinationLabel(), $second->destinationLabel());
        self::assertNotSame($first->destinationLabel(), $third->destinationLabel());
        self::assertNotSame(
            $first->targetLabel('Production', 'ssh-a'),
            $first->targetLabel('Production', 'ssh-b'),
        );
    }

    public function test_invalid_hosts_fail_locally_without_dns_or_connection_attempts(): void
    {
        foreach ([
            '',
            ' ',
            'localhost',
            'localhost.',
            'http://203.0.113.10',
            'user@example.test',
            'example.test:22',
            'example..test',
            'example.test..',
            '.example.test',
            'bad_label.example.test',
            '-bad.example.test',
            'bad-.example.test',
            'a'.str_repeat('b', 63).'.test',
            str_repeat('a', 254).'.test',
            "example.test\n",
            '[2001:db8::1%eth0]',
            '203.0.113.10/24',
            '127.1',
            '010.001.002.003',
            '0x7f000001',
            '123.456.789',
        ] as $host) {
            try {
                SshRegisteredEndpoint::fromInput($host, 22, 'deploy');
                self::fail('Unsafe or ambiguous SSH host was accepted: '.json_encode($host));
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_out_of_range_port_or_unsafe_username_is_rejected(): void
    {
        foreach ([0, -1, 65536, 100000] as $port) {
            $this->expectInvalid(static fn (): SshRegisteredEndpoint => SshRegisteredEndpoint::fromInput(
                '203.0.113.10', $port, 'deploy',
            ));
        }

        foreach ([
            '', ' ', 'user name', "admin\n", 'user@host', 'name:22',
            '/root', '[user]', str_repeat('a', 129),
        ] as $username) {
            $this->expectInvalid(static fn (): SshRegisteredEndpoint => SshRegisteredEndpoint::fromInput(
                '203.0.113.10', 22, $username,
            ));
        }

        // Root is an OS-account choice, not a Gateway shell-command policy.
        self::assertSame('root@203.0.113.10:22',
            SshRegisteredEndpoint::fromInput('203.0.113.10', 22, 'root')->destinationLabel());
    }

    /** @param \Closure(): SshRegisteredEndpoint $operation */
    private function expectInvalid(\Closure $operation): void
    {
        try {
            $operation();
            self::fail('An invalid registered SSH endpoint was accepted.');
        } catch (InvalidArgumentException) {
            self::assertTrue(true);
        }
    }
}
