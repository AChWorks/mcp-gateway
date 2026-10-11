<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshAlgorithmPolicy;
use App\Infrastructure\Connectors\SshDirect\SshDeadlineDnsResolver;
use App\Infrastructure\Connectors\SshDirect\SshFileAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshTcpAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\PublicIpAddressPolicy;
use Illuminate\Support\Str;
use React\Dns\Model\Message;
use React\Dns\RecordNotFoundException;
use React\Dns\Resolver\ResolverInterface;
use React\Promise\Promise;
use React\Promise\PromiseInterface;
use RuntimeException;
use Tests\TestCase;

use function React\Promise\reject;
use function React\Promise\resolve;

final class SshDeadlineDnsResolverTest extends TestCase
{
    public function test_stalled_dns_cancels_both_queries_and_releases_target_lease_before_expiry(): void
    {
        $fixture = new class implements ResolverInterface
        {
            public int $cancelled = 0;

            /** @var list<array{string,int}> */
            public array $lookups = [];

            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('Only complete record-set queries may be used.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                $this->lookups[] = [$domain, $type];

                return new Promise(
                    static function (callable $resolve, callable $reject): void {
                        // Deliberately never answer: the DNS deadline alone
                        // must break the wait, not a mocked response.
                    },
                    function (): void {
                        $this->cancelled++;
                    },
                );
            }
        };

        $fallbackDns = new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                throw new RuntimeException('Never invoke blocking dns_get_record for bounded SFTP.');
            }
        };

        $policy = new SshTcpAddressPolicy(
            $fallbackDns, new PublicIpAddressPolicy,
            new SshDeadlineDnsResolver($fixture),
        );
        $transport = new SshVerifiedTransport($policy, new SshAlgorithmPolicy);
        $endpoint = SshRegisteredEndpoint::fromInput('prod.example.test', 22, 'deploy');
        $rawPin = pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x66", 32);
        $pin = SshHostKeyPin::fromLine('ssh-ed25519 '.base64_encode($rawPin));
        $admission = new SshFileAdmission;
        $id = 'stalled-dns-'.Str::random(16);

        $started = hrtime(true);
        $deadline = $started + 80_000_000; // 80ms, not the default 55s
        try {
            $admission->run($id, static fn () => $transport->withAuthenticatedSftpSession(
                $endpoint, $pin, 'password', 'fixture-password', null,
                static fn () => self::fail('DNS must not reach TCP or login.'),
                $deadline,
            ));
            self::fail('A stalled DNS query must terminate within the monotonic budget.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('transfer_timed_out', $exception->reason);
        }
        $elapsed = (hrtime(true) - $started) / 1_000_000_000;
        self::assertLessThan(0.65, $elapsed, 'DNS must not outlive an admission lease or stall request.');
        self::assertSame([
            ['prod.example.test', Message::TYPE_A],
            ['prod.example.test', Message::TYPE_AAAA],
        ], $fixture->lookups);
        self::assertSame(2, $fixture->cancelled);
        self::assertSame('released', $admission->run($id, static fn (): string => 'released'));
    }

    public function test_bounded_lookup_collects_full_ipv4_and_ipv6_set_before_public_egress_policy(): void
    {
        $resolver = new class implements ResolverInterface
        {
            /** @var list<string> */
            public array $hosts = [];

            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('Do not use a random single A address.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                $this->hosts[] = $domain;

                return resolve($type === Message::TYPE_A ? ['1.1.1.1'] : ['10.0.0.5']);
            }
        };
        $policy = new SshTcpAddressPolicy(new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                throw new RuntimeException('Unbounded resolver must not execute.');
            }
        }, new PublicIpAddressPolicy, new SshDeadlineDnsResolver($resolver));

        try {
            $policy->approvedDialAddresses(
                SshRegisteredEndpoint::fromInput('PROD.EXAMPLE.TEST', 22, 'deploy'),
                hrtime(true) + 1_000_000_000,
            );
            self::fail('Never select only public A while ignoring private AAAA.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('unapproved', $exception->getMessage());
        }
        self::assertSame(['prod.example.test', 'prod.example.test'], $resolver->hosts);
    }

    public function test_ipv4_only_nodata_for_aaaa_is_allowed_but_other_dns_errors_fail_closed(): void
    {
        $resolver = new class implements ResolverInterface
        {
            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('Do not use the single A record path.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                return $type === Message::TYPE_A
                    ? resolve(['1.1.1.1'])
                    : reject(new RecordNotFoundException('NOERROR / NODATA'));
            }
        };
        $policy = new SshTcpAddressPolicy(new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                throw new RuntimeException('Unbounded resolver is forbidden.');
            }
        }, new PublicIpAddressPolicy, new SshDeadlineDnsResolver($resolver));

        self::assertSame(['1.1.1.1'], $policy->approvedDialAddresses(
            SshRegisteredEndpoint::fromInput('prod.example.test', 22, 'deploy'),
            hrtime(true) + 1_000_000_000,
        ));
    }

    public function test_dns_server_failure_cannot_hide_other_address_family(): void
    {
        $resolver = new class implements ResolverInterface
        {
            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('Do not choose a random A address.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                return $type === Message::TYPE_A
                    ? resolve(['1.1.1.1'])
                    : reject(new RecordNotFoundException('DNS SERVFAIL', 2));
            }
        };
        $policy = new SshTcpAddressPolicy(new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                throw new RuntimeException('Do not invoke native DNS.');
            }
        }, new PublicIpAddressPolicy, new SshDeadlineDnsResolver($resolver));

        try {
            $policy->approvedDialAddresses(
                SshRegisteredEndpoint::fromInput('prod.example.test', 22, 'deploy'),
                hrtime(true) + 1_000_000_000,
            );
            self::fail('Incomplete public A answers cannot hide a failed AAAA query.');
        } catch (RuntimeException $exception) {
            self::assertSame('SSH DNS lookup unavailable.', $exception->getMessage());
        }
    }

    public function test_literal_public_ip_skips_both_dns_engines_under_deadline(): void
    {
        $fallback = new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                throw new RuntimeException('Literal IP must not invoke DNS.');
            }
        };
        $policy = new SshTcpAddressPolicy($fallback, new PublicIpAddressPolicy);
        self::assertSame(['8.8.8.8'], $policy->approvedDialAddresses(
            SshRegisteredEndpoint::fromInput('8.8.8.8', 22, 'deploy'),
            hrtime(true) + 1_000_000_000,
        ));
    }
}
