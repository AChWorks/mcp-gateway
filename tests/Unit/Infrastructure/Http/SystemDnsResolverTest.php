<?php

namespace Tests\Unit\Infrastructure\Http;

use App\Infrastructure\Http\DeadlineDnsLookup;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\PublicIpAddressPolicy;
use App\Infrastructure\Http\SystemDnsResolver;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use PHPUnit\Framework\TestCase;
use React\Dns\Model\Message;
use React\Dns\RecordNotFoundException;
use React\Dns\Resolver\ResolverInterface;
use React\Promise\Promise;
use React\Promise\PromiseInterface;
use RuntimeException;

use function React\Promise\reject;
use function React\Promise\resolve;

final class SystemDnsResolverTest extends TestCase
{
    public function test_http_dns_deadline_cancels_both_pending_address_families(): void
    {
        $fixture = new class implements ResolverInterface
        {
            public int $cancelled = 0;

            /** @var list<array{string,int}> */
            public array $queries = [];

            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('A single address family is not sufficient.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                $this->queries[] = [$domain, $type];

                return new Promise(
                    static function (callable $resolve, callable $reject): void {},
                    function (): void {
                        $this->cancelled++;
                    },
                );
            }
        };

        $dns = new SystemDnsResolver(new DeadlineDnsLookup($fixture));
        $started = hrtime(true);

        try {
            $dns->resolve('wp.example.test', $started + 70_000_000);
            self::fail('HTTP DNS lookup must not outlive the request deadline.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('network_failure', $exception->reason);
            self::assertTrue($exception->preDispatch);
        }

        self::assertLessThan(0.65, (hrtime(true) - $started) / 1_000_000_000);
        self::assertSame([
            ['wp.example.test', Message::TYPE_A],
            ['wp.example.test', Message::TYPE_AAAA],
        ], $fixture->queries);
        self::assertSame(2, $fixture->cancelled);
    }

    public function test_http_policy_rejects_mixed_public_and_private_results_before_connecting(): void
    {
        $fixture = new class implements ResolverInterface
        {
            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('All A+AAAA records are required.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                return resolve($type === Message::TYPE_A ? ['8.8.8.8'] : ['::1']);
            }
        };

        $policy = new OutboundTargetPolicy(
            new SystemDnsResolver(new DeadlineDnsLookup($fixture)),
            new PublicIpAddressPolicy,
        );

        $this->expectException(UnsafeOutboundTarget::class);
        $this->expectExceptionMessage('non-public');
        $policy->validate('https://wp.example.test/mcp', 2048, hrtime(true) + 1_000_000_000);
    }

    public function test_ipv4_only_nodata_is_acceptable_but_servfail_is_not(): void
    {
        $fixture = new class implements ResolverInterface
        {
            public bool $failed = false;

            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('All address records must be queried.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                if ($type === Message::TYPE_A) {
                    return resolve(['8.8.8.8']);
                }

                return $this->failed
                    ? reject(new RecordNotFoundException('DNS SERVFAIL', 2))
                    : reject(new RecordNotFoundException('NODATA', 0));
            }
        };

        $dns = new SystemDnsResolver(new DeadlineDnsLookup($fixture));
        self::assertSame(['8.8.8.8'], $dns->resolve('wp.example.test', hrtime(true) + 1_000_000_000));

        $fixture->failed = true;
        try {
            $dns->resolve('wp.example.test', hrtime(true) + 1_000_000_000);
            self::fail('Partial DNS answers cannot hide a failed address family.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('network_failure', $exception->reason);
            self::assertTrue($exception->preDispatch);
        }
    }

    public function test_literal_ip_skips_async_dns_and_keeps_policy_rejection(): void
    {
        $fixture = new class implements ResolverInterface
        {
            public function resolve($domain): PromiseInterface
            {
                throw new RuntimeException('No literal lookup allowed.');
            }

            public function resolveAll($domain, $type): PromiseInterface
            {
                throw new RuntimeException('No literal lookup allowed.');
            }
        };

        $dns = new SystemDnsResolver(new DeadlineDnsLookup($fixture));
        self::assertSame(['8.8.8.8'], $dns->resolve('8.8.8.8', hrtime(true) + 1_000_000_000));

        $policy = new OutboundTargetPolicy($dns, new PublicIpAddressPolicy);
        $this->expectException(UnsafeOutboundTarget::class);
        $policy->validate('https://127.0.0.1', 2048, hrtime(true) + 1_000_000_000);
    }
}
