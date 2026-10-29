<?php

namespace Tests\Unit\Infrastructure\Http;

use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\PublicIpAddressPolicy;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use PHPUnit\Framework\TestCase;

final class OutboundTargetPolicyTest extends TestCase
{
    public function test_public_https_target_is_canonicalized_and_all_dns_answers_must_be_public(): void
    {
        $policy = $this->policy([
            'wp.example.test' => ['1.1.1.1', '8.8.8.8'],
        ]);

        self::assertSame('https://wp.example.test/wordpress', $policy->canonicalBaseUrl('https://WP.EXAMPLE.TEST/wordpress/'));
        $target = $policy->validate('https://wp.example.test/wp-json/wp-ai-bridge/v1/mcp');
        self::assertSame(['1.1.1.1', '8.8.8.8'], $target->addresses);
        self::assertSame(443, $target->port);
    }

    public function test_private_or_mixed_dns_answers_fail_closed(): void
    {
        $policy = $this->policy([
            'private.example.test' => ['127.0.0.1'],
            'mixed.example.test' => ['1.1.1.1', '10.0.0.5'],
        ]);

        foreach (['https://private.example.test', 'https://mixed.example.test'] as $url) {
            try {
                $policy->validate($url);
                self::fail('Unsafe target was accepted: '.$url);
            } catch (UnsafeOutboundTarget $exception) {
                self::assertStringContainsString('non-public', $exception->getMessage());
            }
        }
    }

    public function test_outbound_rejections_carry_actionable_but_non_secret_provenance(): void
    {
        $policy = $this->policy([
            'local.example.test' => ['127.0.0.1'],
            'private.example.test' => ['10.20.30.40'],
            'ipv6.example.test' => ['::1'],
            'mapped.example.test' => ['::ffff:127.0.0.2'],
            'linklocal.example.test' => ['fe80::1234'],
            'empty.example.test' => [],
        ]);

        foreach ([
            'local.example.test' => ['127.0.0.1', 'loopback'],
            'private.example.test' => ['10.20.30.40', 'private'],
            'ipv6.example.test' => ['::1', 'loopback'],
            'mapped.example.test' => ['::ffff:127.0.0.2', 'loopback'],
            'linklocal.example.test' => ['fe80::1234', 'link_local'],
        ] as $host => [$address, $kind]) {
            try {
                $policy->canonicalBaseUrl('https://'.$host);
                self::fail('Policy unexpectedly permitted '.$host);
            } catch (UnsafeOutboundTarget $exception) {
                self::assertSame('dns_non_public', $exception->reason);
                self::assertSame($address, $exception->rejectedAddress);
                self::assertSame($kind, $exception->diagnostics()['outbound_address_class']);
                self::assertSame('dns_lookup', $exception->diagnostics()['failure_stage']);
                self::assertArrayNotHasKey('pre_dispatch', $exception->diagnostics());
            }
        }

        try {
            $policy->validate('https://empty.example.test');
            self::fail('Missing DNS records were accepted.');
        } catch (UnsafeOutboundTarget $exception) {
            self::assertSame('dns_no_address', $exception->reason);
            self::assertArrayNotHasKey('outbound_rejected_address', $exception->diagnostics());
        }

        foreach ([
            'http://public.example.test' => 'https_required',
            'https://user:secret@public.example.test/' => 'unsupported_url_components',
            'https://public.example.test/?token=secret' => 'unsupported_url_components',
        ] as $url => $reason) {
            try {
                $policy->validate($url);
                self::fail('Invalid URL was accepted.');
            } catch (UnsafeOutboundTarget $exception) {
                self::assertSame($reason, $exception->reason);
                self::assertStringNotContainsString('secret', $exception->getMessage());
                self::assertStringNotContainsString('secret', json_encode($exception->diagnostics(), JSON_THROW_ON_ERROR));
            }
        }
    }

    public function test_shared_https_policy_also_rejects_non_global_ipv6_even_with_public_dns_answers(): void
    {
        $policy = $this->policy([
            'local-translation.example.test' => ['64:ff9b:1::1'],
            'dummy.example.test' => ['100:0:0:1::1'],
            'documentation.example.test' => ['3fff::1'],
            'srv6.example.test' => ['5f00::1'],
            'mixed.example.test' => ['8.8.8.8', '64:ff9b:1::1'],
        ]);

        foreach ([
            'local-translation.example.test',
            'dummy.example.test',
            'documentation.example.test',
            'srv6.example.test',
            'mixed.example.test',
        ] as $host) {
            try {
                $policy->validate('https://'.$host);
                self::fail('Non-global IPv6 destination passed shared HTTP outbound policy: '.$host);
            } catch (UnsafeOutboundTarget $exception) {
                self::assertStringContainsString('non-public', $exception->getMessage());
            }
        }
    }

    public function test_literal_ips_and_dns_answers_have_distinct_safe_provenance_without_policy_bypass(): void
    {
        $dns = new class implements DnsResolver
        {
            /** @var list<string> */
            public array $queried = [];

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                $this->queried[] = $host;

                return match ($host) {
                    'dns-local.example.test' => ['127.0.0.1'],
                    'dns-mixed.example.test' => ['1.1.1.1', '10.0.0.2'],
                    default => [],
                };
            }
        };
        $policy = new OutboundTargetPolicy($dns, new PublicIpAddressPolicy);
        foreach ([
            ['https://127.0.0.1', 'literal', 'admission', '127.0.0.1'],
            ['https://10.0.0.2', 'literal', 'admission', '10.0.0.2'],
            ['https://dns-local.example.test', 'dns', 'dns_lookup', '127.0.0.1'],
            ['https://dns-mixed.example.test', 'dns', 'dns_lookup', '10.0.0.2'],
        ] as [$url, $source, $stage, $ip]) {
            try {
                $policy->validate($url);
                self::fail('Non-public endpoint passed the HTTPS policy.');
            } catch (UnsafeOutboundTarget $exception) {
                self::assertSame('dns_non_public', $exception->reason);
                self::assertSame($ip, $exception->rejectedAddress);
                self::assertSame($source, $exception->diagnostics()['outbound_address_source']);
                self::assertSame($stage, $exception->diagnostics()['failure_stage']);
            }
        }
        self::assertSame(['dns-local.example.test', 'dns-mixed.example.test'], $dns->queried);
    }

    public function test_ambiguous_and_cross_origin_targets_are_rejected(): void
    {
        $policy = $this->policy([
            'wp.example.test' => ['1.1.1.1'],
            'other.example.test' => ['8.8.8.8'],
        ]);

        foreach ([
            'http://wp.example.test',
            'https://user@wp.example.test',
            'https://wp.example.test/path#fragment',
            'https://wp.example.test/a/../b',
        ] as $url) {
            try {
                $policy->validate($url);
                self::fail('Ambiguous target was accepted: '.$url);
            } catch (UnsafeOutboundTarget) {
                self::assertTrue(true);
            }
        }

        $this->expectException(UnsafeOutboundTarget::class);
        $policy->assertSameOrigin('https://other.example.test/oauth/token', 'https://wp.example.test');
    }

    /** @param array<string, list<string>> $answers */
    private function policy(array $answers): OutboundTargetPolicy
    {
        $dns = new class($answers) implements DnsResolver
        {
            /** @param array<string, list<string>> $answers */
            public function __construct(private readonly array $answers) {}

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $this->answers[$host] ?? [];
            }
        };

        return new OutboundTargetPolicy($dns, new PublicIpAddressPolicy);
    }
}
