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

            public function resolve(string $host): array
            {
                return $this->answers[$host] ?? [];
            }
        };

        return new OutboundTargetPolicy($dns, new PublicIpAddressPolicy);
    }
}
