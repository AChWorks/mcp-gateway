<?php

namespace Tests\Unit;

use App\Application\Targets\ExternalAuthorizationDestination;
use InvalidArgumentException;
use Tests\TestCase;

final class ExternalAuthorizationDestinationTest extends TestCase
{
    public function test_generic_verified_https_provider_preserves_opaque_oauth_parameters_without_wordpress_coupling(): void
    {
        $url = 'https://accounts.example.test:8443/authorize?state=aBc_123&code_challenge=xyz&redirect_uri=https%3A%2F%2Fgateway.example.test%2Foauth';
        self::assertSame($url, ExternalAuthorizationDestination::validate(
            $url, 'https://accounts.example.test:8443/issuer',
        ));
        self::assertSame('https://another.example.test/consent?a=b', ExternalAuthorizationDestination::validate(
            'https://another.example.test/consent?a=b',
            'https://another.example.test/',
        ));
        self::assertSame('https://provider.example.test/authorize', ExternalAuthorizationDestination::validate(
            'https://provider.example.test/authorize',
            'https://provider.example.test:443',
        ));
    }

    public function test_invalid_untrusted_or_malformed_authorization_urls_are_rejected_before_navigation(): void
    {
        foreach ([
            ['https://provider.example.test/authorize', null],
            ['https://provider.example.test/authorize', 'https://elsewhere.example.test'],
            ['https://provider.example.test.evil.test/authorize', 'https://provider.example.test'],
            ['https://provider.example.test@evil.example.test/authorize', 'https://provider.example.test'],
            ['https://user:pass@provider.example.test/authorize', 'https://provider.example.test'],
            ['http://provider.example.test/authorize', 'https://provider.example.test'],
            ['javascript:alert(1)', 'https://provider.example.test'],
            ['//provider.example.test/authorize', 'https://provider.example.test'],
            ['https://provider.example.test/authorize#fragment', 'https://provider.example.test'],
            ["https://provider.example.test/authorize\r\nLocation: https://evil.test", 'https://provider.example.test'],
            ['https://provider.example.test/authorize', 'https://user:pass@provider.example.test'],
            ['https://provider.example.test/authorize', 'https://provider.example.test?redirect=bad'],
            ['https://provider.example.test:8443/authorize', 'https://provider.example.test'],
            ['https://provider.example.test/'.str_repeat('a', 8192), 'https://provider.example.test'],
            ['https://127.0.0.1/authorize', 'https://provider.example.test'],
        ] as [$url, $origin]) {
            try {
                ExternalAuthorizationDestination::validate($url, $origin);
                self::fail('Untrusted browser navigation was accepted.');
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }
}
