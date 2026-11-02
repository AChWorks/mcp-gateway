<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Uri;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Assert;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Native Admin PRG adds a server-owned, one-use result nonce. Keep
        // asserting the exact canonical destination and every other query
        // parameter; explicitly validate the permitted token shape.
        if (! TestResponse::hasMacro('assertAdminRedirect')) {
            TestResponse::macro('assertAdminRedirect', function (?string $expected = null) {
                /** @var TestResponse $this */
                $location = (string) $this->headers->get('Location', '');
                $uri = Uri::of($location);
                $token = $uri->query()->all()['_admin_feedback'] ?? null;
                if ($token === null) {
                    return $this->assertRedirect($expected);
                }

                $this->assertRedirect();
                Assert::assertIsString($token);
                Assert::assertMatchesRegularExpression('/\\A[a-f0-9]{40}\\z/D', $token);
                Assert::assertSame(1, substr_count((string) parse_url($location, PHP_URL_QUERY), '_admin_feedback='));
                if ($expected !== null) {
                    Assert::assertSame(
                        app('url')->to($expected),
                        app('url')->to((string) $uri->withoutQuery('_admin_feedback')),
                        'The Admin redirect must preserve its exact original path and non-feedback query.',
                    );
                }

                return $this;
            });
        }
    }
}
