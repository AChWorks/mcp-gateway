<?php

namespace Tests\Unit\Infrastructure\OAuth;

use App\Infrastructure\OAuth\OAuthEncryptionKey;
use Tests\TestCase;

final class OAuthEncryptionKeyTest extends TestCase
{
    public function test_league_key_derivation_remains_backward_compatible(): void
    {
        $applicationKey = (string) config('app.key');
        self::assertNotSame('', $applicationKey);

        self::assertSame(
            hash_hmac('sha256', 'mcp-gateway:league-oauth:v1', $applicationKey),
            app(OAuthEncryptionKey::class)->league(),
        );
    }

    public function test_refresh_recovery_keys_are_domain_separated(): void
    {
        $keys = app(OAuthEncryptionKey::class);

        self::assertNotSame($keys->league(), $keys->refreshRecoveryLookup());
        self::assertNotSame($keys->league(), $keys->refreshRecoveryCipher());
        self::assertNotSame($keys->refreshRecoveryLookup(), $keys->refreshRecoveryCipher());
    }
}
