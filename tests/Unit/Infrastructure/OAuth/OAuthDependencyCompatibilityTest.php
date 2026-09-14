<?php

namespace Tests\Unit\Infrastructure\OAuth;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class OAuthDependencyCompatibilityTest extends TestCase
{
    public function test_selected_oauth_library_exposes_required_lifecycle_primitives(): void
    {
        self::assertTrue(class_exists(AuthorizationServer::class));
        self::assertTrue(class_exists(AuthCodeGrant::class));
        self::assertTrue(class_exists(RefreshTokenGrant::class));
        self::assertTrue(method_exists(AccessTokenRepositoryInterface::class, 'revokeAccessToken'));
        self::assertTrue(method_exists(AuthCodeRepositoryInterface::class, 'revokeAuthCode'));
        self::assertTrue(method_exists(RefreshTokenRepositoryInterface::class, 'revokeRefreshToken'));
    }

    public function test_selected_oauth_library_verifies_s256_pkce(): void
    {
        $verifier = str_repeat('a', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $s256 = new S256Verifier;

        self::assertTrue($s256->verifyCodeChallenge($verifier, $challenge));
        self::assertFalse($s256->verifyCodeChallenge(str_repeat('b', 43), $challenge));
    }

    public function test_client_authentication_is_an_overridable_grant_boundary(): void
    {
        $method = new ReflectionMethod(AbstractGrant::class, 'validateClient');

        self::assertTrue($method->isProtected());
        self::assertFalse($method->isFinal());
    }
}
