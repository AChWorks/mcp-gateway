<?php

namespace App\Infrastructure\OAuth;

use DateTimeImmutable;

final readonly class SiteCredentialSecret
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $accessToken,
        public ?string $refreshToken,
        public ?DateTimeImmutable $accessExpiresAt,
        public array $scopes,
    ) {
    }
}
