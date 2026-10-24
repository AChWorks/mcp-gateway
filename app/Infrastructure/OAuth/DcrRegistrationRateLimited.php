<?php

namespace App\Infrastructure\OAuth;

use RuntimeException;

final class DcrRegistrationRateLimited extends RuntimeException
{
    public function __construct(public readonly int $retryAfterSeconds)
    {
        parent::__construct('The public OAuth client registration rate limit was reached.');
    }
}
