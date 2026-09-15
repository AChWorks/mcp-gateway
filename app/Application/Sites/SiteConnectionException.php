<?php

namespace App\Application\Sites;

use RuntimeException;

final class SiteConnectionException extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
