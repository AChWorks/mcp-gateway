<?php

namespace App\Infrastructure\Http;

use RuntimeException;

final class OutboundRequestException extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
