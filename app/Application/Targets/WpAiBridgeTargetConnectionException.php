<?php

namespace App\Application\Targets;

use RuntimeException;

final class WpAiBridgeTargetConnectionException extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
