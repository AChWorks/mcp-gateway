<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use RuntimeException;

final class BridgeDiscoveryException extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
