<?php

namespace App\Infrastructure\Connectors\Relay;

use RuntimeException;

/** No authorization to fall back to a different connection path. */
final class ConnectionRelayUnavailable extends RuntimeException
{
    public function __construct(string $message = 'relay_unavailable')
    {
        parent::__construct($message);
    }
}
