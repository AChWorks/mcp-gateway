<?php

namespace App\Infrastructure\Connectors\Relay;

use RuntimeException;

/** No authorization to fall back to a different connection path. */
final class ConnectionRelayUnavailable extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('relay_unavailable');
    }
}
