<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use RuntimeException;

final class BridgeDiscoveryException extends RuntimeException
{
    /** @param array<string,mixed> $diagnostics No URL, token, response body or exception text. */
    public function __construct(public readonly string $reason, string $message, public readonly array $diagnostics = [])
    {
        parent::__construct($message);
    }
}
