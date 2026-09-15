<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use RuntimeException;
use Throwable;

final class WpAiBridgeMcpException extends RuntimeException
{
    public function __construct(
        public readonly string $reason,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
