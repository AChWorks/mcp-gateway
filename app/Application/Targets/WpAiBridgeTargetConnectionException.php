<?php

namespace App\Application\Targets;

use RuntimeException;

final class WpAiBridgeTargetConnectionException extends RuntimeException
{
    /** @param array<string,mixed> $diagnostics Safe scalar cause metadata only. */
    public function __construct(public readonly string $reason, string $message, public readonly array $diagnostics = [])
    {
        parent::__construct($message);
    }
}
