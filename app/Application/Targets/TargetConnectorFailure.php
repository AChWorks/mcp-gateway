<?php

namespace App\Application\Targets;

use RuntimeException;

/** A connector-specific failure translated to a bounded, non-secret Admin message. */
final class TargetConnectorFailure extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?string $field = null,
        public readonly ?string $reason = null,
        /** @var array<string,mixed> */
        public readonly array $diagnostics = [],
    ) {
        parent::__construct($message);
    }
}
