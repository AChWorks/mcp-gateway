<?php

namespace App\Infrastructure\Mcp;

use RuntimeException;
use Throwable;

/**
 * Transport-local machine evidence; the application layer still owns
 * operator-visible projection, authorization and protected diagnostics.
 */
final class OutboundMcpFailure extends RuntimeException
{
    /**
     * @param  array<string, bool|int|string>  $details  Bounded nonsecret evidence only.
     */
    public function __construct(
        public readonly string $reason,
        public readonly string $outcome,
        public readonly string $phase,
        string $message,
        public readonly array $details = [],
        public readonly ?string $reference = null,
        public readonly ?string $upstreamRequestId = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
