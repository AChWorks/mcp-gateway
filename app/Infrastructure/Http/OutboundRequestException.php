<?php

namespace App\Infrastructure\Http;

use RuntimeException;

final class OutboundRequestException extends RuntimeException
{
    /**
     * Only bounded, safe machine metadata. Never include a rejected response body or secrets.
     *
     * @param  array{limit_bytes?:int,observed_bytes?:int,phase?:string,failure_stage?:string,http_status?:int}  $details
     */
    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly array $details = [],
        // True only when no HTTP application request/payload could have
        // reached the destination (including failed TCP/TLS setup).
        // Unknown send/receive failures must remain false because an OAuth
        // rotating credential may already have been consumed remotely.
        public readonly bool $preDispatch = false,
    ) {
        parent::__construct($message);
    }
}
