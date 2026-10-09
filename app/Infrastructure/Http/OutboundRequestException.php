<?php

namespace App\Infrastructure\Http;

use RuntimeException;

final class OutboundRequestException extends RuntimeException
{
    /**
     * Only bounded, safe machine metadata. Never include a rejected response body or secrets.
     *
     * @param  array{limit_bytes?:int,observed_bytes?:int,phase?:string}  $details
     */
    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly array $details = [],
    ) {
        parent::__construct($message);
    }
}
