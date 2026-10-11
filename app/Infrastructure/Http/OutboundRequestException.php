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
        // True only when the outbound HTTP call is guaranteed not to have
        // started, so OAuth rotation can retain the unconsumed credential.
        public readonly bool $preDispatch = false,
    ) {
        parent::__construct($message);
    }
}
