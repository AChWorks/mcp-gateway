<?php

namespace App\Infrastructure\OAuth;

use RuntimeException;
use Throwable;

final class OAuthClientMetadataUnavailable extends RuntimeException
{
    public function __construct(
        public readonly ?int $upstreamStatus = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct('OAuth client identity metadata is unavailable.', 0, $previous);
    }
}
