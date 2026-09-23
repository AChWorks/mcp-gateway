<?php

namespace App\Application\Sites;

use RuntimeException;

final class SiteCheckOperationException extends RuntimeException
{
    public function __construct(
        public readonly string $reason,
        string $message,
        public readonly ?string $operationId = null,
    ) {
        parent::__construct($message);
    }
}
