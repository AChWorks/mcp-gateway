<?php

namespace App\Application\Targets;

final readonly class TargetConnectorResult
{
    public function __construct(
        public ?string $redirectUrl = null,
        public ?string $statusMessage = null,
        // Required for redirectUrl: the origin verified by the trusted connector.
        public ?string $authorizedOrigin = null,
    ) {}
}
