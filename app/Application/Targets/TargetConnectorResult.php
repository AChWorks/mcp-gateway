<?php

namespace App\Application\Targets;

final readonly class TargetConnectorResult
{
    public function __construct(
        public ?string $redirectUrl = null,
        public ?string $statusMessage = null,
    ) {}
}
