<?php

namespace App\Application\Targets;

/** A read-only, time-of-check observation, never an authorization or trust proof. */
final readonly class TargetPreflightResult
{
    public function __construct(
        public string $message,
        public string $limitation,
    ) {}
}
