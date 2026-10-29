<?php

namespace App\Application\Targets;

/** A read-only, time-of-check observation, never an authorization or trust proof. */
final readonly class TargetPreflightResult
{
    public function __construct(
        public string $message,
        public string $limitation,
        // This exact, non-secret endpoint was checked at the time of the probe.
        public string $checkedSubject,
        /** @var array<string, string> Values of the reviewed non-secret endpoint form inputs. */
        public array $checkedFields,
    ) {}
}
