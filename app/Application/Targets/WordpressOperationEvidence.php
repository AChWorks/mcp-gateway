<?php

namespace App\Application\Targets;

use App\Infrastructure\Activity\ActivityAttribution;
use App\Support\OperationDiagnostics;
use Illuminate\Support\Str;

/** Request-local native result evidence for the existing durable Batch consumer. */
final class WordpressOperationEvidence
{
    public readonly string $reference;

    /** @var array<string,mixed> */
    public array $diagnostics = [];

    public function __construct(public readonly ActivityAttribution $attribution)
    {
        $this->reference = (string) Str::uuid();
    }

    /** @param array<string,mixed> $details */
    public function failure(string $code, array $details): void
    {
        // Local admission failures have no downstream origin. When the
        // connector supplied a more specific native cause, retain it.
        if ($details === [] && in_array($code, ['forbidden', 'target_not_found', 'invalid_input', 'target_paused'], true)) {
            $details = ['failure_origin' => 'gateway_admission', 'failure_stage' => 'admission', 'request_not_sent' => true];
        }
        $this->diagnostics = OperationDiagnostics::safeContext([
            ...$details, 'provider_error_code' => $code,
        ]);
    }
}
