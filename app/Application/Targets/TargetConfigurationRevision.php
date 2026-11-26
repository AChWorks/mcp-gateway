<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;

/**
 * Opaque optimistic concurrency token for the actual mutation scope.
 * Callers project only the editable fields and genuinely coupled authority.
 * Observations, timestamps and unrelated metadata are never implicit inputs.
 */
final class TargetConfigurationRevision
{
    /** @param array<string, mixed> $configuration */
    public static function make(Target $target, array $configuration, ?string $credentialBinding): string
    {
        return hash('sha256', json_encode([
            (string) $target->getKey(),
            $target->target_id,
            $target->connector_type,
            $configuration,
            $credentialBinding,
        ], JSON_THROW_ON_ERROR));
    }
}
