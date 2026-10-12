<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;

/**
 * Opaque optimistic concurrency token. Never expose or persist a login secret.
 * Changes to the connector configuration OR credential invalidate an old form.
 */
final class TargetConfigurationRevision
{
    /** @param array<string, mixed> $configuration */
    public static function make(Target $target, array $configuration, ?TargetCredential $credential): string
    {
        return hash('sha256', json_encode([
            (string) $target->getKey(),
            $target->target_id,
            $target->connector_type,
            $target->getRawOriginal('connection_state'),
            $configuration,
            $credential?->getKey(),
            $credential?->encrypted_payload,
        ], JSON_THROW_ON_ERROR));
    }
}
