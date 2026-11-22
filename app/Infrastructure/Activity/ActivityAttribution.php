<?php

namespace App\Infrastructure\Activity;

/**
 * Immutable, server-owned attribution for deferred work with no HTTP request.
 * Never carries an OAuth bearer/refresh token or raw credential.
 */
final readonly class ActivityAttribution
{
    private function __construct(
        public string $actorType,
        public string $actorId,
        public ?string $clientHash,
        public ?string $clientProfileKey,
    ) {}

    public static function fromBatch(object $batch): self
    {
        $actorId = (string) $batch->actor_user_id;
        if (! ctype_digit($actorId) || (int) $actorId < 1) {
            throw new \RuntimeException('Batch Activity has no valid persisted actor.');
        }
        if ($batch->source_channel === 'web') {
            return new self('administrator', $actorId, null, null);
        }
        if ($batch->source_channel !== 'mcp'
            || ! is_string($batch->client_id) || $batch->client_id === ''
            || ! is_string($batch->client_profile_key)
            || preg_match('/^[a-z][a-z0-9_-]{0,47}$/D', $batch->client_profile_key) !== 1
            || ! hash_equals((string) $batch->client_identity_hash,
                hash('sha256', $batch->client_profile_key."\0".$batch->client_id))) {
            throw new \RuntimeException('Batch Activity has invalid persisted OAuth Client provenance.');
        }

        // ActivityFeed intentionally hashes the raw client_id (not the
        // profile-scoped Batch admission hash), preserving its strict filter.
        return new self(
            'oauth_user', $actorId, hash('sha256', $batch->client_id),
            $batch->client_profile_key,
        );
    }
}
