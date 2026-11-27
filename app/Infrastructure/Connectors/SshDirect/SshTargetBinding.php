<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;

/** Independent peer, route and grant evidence; retained Job identity is immutable. */
final class SshTargetBinding
{
    /** @return list<string> */
    public static function endpointParts(Target $target, SshTargetConfig $config, ?string $canonicalHostKey = null): array
    {
        return [
            (string) $target->getKey(), (string) $target->target_id,
            (string) $config->host, (string) $config->port,
            (string) $config->username, (string) $config->auth_method,
            $canonicalHostKey ?? (string) $config->pinned_host_key,
        ];
    }

    /** Peer/trust identity and ABA generation, with no transport or credential. */
    public static function peerFingerprint(Target $target, SshTargetConfig $config): string
    {
        return hash('sha256', json_encode([
            ...self::endpointParts($target, $config),
            (string) $config->getKey(), (string) $config->target_record_id,
            (int) $config->binding_revision,
        ], JSON_THROW_ON_ERROR));
    }

    /** Exact identity of the authenticated session used for a new effect or Verify. */
    public static function executionFingerprint(
        Target $target, SshTargetConfig $config, TargetCredential $credential,
    ): string {
        return hash('sha256', json_encode([
            self::peerFingerprint($target, $config),
            $target->transportAuthorityFingerprint(),
            (string) $credential->target_record_id, $credential->connector_type,
            $credential->purpose, $credential->dispatchFingerprint(),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * Retained Job launch endpoint/route identity, including its persisted
     * evidence format. This is a single historical artifact contract, not an
     * alternative admission hash. Do not rewrite already-dispatched Jobs.
     */
    public static function hash(Target $target, SshTargetConfig $config): string
    {
        $parts = self::endpointParts($target, $config);
        $epoch = (int) ($config->binding_revision ?? 0);
        if ($epoch > 0 || $target->usesReverseRoute()) {
            $parts = [
                ...$parts, $target->usesReverseRoute() ? 'reverse' : 'direct',
                (string) $target->reverse_listener_port,
                (string) $target->reverse_tunnel_identity,
                (string) $epoch,
            ];
        }

        $routeEpoch = (int) ($target->getAttribute('transport_revision') ?? 0);
        $relayId = $target->getAttribute('relay_record_id');
        if ($routeEpoch > 0 || $relayId !== null) {
            $parts = [...$parts, 'connection_relay', (string) $relayId, (string) $routeEpoch];
        }

        return hash('sha256', implode("\0", $parts));
    }
}
