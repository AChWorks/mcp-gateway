<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;

/** Non-secret immutable SSH endpoint/trust identity used by retained Jobs. */
final class SshTargetBinding
{
    public static function hash(Target $target, SshTargetConfig $config): string
    {
        $parts = [
            (string) $target->getKey(), (string) $target->target_id,
            (string) $config->host, (string) $config->port,
            (string) $config->username, (string) $config->auth_method,
            (string) $config->pinned_host_key,
        ];
        if (($config->route_mode ?? 'direct') !== 'direct') {
            $parts = [
                ...$parts, (string) $config->route_mode,
                (string) $config->reverse_listener_port,
                (string) $config->reverse_tunnel_identity,
            ];
        }

        // Legacy direct bindings intentionally retain their exact previous
        // digest: migrations must not strand existing encrypted credentials or Jobs.
        return hash('sha256', implode("\0", $parts));
    }
}
