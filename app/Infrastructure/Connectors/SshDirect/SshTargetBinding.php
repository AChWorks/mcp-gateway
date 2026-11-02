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
        $epoch = (int) ($config->binding_revision ?? 0);
        if ($epoch > 0 || ($config->route_mode ?? 'direct') !== 'direct') {
            $parts = [
                ...$parts, (string) ($config->route_mode ?? 'direct'),
                (string) $config->reverse_listener_port,
                (string) $config->reverse_tunnel_identity,
                (string) $epoch,
            ];
        }

        // Untouched legacy Direct bindings (epoch=0) intentionally retain
        // their exact previous digest. A->B->A route/trust changes NEVER
        // revive prior Jobs because the epoch cannot decrease.
        return hash('sha256', implode("\0", $parts));
    }
}
