<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;

/** Non-secret immutable SSH endpoint/trust identity used by retained Jobs. */
final class SshTargetBinding
{
    public static function hash(Target $target, SshTargetConfig $config): string
    {
        return hash('sha256', implode("\0", [
            (string) $target->getKey(), (string) $target->target_id,
            (string) $config->host, (string) $config->port,
            (string) $config->username, (string) $config->auth_method,
            (string) $config->pinned_host_key,
        ]));
    }
}
