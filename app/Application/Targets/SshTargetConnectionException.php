<?php

namespace App\Application\Targets;

use RuntimeException;

final class SshTargetConnectionException extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        // Never propagate socket, crypto or credential exception details to UI/MCP.
        parent::__construct('SSH connection cannot be completed safely.');
    }
}
