<?php

namespace App\Application\Targets;

use RuntimeException;

final class SshTargetConnectionException extends RuntimeException
{
    /**
     * Observed, untrusted diagnostic context is never exposed in public errors.
     * Only ActivityRecorder's selective redaction may persist or display it.
     *
     * @param  array<string,mixed>  $diagnostics
     */
    public function __construct(
        public readonly string $reason,
        public readonly array $diagnostics = [],
    ) {
        // Never propagate socket, crypto or credential exception details to UI/MCP.
        parent::__construct('SSH connection cannot be completed safely.');
    }
}
