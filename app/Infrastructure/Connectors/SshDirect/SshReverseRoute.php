<?php

namespace App\Infrastructure\Connectors\SshDirect;

/**
 * A narrowly approved loopback-only remote forward, never a generic proxy.
 * Construct exclusively via the operator-managed allowlist policy.
 */
final readonly class SshReverseRoute
{
    private function __construct(
        public string $targetId,
        public int $listenerPort,
        public string $tunnelIdentity,
    ) {}

    public static function fromApprovedPolicy(string $targetId, int $port, string $identity): self
    {
        return new self($targetId, $port, $identity);
    }
}
