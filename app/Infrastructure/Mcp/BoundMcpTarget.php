<?php

namespace App\Infrastructure\Mcp;

use App\Application\Targets\TargetOperationGate;
use App\Domain\Targets\Target;
use InvalidArgumentException;
use LogicException;

/**
 * Request-scoped downstream transport binding. A connector must acquire the
 * provider-owned credential for the actual authorized caller before creating it.
 *
 * This is not an authorization grant or an arbitrary-URL registration API.
 */
final readonly class BoundMcpTarget
{
    private function __construct(
        public string $recordId,
        public string $connectorType,
        public string $resourceUrl,
        private string $accessToken,
    ) {}

    public static function forRegisteredTarget(Target $target, string $resourceUrl, string $accessToken): self
    {
        if (! $target->exists || ! is_string($target->getKey()) || $target->getKey() === '') {
            throw new InvalidArgumentException('A persisted Gateway Target is required for downstream MCP.');
        }

        // Only the owning connector may supply a previously verified, stored
        // resource URL and an actual caller-bound downstream credential.
        // SafeHttpClient revalidates HTTPS, DNS/public IP, TLS and redirects at
        // every dispatch; neither tools/list nor tools/call accepts a URL.
        if ($resourceUrl === '' || strlen($resourceUrl) > 2048
            || ! str_starts_with($resourceUrl, 'https://')
            || $accessToken === '' || strlen($accessToken) > 8192
            || preg_match('/^[A-Za-z0-9._~+\/-]+={0,}$/D', $accessToken) !== 1) {
            throw new InvalidArgumentException('Downstream MCP endpoint or credential binding is invalid.');
        }

        return new self(
            (string) $target->getKey(),
            (string) $target->connector_type,
            $resourceUrl,
            $accessToken,
        );
    }

    public function assertCurrentTarget(Target $target): void
    {
        if (! $target->exists || ! hash_equals($this->recordId, (string) $target->getKey())
            || ! hash_equals($this->connectorType, (string) $target->connector_type)) {
            throw new OutboundMcpFailure(
                'target_binding_mismatch', 'not_executed', 'admission',
                'Downstream MCP is not bound to this Gateway Target.',
            );
        }

        // Re-read the persisted identity and connection state. A stale Eloquent
        // object or a paused/deleted/disconnected Target is not an admission.
        if (! Target::query()->whereKey($this->recordId)
            ->where('connector_type', $this->connectorType)
            ->where('connection_state', 'connected')->exists()
            || TargetOperationGate::isPaused($target)) {
            throw new OutboundMcpFailure(
                'target_unavailable', 'not_executed', 'admission',
                'The bound Gateway Target is not connected or is paused.',
            );
        }
    }

    public function authorizationHeader(): string
    {
        return 'Bearer '.$this->accessToken;
    }

    /** Do not emit a reusable bearer in accidental debugging or serialization. */
    public function __debugInfo(): array
    {
        return [
            'recordId' => $this->recordId,
            'connectorType' => $this->connectorType,
            'resourceUrl' => $this->resourceUrl,
            'accessToken' => '[redacted]',
        ];
    }

    public function __serialize(): array
    {
        throw new LogicException('A downstream MCP bearer binding may not be serialized.');
    }
}
