<?php

namespace App\Infrastructure\Connectors\Relay;

use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\OutboundRequestException;
use Illuminate\Support\Collection;

/**
 * Resolves a persisted, enabled, host-attested, Target-scoped Relay route.
 * This is a control-plane authorization; the actual numeric data-plane
 * connection still verifies the TCP loopback peer and the remote SSH/TLS pin.
 */
final readonly class ConnectionRelayRoutes
{
    public function __construct(private ConnectionRelayHostReadiness $host) {}

    /** @return Collection<int,ConnectionRelay> */
    public function selectable(): Collection
    {
        return ConnectionRelay::query()->where('enabled', true)->orderBy('display_name')
            ->get()->filter(fn (ConnectionRelay $relay): bool => $this->host->ready($relay))->values();
    }

    public function selected(?string $relayId): ?ConnectionRelay
    {
        if ($relayId === null || $relayId === '') {
            return null;
        }
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $relayId) !== 1) {
            throw new ConnectionRelayUnavailable;
        }
        $relay = ConnectionRelay::query()->where('relay_id', $relayId)->first();
        if (! $relay instanceof ConnectionRelay || ! $relay->enabled || ! $this->host->ready($relay)) {
            throw new ConnectionRelayUnavailable;
        }

        return $relay;
    }

    /**
     * Only call inside the same DB transaction that persists the Target
     * binding. This lock serializes new enrollment/rebinding against Disable's
     * Relay-then-Targets lock order. It is not an outbound connectivity probe.
     */
    public function selectedForBinding(?string $relayId): ?ConnectionRelay
    {
        if ($relayId === null || $relayId === '') {
            return null;
        }
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $relayId) !== 1) {
            throw new ConnectionRelayUnavailable;
        }
        $relay = ConnectionRelay::query()->where('relay_id', $relayId)->lockForUpdate()->first();
        if (! $relay instanceof ConnectionRelay || ! $relay->enabled || ! $this->host->ready($relay)) {
            throw new ConnectionRelayUnavailable;
        }

        return $relay;
    }

    public function routeForSelection(?string $relayId): ?LocalSocks5Route
    {
        $relay = $this->selected($relayId);

        return $relay === null ? null : LocalSocks5Route::fromApprovedBinding($relay->relay_id, $relay->local_socks_port);
    }

    public function httpRouteForTarget(Target $target): ?LocalSocks5Route
    {
        try {
            return $this->routeForTarget($target);
        } catch (ConnectionRelayUnavailable) {
            throw new OutboundRequestException(
                'network_failure', 'The selected Connection Relay is unavailable.',
                ['failure_stage' => 'connection_setup'], true,
            );
        }
    }

    public function httpRouteForRecord(string $targetRecordId): ?LocalSocks5Route
    {
        $target = Target::query()->find($targetRecordId);
        if (! $target instanceof Target) {
            throw new OutboundRequestException('network_failure', 'The selected Target no longer exists.', [], true);
        }

        return $this->httpRouteForTarget($target);
    }

    public function httpRouteAtEpoch(
        string $targetRecordId, int $expectedEpoch, ?LocalSocks5Route $expected = null,
        bool $enforceExpected = false,
    ): ?LocalSocks5Route {
        $target = Target::query()->find($targetRecordId);
        if (! $target instanceof Target || $expectedEpoch < 0
            || (int) ($target->getAttribute('relay_binding_revision') ?? 0) !== $expectedEpoch) {
            throw new OutboundRequestException(
                'network_failure', 'Target route binding changed before HTTP dispatch.',
                ['failure_stage' => 'connection_setup'], true,
            );
        }

        $actual = $this->httpRouteForTarget($target);
        if ($enforceExpected && (
            ($actual === null) !== ($expected === null)
            || ($actual !== null && $expected !== null && ($actual->relayId !== $expected->relayId
                || $actual->loopbackPort !== $expected->loopbackPort))
        )) {
            throw new OutboundRequestException(
                'network_failure', 'Target Relay identity changed before HTTP dispatch.',
                ['failure_stage' => 'connection_setup'], true,
            );
        }

        return $actual;
    }

    public function sshRouteForTarget(Target $target): ?LocalSocks5Route
    {
        try {
            return $this->routeForTarget($target);
        } catch (ConnectionRelayUnavailable) {
            throw new SshTargetConnectionException('relay_unavailable');
        }
    }

    public function routeForTarget(Target $target): ?LocalSocks5Route
    {
        $id = $target->getAttribute('relay_record_id');
        if ($id === null || $id === '') {
            return null;
        }
        $relay = ConnectionRelay::query()->find($id);
        if (! $relay instanceof ConnectionRelay || ! $relay->enabled || ! $this->host->ready($relay)) {
            throw new ConnectionRelayUnavailable;
        }

        return LocalSocks5Route::fromApprovedBinding($relay->relay_id, $relay->local_socks_port);
    }
}
