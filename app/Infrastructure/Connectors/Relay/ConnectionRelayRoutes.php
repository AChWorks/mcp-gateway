<?php

namespace App\Infrastructure\Connectors\Relay;

use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\OutboundRequestException;
use Illuminate\Support\Collection;

/**
 * Resolves a persisted, enabled, Target-scoped Relay route.
 * The data plane connects through local SOCKS5 and independently verifies
 * the actual SSH/HTTPS Target identity.
 */
final readonly class ConnectionRelayRoutes
{
    /** @return array<string,list<string>> */
    public static function selectionRules(): array
    {
        return [
            'connection_relay_id' => ['nullable', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
        ];
    }

    /** @return Collection<int,ConnectionRelay> */
    public function selectable(): Collection
    {
        return ConnectionRelay::query()->where('enabled', true)->orderBy('display_name')
            ->get();
    }

    public function selected(?string $relayId): ?ConnectionRelay
    {
        return $this->resolveSelection($relayId, false);
    }

    /**
     * Only call inside the same DB transaction that persists the Target
     * binding. This lock serializes new enrollment/rebinding against Disable's
     * Relay-then-Targets lock order. It is not an outbound connectivity probe.
     */
    public function selectedForBinding(?string $relayId): ?ConnectionRelay
    {
        return $this->resolveSelection($relayId, true);
    }

    private function resolveSelection(?string $relayId, bool $lock): ?ConnectionRelay
    {
        if ($relayId === null || $relayId === '') {
            return null;
        }
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $relayId) !== 1) {
            throw new ConnectionRelayUnavailable;
        }
        $query = ConnectionRelay::query()->where('relay_id', $relayId);
        $relay = ($lock ? $query->lockForUpdate() : $query)->first();
        if (! $relay instanceof ConnectionRelay || ! $relay->enabled) {
            throw new ConnectionRelayUnavailable;
        }

        return $relay;
    }

    public function routeForSelection(?string $relayId): ?LocalSocks5Route
    {
        $relay = $this->selected($relayId);

        return $relay === null ? null : LocalSocks5Route::fromApprovedBinding($relay->relay_id, $relay->local_socks_port);
    }

    /** All Target-bound HTTP uses the admitted snapshot's persisted route epoch. */
    public function httpRouteForTarget(Target $target): ?LocalSocks5Route
    {
        return $this->httpRouteAtEpoch((string) $target->getKey(), (int) $target->relay_binding_revision);
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

        try {
            $actual = $this->routeForTarget($target);
        } catch (ConnectionRelayUnavailable) {
            throw new OutboundRequestException(
                'network_failure', 'The selected Connection Relay is unavailable.',
                ['failure_stage' => 'connection_setup'], true,
            );
        }
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

    private function routeForTarget(Target $target): ?LocalSocks5Route
    {
        $id = $target->getAttribute('relay_record_id');
        if ($id === null || $id === '') {
            return null;
        }
        $relay = ConnectionRelay::query()->find($id);
        if (! $relay instanceof ConnectionRelay || ! $relay->enabled) {
            throw new ConnectionRelayUnavailable;
        }

        return LocalSocks5Route::fromApprovedBinding($relay->relay_id, $relay->local_socks_port);
    }
}
