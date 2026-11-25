<?php

namespace App\Infrastructure\Connectors\Relay;

use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\OutboundRequestException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

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
    public function selectedForBinding(?string $relayId, bool $allowDisabled = false): ?ConnectionRelay
    {
        return $this->resolveSelection($relayId, true, $allowDisabled);
    }

    private function resolveSelection(?string $relayId, bool $lock, bool $allowDisabled = false): ?ConnectionRelay
    {
        if ($relayId === null || $relayId === '') {
            return null;
        }
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $relayId) !== 1) {
            throw new ConnectionRelayUnavailable;
        }
        $query = ConnectionRelay::query()->where('relay_id', $relayId);
        $relay = ($lock ? $query->lockForUpdate() : $query)->first();
        if (! $relay instanceof ConnectionRelay || (! $allowDisabled && ! $relay->enabled)) {
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
        return $this->httpRouteAtEpoch((string) $target->getKey(), (int) $target->transport_revision);
    }

    public function httpRouteForCurrentTarget(string $targetRecordId): ?LocalSocks5Route
    {
        return $this->httpRouteAtEpoch($targetRecordId, null);
    }

    public function httpRouteAtEpoch(
        string $targetRecordId, ?int $expectedEpoch, ?LocalSocks5Route $expected = null,
        bool $enforceExpected = false,
    ): ?LocalSocks5Route {
        try {
            $actual = $this->routeAtEpoch($targetRecordId, $expectedEpoch);
        } catch (ConnectionRelayUnavailable $exception) {
            throw new OutboundRequestException(
                'network_failure', $exception->getMessage(),
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
            return $this->routeAtEpoch((string) $target->getKey(), (int) $target->transport_revision, allowReverse: true);
        } catch (ConnectionRelayUnavailable) {
            throw new SshTargetConnectionException('relay_unavailable');
        }
    }

    private function routeAtEpoch(string $targetRecordId, ?int $expectedEpoch, bool $allowReverse = false): ?LocalSocks5Route
    {
        // One database snapshot of both records. Never combine an old Target
        // binding with a Relay endpoint modified after Disable.
        $binding = DB::table('targets as target')
            ->leftJoin('connection_relays as relay', 'relay.id', '=', 'target.relay_record_id')
            ->where('target.id', $targetRecordId)
            ->first(['target.relay_record_id', 'target.transport_revision', 'target.reverse_listener_port',
                'relay.relay_id', 'relay.local_socks_port', 'relay.enabled']);

        if ($binding === null || ($expectedEpoch !== null
            && ($expectedEpoch < 0 || (int) $binding->transport_revision !== $expectedEpoch))) {
            throw new ConnectionRelayUnavailable('Target route binding changed before dispatch.');
        }
        if ($binding->reverse_listener_port !== null && (! $allowReverse || $binding->relay_record_id !== null)) {
            throw new ConnectionRelayUnavailable('The selected fixed Reverse listener is incompatible with this transport.');
        }
        if ($binding->relay_record_id === null) {
            return null;
        }
        if ($binding->relay_id === null || ! $binding->enabled) {
            throw new ConnectionRelayUnavailable('The selected Connection Relay is unavailable.');
        }

        return LocalSocks5Route::fromApprovedBinding((string) $binding->relay_id, (int) $binding->local_socks_port);
    }
}
