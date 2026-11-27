<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Targets\Target;

/**
 * A local owner-selected Reverse SSH route is usable only when the same
 * Target/port/tunnel identity is independently allowlisted by the operator.
 * No DNS, arbitrary private address, caller-supplied host, or dynamic port
 * is authorized by this exception to the ordinary public-address policy.
 */
final class SshReverseRoutePolicy
{
    public function forTarget(Target $target): ?SshReverseRoute
    {
        $managed = SshManagedReverseEnrollment::query()->where('target_id', $target->target_id)->first();
        if ($managed && ((string) $managed->target_record_id !== (string) $target->getKey()
            || ($managed->state !== 'revoked' && ! $target->usesReverseRoute()))) {
            // No silent Direct fallback from a live or pending managed
            // tunnel, even if an internal caller bypassed the Admin form.
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }

        return $this->approve(
            (string) $target->target_id, $target->usesReverseRoute() ? 'reverse' : 'direct',
            $target->reverse_listener_port, $target->reverse_tunnel_identity,
        );
    }

    public function assertPortAvailable(SshReverseRoute $route, ?string $existingTargetRecordId = null): void
    {
        $query = Target::query()->where('reverse_listener_port', $route->listenerPort);
        if ($existingTargetRecordId !== null) {
            $query->where('id', '!=', $existingTargetRecordId);
        }
        if ($query->exists()) {
            throw new SshTargetConnectionException('reverse_listener_conflict');
        }
    }

    public function approve(string $targetId, string $mode, mixed $port, mixed $identity): ?SshReverseRoute
    {
        if ($mode === 'direct') {
            if (! in_array($port, [null, ''], true) || ! in_array($identity, [null, ''], true)) {
                throw new SshTargetConnectionException('reverse_route_not_approved');
            }

            return null;
        }
        if ($mode !== 'reverse') {
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }

        $number = filter_var($port, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1024, 'max_range' => 65535],
        ]);
        if (! is_int($number) || ! is_string($identity)
            || preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/D', $identity) !== 1) {
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }
        $allowed = $this->approvedRoutes();
        // An empty/malformed/multi-owner port assignment fails closed. No
        // app-level listener can choose its own identity by changing DB fields.
        $entry = $allowed[$targetId] ?? null;
        if ($allowed === null) {
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }
        if ($entry !== null && $entry['port'] === $number
            && $entry['tunnel_identity'] === $identity) {
            // A managed identity must never override or shadow a legacy operator key.
            if (SshManagedReverseEnrollment::query()->where('target_id', $targetId)->exists()) {
                throw new SshTargetConnectionException('reverse_route_not_approved');
            }

            return SshReverseRoute::fromApprovedPolicy($targetId, $number, $identity);
        }

        if (! SshManagedReverseGateway::active() || isset($allowed[$targetId])) {
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }
        // The DB approval is independent of the Target form, and is usable
        // only after a one-use enrollment is claimed and host keys are staged.
        $managed = SshManagedReverseEnrollment::query()
            ->where('target_id', $targetId)
            ->where('listener_port', $number)
            ->where('tunnel_identity', $identity)
            ->where('state', 'active')
            ->whereNull('revoked_at')
            ->whereNotNull('control_public_key')
            ->first();
        if (! $managed || $managed->tunnel_identity !== $identity || in_array($number, array_column($allowed, 'port'), true)) {
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }

        return SshReverseRoute::fromApprovedPolicy($targetId, $number, $identity);
    }

    /** @return array<string,array{port:int,tunnel_identity:string}>|null */
    public function approvedRoutes(): ?array
    {
        $raw = config('ssh.reverse_approved_routes');
        if (! is_string($raw)) {
            return null;
        }
        if (trim($raw) === '') {
            return [];
        }
        $document = json_decode($raw, false, 16);
        // Require an object map, not a JSON array of unowned ports.
        $allowed = $document instanceof \stdClass ? json_decode($raw, true, 16) : null;

        return is_array($allowed) && $this->unambiguousAllowlist($allowed) ? $allowed : null;
    }

    /** @param array<string,mixed> $allowed */
    private function unambiguousAllowlist(array $allowed): bool
    {
        $usedPorts = [];
        foreach ($allowed as $targetId => $route) {
            if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1
                || ! is_array($route) || count($route) !== 2
                || ! is_int($route['port'] ?? null)
                || $route['port'] < 1024 || $route['port'] > 65535
                || ! is_string($route['tunnel_identity'] ?? null)
                || preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/D', $route['tunnel_identity']) !== 1
                || isset($usedPorts[$route['port']])) {
                return false;
            }
            $usedPorts[$route['port']] = true;
        }

        return true;
    }
}
