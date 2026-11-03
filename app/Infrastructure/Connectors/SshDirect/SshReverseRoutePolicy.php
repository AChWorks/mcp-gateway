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
    public function forTarget(Target $target, SshTargetConfig $config): ?SshReverseRoute
    {
        if ($target->connector_type !== 'ssh_direct'
            || (string) $config->target_record_id !== (string) $target->getKey()) {
            throw new SshTargetConnectionException('target_changed');
        }

        return $this->approve(
            (string) $target->target_id, (string) ($config->route_mode ?? 'direct'),
            $config->reverse_listener_port, $config->reverse_tunnel_identity,
        );
    }

    public function assertPortAvailable(SshReverseRoute $route, ?string $existingTargetRecordId = null): void
    {
        $query = SshTargetConfig::query()->where('route_mode', 'reverse')
            ->where('reverse_listener_port', $route->listenerPort);
        if ($existingTargetRecordId !== null) {
            $query->where('target_record_id', '!=', $existingTargetRecordId);
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
        $raw = config('ssh.reverse_approved_routes', '');
        $document = is_string($raw) ? json_decode($raw, false, 16) : null;
        // Require an object map, not a JSON array of unowned ports.
        $allowed = $document instanceof \stdClass ? json_decode($raw, true, 16) : null;
        if (! is_array($allowed) || ! $this->unambiguousAllowlist($allowed)) {
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }
        // An empty/malformed/multi-owner port assignment fails closed. No
        // app-level listener can choose its own identity by changing DB fields.
        $entry = $allowed[$targetId] ?? null;
        if (! is_array($entry) || count($entry) !== 2
            || ($entry['port'] ?? null) !== $number
            || ($entry['tunnel_identity'] ?? null) !== $identity) {
            throw new SshTargetConnectionException('reverse_route_not_approved');
        }

        return SshReverseRoute::fromApprovedPolicy($targetId, $number, $identity);
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
