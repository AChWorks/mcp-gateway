<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use DateTimeInterface;

/** Safe local projection; never resolves DNS or reads credentials. */
final class SshTargetIdentity
{
    /**
     * @return array{registered_host:string,username:string,port:int,ip:?string,ip_status:string,observed_at:?string,destination_label:string,route_mode:string,reverse_listener_port:?int,reverse_tunnel_identity:?string}|null
     */
    public static function safeMetadata(Target $target): ?array
    {
        if ($target->connector_type !== 'ssh_direct') {
            return null;
        }
        $config = $target->sshConfig;
        if (! $config instanceof SshTargetConfig) {
            return null;
        }
        $endpoint = $config->endpoint();
        $currentRoute = (int) $target->transport_revision === 0 || $target->last_tested_at !== null;
        $observed = $currentRoute ? $config->observed_peer_ip : null;
        $state = $target->getAttribute('connection_state');
        $seenAt = $currentRoute ? $config->getAttribute('observed_at') : null;
        $literal = $endpoint->configuredIp();
        $ip = $observed ?? $literal;
        $reverse = $target->usesReverseRoute();
        $verified = $state === TargetConnectionState::Connected && $target->last_error_code === null;
        $ipStatus = $reverse && $seenAt !== null
            ? ($verified ? 'reverse_route_verified' : 'reverse_route_stale')
            : ($observed !== null
                ? ($verified ? 'last_verified' : 'stale')
                : ($literal !== null ? 'registered_unverified' : 'not_yet_verified'));

        $host = $ip ?? $endpoint->host;
        $displayHost = str_contains($host, ':') ? '['.$host.']' : $host;

        return [
            'registered_host' => $endpoint->host,
            'username' => $endpoint->username,
            'port' => $endpoint->port,
            'ip' => $ip,
            'ip_status' => $ipStatus,
            'observed_at' => $seenAt instanceof DateTimeInterface ? $seenAt->format(DATE_ATOM) : null,
            'destination_label' => $endpoint->username.'@'.$displayHost.':'.$endpoint->port,
            'route_mode' => $target->transportKind(),
            'reverse_listener_port' => $reverse ? $target->reverse_listener_port : null,
            'reverse_tunnel_identity' => $reverse ? $target->reverse_tunnel_identity : null,
        ];
    }
}
