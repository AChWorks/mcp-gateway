<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use DateTimeInterface;

/** Safe local projection; never resolves DNS or reads credentials. */
final class SshTargetIdentity
{
    /**
     * @return array{registered_host:string,username:string,port:int,ip:?string,ip_status:string,observed_at:?string,destination_label:string}|null
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
        $observed = $config->observed_peer_ip;
        $state = $target->getAttribute('connection_state');
        $seenAt = $config->getAttribute('observed_at');
        $literal = $endpoint->configuredIp();
        $ip = $observed ?? $literal;
        $ipStatus = $observed !== null
            ? ($state === TargetConnectionState::Connected ? 'last_verified' : 'stale')
            : ($literal !== null ? 'registered_unverified' : 'not_yet_verified');

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
        ];
    }
}
