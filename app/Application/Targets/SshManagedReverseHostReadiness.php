<?php

namespace App\Application\Targets;

use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use phpseclib4\Net\SSH2;
use Throwable;

/**
 * Bounded, unauthenticated loopback SSH host-key probe. No OS privilege,
 * systemctl execution, public egress, credentials or mutable host effects.
 * This is local readiness, NOT proof of remote Target network reachability.
 */
final class SshManagedReverseHostReadiness
{
    public function __construct(private SshManagedReverseAuthorizedKeys $keys) {}

    /** @return array{state:string,reason:string,external:string} */
    public function assess(?SshManagedReverseGateway $gateway): array
    {
        $result = static fn (string $state, string $reason): array => [
            'state' => $state,
            'reason' => $reason,
            'external' => 'Not verified — check TCP egress from each Target to the configured control endpoint.',
        ];

        $manifest = $this->keys->hostManifest();
        if ($manifest === null) {
            return $result($gateway?->enabled ? 'Degraded' : 'Needs host setup',
                'Trusted host manifest missing or invalid, or unreadable under PHP open_basedir. Verify the approved host bootstrap and PHP path restrictions without disabling PHP isolation.');
        }
        if (! $this->keys->canPublish()) {
            return $result('Degraded',
                'Restricted key reader is unavailable or not writable by the approved PHP worker.');
        }
        if (! $gateway?->enabled) {
            return $result('Disabled', 'Managed routing is disabled by Owner configuration.');
        }
        if (! $this->keys->matchesGateway($gateway)) {
            return $result('Degraded',
                'Control SSHD host identity, username or port differs from its root-owned manifest.');
        }
        if (! $this->keys->isReconciled()) {
            return $result('Degraded',
                'The SSH key reader differs from durable enrollment policy or a publication is pending. Use Reconcile.');
        }

        $port = (int) $manifest['control_port'];
        $errno = 0;
        $error = '';
        $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errno, $error, 2, STREAM_CLIENT_CONNECT);
        if (! is_resource($socket)) {
            return $result('Degraded',
                'Local control SSHD listener not reachable from the PHP network namespace. Check systemd, port and namespace.');
        }
        try {
            $ssh = new SSH2($socket, $port, 3);
            $ssh->setTimeout(3);
            $presented = $ssh->getServerPublicHostKey();
            if (! is_string($presented)
                || ! SshHostKeyPin::fromLine($manifest['control_host_key'])->matches($presented)) {
                return $result('Degraded',
                    'The local control listener presented a different SSH host key. Check for a conflicting service.');
            }

            return $result('Ready',
                'Local TCP/SSH handshake verified the pinned control host key. systemd unit health and Target-side egress remain separately verifiable.');
        } catch (Throwable) {
            return $result('Degraded',
                'The control TCP port did not complete a valid pinned SSH handshake. Check isolated SSHD logs/configuration.');
        } finally {
            fclose($socket);
        }
    }
}
