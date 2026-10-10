<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use Closure;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Net\SSH2;
use Throwable;

/**
 * Numeric-only TCP dial -> actual socket peer -> cryptographic host-key proof
 * -> independent pinned-key comparison -> credential login, in this order.
 * Never construct SSH2 with a hostname or caller-selected destination.
 */
final readonly class SshVerifiedTransport
{
    public function __construct(
        private SshDialAddressPolicy $policy,
        private SshAlgorithmPolicy $algorithms,
    ) {}

    public function authenticate(
        SshRegisteredEndpoint $endpoint, SshHostKeyPin $pin,
        string $authMethod, string $secret, ?string $passphrase,
    ): string {
        return $this->withAuthenticatedSession(
            $endpoint, $pin, $authMethod, $secret, $passphrase,
            static fn (SSH2 $ssh, string $peerIp): string => $peerIp,
        );
    }

    /**
     * Invoke one operation on a verified and authenticated connection. The
     * callback cannot bypass pin verification or select a different endpoint.
     * All socket/session cleanup remains owned by this transport.
     *
     * @param  Closure(SSH2,string):mixed  $operation
     */
    public function withAuthenticatedSession(
        SshRegisteredEndpoint $endpoint, SshHostKeyPin $pin,
        string $authMethod, string $secret, ?string $passphrase,
        Closure $operation,
    ): mixed {
        $privateKey = null;
        $rsaClientAuthentication = false;
        if ($authMethod === 'password') {
            if ($passphrase !== null) {
                throw new SshTargetConnectionException('credential_invalid');
            }
        } elseif ($authMethod === 'private_key') {
            try {
                $privateKey = PublicKeyLoader::loadPrivateKey($secret, $passphrase);
                $rsaClientAuthentication = $privateKey instanceof RSA;
            } catch (Throwable) {
                throw new SshTargetConnectionException('credential_invalid');
            }
        } else {
            throw new SshTargetConnectionException('credential_invalid');
        }

        try {
            $approved = $this->policy->approvedDialAddresses($endpoint);
        } catch (Throwable) {
            throw new SshTargetConnectionException('egress_denied');
        }

        // One approved connection attempt. In particular, never retry a key
        // mismatch against a different DNS answer or silently rebind a Target.
        $ip = $approved[0];
        if (@inet_pton($ip) === false) {
            throw new SshTargetConnectionException('egress_denied');
        }
        $address = 'tcp://'.(str_contains($ip, ':') ? '['.$ip.']' : $ip).':'.$endpoint->port;
        $errno = 0;
        $error = '';
        $socket = @stream_socket_client($address, $errno, $error, 5, STREAM_CLIENT_CONNECT);
        if (! is_resource($socket)) {
            throw new SshTargetConnectionException('tcp_unreachable');
        }

        $ssh = null;
        try {
            $peer = @stream_socket_get_name($socket, true);
            $peerHost = is_string($peer) ? parse_url('tcp://'.$peer, PHP_URL_HOST) : false;
            $peerPort = is_string($peer) ? parse_url('tcp://'.$peer, PHP_URL_PORT) : false;
            $peerIp = is_string($peerHost) ? trim($peerHost, '[]') : '';
            if ($peerPort !== $endpoint->port || @inet_pton($peerIp) === false
                || ! hash_equals((string) inet_pton($ip), (string) inet_pton($peerIp))) {
                throw new SshTargetConnectionException('tcp_peer_mismatch');
            }

            try {
                $ssh = new SSH2($socket, $endpoint->port, 8);
                $ssh->setTimeout(8);
                $ssh->setPreferredAlgorithms(
                    $this->algorithms->preferredAlgorithms($pin, $rsaClientAuthentication),
                );
                $serverKey = $ssh->getServerPublicHostKey();
            } catch (Throwable) {
                throw new SshTargetConnectionException('ssh_handshake_failed');
            }
            if (! is_string($serverKey) || ! $pin->matches($serverKey)) {
                throw new SshTargetConnectionException('host_key_mismatch');
            }

            try {
                $authenticated = $authMethod === 'password'
                    ? $ssh->login($endpoint->username, $secret)
                    : $ssh->login($endpoint->username, $privateKey);
            } catch (Throwable) {
                throw new SshTargetConnectionException('authentication_failed');
            }

            if (! $authenticated) {
                throw new SshTargetConnectionException('authentication_failed');
            }

            return $operation($ssh, $peerIp);
        } finally {
            if ($ssh instanceof SSH2) {
                try {
                    $ssh->disconnect();
                } catch (Throwable) {
                    // Session/remote outcome is already known to the caller.
                    // Closing the underlying socket is the final safeguard.
                }
            }
            if (get_resource_type($socket) === 'stream') {
                fclose($socket);
            }
        }
    }
}
