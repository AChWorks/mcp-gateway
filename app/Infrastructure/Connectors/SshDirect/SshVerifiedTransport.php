<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Net\SSH2;
use Throwable;

/**
 * Numeric-only TCP dial -> actual socket peer -> cryptographic host-key proof
 * -> independent pinned-key comparison -> credential login, in this order.
 * Never construct SSH2 with a hostname or caller-selected destination.
 */
final readonly class SshVerifiedTransport
{
    public function __construct(private SshDialAddressPolicy $policy) {}

    public function authenticate(
        SshRegisteredEndpoint $endpoint, SshHostKeyPin $pin,
        string $authMethod, string $secret, ?string $passphrase,
    ): string {
        try {
            $approved = $this->policy->approvedDialAddresses($endpoint);
        } catch (Throwable) {
            throw new SshTargetConnectionException('egress_denied');
        }

        // One approved connection attempt. In particular, never retry a key
        // mismatch against a different DNS answer or silently rebind a Target.
        $ip = $approved[0];
        if (@inet_pton($ip) === false) {
            // A policy adapter must never smuggle a hostname into the dialer.
            throw new SshTargetConnectionException('egress_denied');
        }
        $address = 'tcp://'.(str_contains($ip, ':') ? '['.$ip.']' : $ip).':'.$endpoint->port;
        $errno = 0;
        $error = '';
        $socket = @stream_socket_client($address, $errno, $error, 5, STREAM_CLIENT_CONNECT);
        if (! is_resource($socket)) {
            throw new SshTargetConnectionException('tcp_unreachable');
        }

        try {
            $peer = @stream_socket_get_name($socket, true);
            $peerHost = is_string($peer) ? parse_url('tcp://'.$peer, PHP_URL_HOST) : false;
            $peerPort = is_string($peer) ? parse_url('tcp://'.$peer, PHP_URL_PORT) : false;
            $peerIp = is_string($peerHost) ? trim($peerHost, '[]') : '';
            if ($peerPort !== $endpoint->port || @inet_pton($peerIp) === false
                || ! hash_equals((string) inet_pton($ip), (string) inet_pton($peerIp))) {
                throw new SshTargetConnectionException('tcp_peer_mismatch');
            }

            $ssh = new SSH2($socket, $endpoint->port, 8);
            $ssh->setTimeout(8);
            try {
                $serverKey = $ssh->getServerPublicHostKey();
            } catch (Throwable) {
                throw new SshTargetConnectionException('ssh_handshake_failed');
            }
            if (! is_string($serverKey) || ! $pin->matches($serverKey)) {
                throw new SshTargetConnectionException('host_key_mismatch');
            }

            try {
                if ($authMethod === 'password' && $passphrase === null) {
                    $authenticated = $ssh->login($endpoint->username, $secret);
                } elseif ($authMethod === 'private_key') {
                    $privateKey = PublicKeyLoader::loadPrivateKey($secret, $passphrase);
                    $authenticated = $ssh->login($endpoint->username, $privateKey);
                } else {
                    throw new SshTargetConnectionException('credential_invalid');
                }
            } catch (SshTargetConnectionException $exception) {
                throw $exception;
            } catch (Throwable) {
                throw new SshTargetConnectionException('authentication_failed');
            }

            if (! $authenticated) {
                throw new SshTargetConnectionException('authentication_failed');
            }

            $ssh->disconnect();

            return $peerIp;
        } finally {
            // phpseclib may already close the supplied stream in disconnect().
            if (get_resource_type($socket) === 'stream') {
                fclose($socket);
            }
        }
    }
}
