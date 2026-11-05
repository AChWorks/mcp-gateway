<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\Relay\LocalSocks5Route;
use App\Infrastructure\Connectors\Relay\Socks5NumericDialer;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use Closure;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Net\SFTP;
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
        ?SshReverseRoute $route = null, ?LocalSocks5Route $relay = null,
    ): string {
        return $this->withAuthenticatedSession(
            $endpoint, $pin, $authMethod, $secret, $passphrase,
            static fn (SSH2 $ssh, string $peerIp): string => $peerIp,
            $route, $relay,
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
        Closure $operation, ?SshReverseRoute $route = null, ?LocalSocks5Route $relay = null,
    ): mixed {
        return $this->withAuthenticatedOperation(
            $endpoint, $pin, $authMethod, $secret, $passphrase, $operation, false,
            null, $route, $relay,
        );
    }

    /** @param Closure(SFTP,string):mixed $operation */
    public function withAuthenticatedSftpSession(
        SshRegisteredEndpoint $endpoint, SshHostKeyPin $pin,
        string $authMethod, string $secret, ?string $passphrase,
        Closure $operation, ?int $deadlineNs = null, ?SshReverseRoute $route = null,
        ?LocalSocks5Route $relay = null,
    ): mixed {
        return $this->withAuthenticatedOperation(
            $endpoint, $pin, $authMethod, $secret, $passphrase,
            static function (SSH2 $ssh, string $peerIp) use ($operation): mixed {
                if (! $ssh instanceof SFTP) {
                    throw new SshTargetConnectionException('sftp_unavailable');
                }

                return $operation($ssh, $peerIp);
            },
            true, $deadlineNs, $route, $relay,
        );
    }

    /** @param Closure(SSH2,string):mixed $operation */
    private function withAuthenticatedOperation(
        SshRegisteredEndpoint $endpoint, SshHostKeyPin $pin,
        string $authMethod, string $secret, ?string $passphrase,
        Closure $operation, bool $requireSftp, ?int $deadlineNs = null,
        ?SshReverseRoute $route = null, ?LocalSocks5Route $relay = null,
    ): mixed {
        if ($route !== null && $relay !== null) {
            throw new SshTargetConnectionException('egress_denied');
        }

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

        $this->assertDeadline($deadlineNs);
        if ($route !== null) {
            // Only an independently owner/operator-approved route may dial
            // loopback. Never accept arbitrary local addresses or fallback
            // to the remote endpoint if the forward disappears.
            $approved = ['127.0.0.1'];
            $dialPort = $route->listenerPort;
        } else {
            try {
                $approved = $this->policy->approvedDialAddresses($endpoint, $deadlineNs);
            } catch (SshTargetConnectionException $exception) {
                throw $exception;
            } catch (UnsafeOutboundTarget $exception) {
                $this->assertDeadline($deadlineNs);

                throw new SshTargetConnectionException('egress_denied', $exception->diagnostics());
            } catch (Throwable) {
                $this->assertDeadline($deadlineNs);

                throw new SshTargetConnectionException('egress_denied');
            }
            $dialPort = $endpoint->port;
        }

        $this->assertDeadline($deadlineNs);

        // One approved numeric connection attempt, no fallback after key
        // mismatch or loss of a specific reverse listener.
        $ip = $approved[0];
        if (@inet_pton($ip) === false) {
            throw new SshTargetConnectionException('egress_denied');
        }
        $address = 'tcp://'.(str_contains($ip, ':') ? '['.$ip.']' : $ip).':'.$dialPort;
        $errno = 0;
        $error = '';
        if ($relay !== null) {
            try {
                $socket = (new Socks5NumericDialer)->connect(
                    $relay->loopbackPort, $ip, $endpoint->port,
                    $this->boundedTimeout(5, $deadlineNs),
                );
            } catch (\RuntimeException $exception) {
                $this->assertDeadline($deadlineNs);
                $code = $exception->getMessage();
                throw new SshTargetConnectionException('relay_unavailable', [
                    'failure_origin' => 'gateway_transport',
                    'failure_stage' => 'relay_socks_connect',
                    'source_error_code' => in_array($code, [
                        'relay_endpoint_invalid', 'relay_unavailable', 'relay_peer_mismatch',
                        'relay_handshake_failed', 'relay_connect_denied',
                    ], true) ? $code : 'relay_handshake_failed',
                    'pre_dispatch' => true,
                ]);
            } catch (Throwable) {
                $this->assertDeadline($deadlineNs);
                throw new SshTargetConnectionException('relay_unavailable', [
                    'failure_origin' => 'gateway_transport',
                    'failure_stage' => 'relay_socks_connect',
                    'pre_dispatch' => true,
                ]);
            }
        } else {
            $socket = @stream_socket_client(
                $address, $errno, $error, $this->boundedTimeout(5, $deadlineNs), STREAM_CLIENT_CONNECT,
            );
            if (! is_resource($socket)) {
                throw new SshTargetConnectionException($route === null ? 'tcp_unreachable' : 'reverse_listener_unavailable');
            }
        }

        $ssh = null;
        try {
            $this->assertDeadline($deadlineNs);
            $peer = @stream_socket_get_name($socket, true);
            $peerHost = is_string($peer) ? parse_url('tcp://'.$peer, PHP_URL_HOST) : false;
            $peerPort = is_string($peer) ? parse_url('tcp://'.$peer, PHP_URL_PORT) : false;
            $peerIp = is_string($peerHost) ? trim($peerHost, '[]') : '';
            // The OS-visible TCP peer for SOCKS is local, not the end host.
            // The CONNECT reply is NOT an independently observed remote peer.
            // Validate the local tunnel endpoint and suppress remote peer
            // claims; the end-host's cryptographic pin is checked below.
            $expectedIp = $relay === null ? $ip : '127.0.0.1';
            $expectedPort = $relay === null ? $dialPort : $relay->loopbackPort;
            if ($peerPort !== $expectedPort || @inet_pton($peerIp) === false
                || ! hash_equals((string) inet_pton($expectedIp), (string) inet_pton($peerIp))) {
                throw new SshTargetConnectionException('tcp_peer_mismatch');
            }
            if ($relay !== null) {
                $peerIp = '';
            }

            try {
                $ssh = $requireSftp
                    ? new SshSubsystemOnlySftp($socket, $dialPort, $this->boundedTimeout(8, $deadlineNs))
                    : new SSH2($socket, $dialPort, 8);
                $ssh->setTimeout($this->boundedTimeout(8, $deadlineNs));
                if ($ssh instanceof SshSubsystemOnlySftp && $deadlineNs !== null) {
                    $ssh->startOperationDeadline($deadlineNs);
                }
                $ssh->setPreferredAlgorithms(
                    $this->algorithms->preferredAlgorithms($pin, $rsaClientAuthentication),
                );
                $serverKey = $ssh->getServerPublicHostKey();
            } catch (SshTargetConnectionException $exception) {
                throw $exception;
            } catch (Throwable) {
                throw new SshTargetConnectionException('ssh_handshake_failed');
            }
            $this->assertDeadline($deadlineNs);
            if (! is_string($serverKey) || ! $pin->matches($serverKey)) {
                throw new SshTargetConnectionException('host_key_mismatch');
            }

            try {
                $authenticated = $authMethod === 'password'
                    ? $ssh->login($endpoint->username, $secret)
                    : $ssh->login($endpoint->username, $privateKey);
            } catch (SshTargetConnectionException $exception) {
                throw $exception;
            } catch (Throwable) {
                throw new SshTargetConnectionException('authentication_failed');
            }

            if (! $authenticated) {
                throw new SshTargetConnectionException('authentication_failed');
            }

            $this->assertDeadline($deadlineNs);
            if ($requireSftp && $deadlineNs !== null) {
                // phpseclib's SSH identification uses stream_select(), which
                // may not work on filtered sockets. Attach AFTER verified login.
                // This bounds all subsequent raw SFTP channel reads/writes.
                SshSocketDeadline::attach($socket, $deadlineNs);
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

    private function assertDeadline(?int $deadlineNs): void
    {
        if ($deadlineNs !== null && hrtime(true) >= $deadlineNs) {
            throw new SshTargetConnectionException('transfer_timed_out');
        }
    }

    private function boundedTimeout(int $maximumSeconds, ?int $deadlineNs): int
    {
        if ($deadlineNs === null) {
            return $maximumSeconds;
        }

        $this->assertDeadline($deadlineNs);

        return max(1, min($maximumSeconds, (int) ceil(($deadlineNs - hrtime(true)) / 1_000_000_000)));
    }
}
