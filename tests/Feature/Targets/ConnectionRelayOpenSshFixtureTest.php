<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\Relay\LocalSocks5Route;
use App\Infrastructure\Connectors\Relay\Socks5NumericDialer;
use App\Infrastructure\Connectors\SshDirect\SshAlgorithmPolicy;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\TransferException;
use phpseclib4\Net\SFTP;
use RuntimeException;
use Tests\TestCase;

/**
 * Exact-candidate real OpenSSH -D -> restricted sshd -> actual target sshd.
 * Runs only on an explicitly started, disposable loopback SSH fixture.
 * No PHP mock for SOCKS or for cryptographic end-host authentication.
 */
final class ConnectionRelayOpenSshFixtureTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (getenv('SSH_FIXTURE_ENABLED') !== '1'
            || getenv('SSH_FIXTURE_RELAY_SOCKS_PORT') === false) {
            $this->markTestSkipped('Real isolated OpenSSH -D fixture not provisioned.');
        }
    }

    public function test_restricted_ipv4_relay_verifies_actual_target_ssh_and_sftp_without_a_remote_peer_ip_claim(): void
    {
        $transport = $this->transport('127.0.0.1');
        $peer = $transport->authenticate(
            $this->endpoint(), $this->pin('SSH_FIXTURE_ED25519_HOST_PUB'),
            'password', $this->env('SSH_FIXTURE_PASSWORD'), null,
            relay: $this->relay(),
        );
        self::assertSame('', $peer, 'SOCKS peer is localhost; do not claim the remote Target IP.');

        $result = $transport->withAuthenticatedSftpSession(
            $this->endpoint(), $this->pin('SSH_FIXTURE_ED25519_HOST_PUB'),
            'password', $this->env('SSH_FIXTURE_PASSWORD'), null,
            static function (SFTP $sftp, string $peer): array {
                return [$peer, $sftp->pwd()];
            },
            relay: $this->relay(),
        );
        self::assertSame('', $result[0]);
        self::assertIsString($result[1]);
        self::assertNotSame('', $result[1]);
    }

    public function test_restricted_ipv6_numeric_connect_verifies_same_pinned_end_host(): void
    {
        $peer = $this->transport('::1')->authenticate(
            $this->endpoint(), $this->pin('SSH_FIXTURE_ED25519_HOST_PUB'),
            'password', $this->env('SSH_FIXTURE_PASSWORD'), null,
            relay: $this->relay(),
        );
        self::assertSame('', $peer);
    }

    public function test_wrong_real_end_host_key_is_rejected_before_password_authentication(): void
    {
        $log = $this->env('SSH_FIXTURE_LOG_MODERN');
        $offset = filesize($log);
        try {
            $this->transport('127.0.0.1')->authenticate(
                $this->endpoint(), $this->pin('SSH_FIXTURE_WRONG_ED25519_HOST_PUB'),
                'password', $this->env('SSH_FIXTURE_PASSWORD'), null,
                relay: $this->relay(),
            );
            self::fail('Untrusted end-host SSH key was accepted via SOCKS.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('host_key_mismatch', $exception->reason);
        }
        usleep(100000);
        $freshLog = (string) substr((string) file_get_contents($log), (int) $offset);
        self::assertDoesNotMatchRegularExpression('/(?:Accepted|Failed) (?:password|publickey)/i', $freshLog);
    }

    public function test_real_guzzle_https_through_openssh_preserves_sni_and_certificate_verification(): void
    {
        if (! extension_loaded('curl')) {
            $this->markTestSkipped('Real libcurl/Guzzle required.');
        }
        $host = $this->env('SSH_FIXTURE_RELAY_TLS_HOST');
        $port = (int) $this->env('SSH_FIXTURE_RELAY_TLS_PORT');
        $trusted = $this->env('SSH_FIXTURE_RELAY_TLS_CERT');
        $client = new Client([
            'proxy' => 'socks5://127.0.0.1:'.$this->relay()->loopbackPort,
            'curl' => [CURLOPT_RESOLVE => [$host.':'.$port.':127.0.0.1']],
            'verify' => $trusted, 'allow_redirects' => false,
            'timeout' => 8, 'connect_timeout' => 4,
        ]);
        $response = $client->request('GET', 'https://'.$host.':'.$port.'/');
        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('SSL', (string) $response->getBody());

        $wrong = new Client([
            'proxy' => 'socks5://127.0.0.1:'.$this->relay()->loopbackPort,
            'curl' => [CURLOPT_RESOLVE => ['wrong.fixture.test:'.$port.':127.0.0.1']],
            'verify' => $trusted, 'allow_redirects' => false,
            'timeout' => 8, 'connect_timeout' => 4,
        ]);
        try {
            $wrong->request('GET', 'https://wrong.fixture.test:'.$port.'/');
            self::fail('Guzzle TLS verified the wrong original hostname through the SOCKS Relay.');
        } catch (TransferException $exception) {
            self::assertNotSame('', $exception->getMessage());
        }
    }

    public function test_remote_open_policy_denies_unapproved_ports_without_fallback(): void
    {
        $dialer = new Socks5NumericDialer;
        foreach (['127.0.0.1', '::1'] as $ip) {
            try {
                $socket = $dialer->connect(
                    $this->relay()->loopbackPort, $ip, 46232, 5,
                );
                if (is_resource($socket)) {
                    fclose($socket);
                }
                self::fail('Restricted forwarding accepted an unapproved destination.');
            } catch (RuntimeException $exception) {
                // OpenSSH can either send a SOCKS5 refusal or close the
                // forwarded channel before completing its response. Both
                // outcomes must fail closed; neither permits Direct fallback.
                self::assertContains($exception->getMessage(), [
                    'relay_connect_denied', 'relay_handshake_failed',
                ]);
            }
        }
    }

    public function test_missing_socks_listener_does_not_fallback_to_direct_target(): void
    {
        try {
            $this->transport('127.0.0.1')->authenticate(
                $this->endpoint(), $this->pin('SSH_FIXTURE_ED25519_HOST_PUB'),
                'password', $this->env('SSH_FIXTURE_PASSWORD'), null,
                relay: LocalSocks5Route::fromApprovedBinding('missing-fixture', 46252),
            );
            self::fail('A missing Relay listener silently contacted the Direct SSH endpoint.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('relay_unavailable', $exception->reason);
        }
    }

    private function transport(string $ip): SshVerifiedTransport
    {
        $policy = new class($ip) implements SshDialAddressPolicy
        {
            public function __construct(private string $ip) {}

            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return [$this->ip]; // Isolated local fixture, not an SSRF policy override in production.
            }
        };

        return new SshVerifiedTransport($policy, new SshAlgorithmPolicy);
    }

    private function endpoint(): SshRegisteredEndpoint
    {
        return SshRegisteredEndpoint::fromInput(
            'fixture.example.test', (int) $this->env('SSH_FIXTURE_PORT_MODERN'),
            $this->env('SSH_FIXTURE_USER'),
        );
    }

    private function pin(string $name): SshHostKeyPin
    {
        return SshHostKeyPin::fromLine(trim((string) file_get_contents($this->env($name))));
    }

    private function relay(): LocalSocks5Route
    {
        return LocalSocks5Route::fromApprovedBinding('fixture-relay', (int) $this->env('SSH_FIXTURE_RELAY_SOCKS_PORT'));
    }

    private function env(string $name): string
    {
        $value = getenv($name);
        self::assertIsString($value);
        self::assertNotSame('', $value);

        return $value;
    }
}
