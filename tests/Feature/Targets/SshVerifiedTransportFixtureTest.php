<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshAlgorithmPolicy;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use Tests\TestCase;

final class SshVerifiedTransportFixtureTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (getenv('SSH_FIXTURE_ENABLED') !== '1') {
            $this->markTestSkipped('Disposable OpenSSH fixture is not configured.');
        }
    }

    public function test_password_login_with_rsa_pin_uses_rsa_sha2_and_reports_actual_numeric_peer(): void
    {
        $peer = $this->transport()->authenticate(
            $this->endpoint('SSH_FIXTURE_PORT_MODERN'),
            $this->pin('SSH_FIXTURE_RSA_HOST_PUB'),
            'password',
            $this->env('SSH_FIXTURE_PASSWORD'),
            null,
        );

        self::assertSame('127.0.0.1', $peer);
    }

    public function test_encrypted_rsa_private_key_login_succeeds_with_pinned_ed25519_host_key(): void
    {
        $peer = $this->transport()->authenticate(
            $this->endpoint('SSH_FIXTURE_PORT_MODERN'),
            $this->pin('SSH_FIXTURE_ED25519_HOST_PUB'),
            'private_key',
            (string) file_get_contents($this->env('SSH_FIXTURE_RSA_LOGIN_KEY')),
            $this->env('SSH_FIXTURE_KEY_PASSPHRASE'),
        );

        self::assertSame('127.0.0.1', $peer);
    }

    public function test_wrong_password_fails_safely_without_secret_in_exception_or_server_log(): void
    {
        $log = $this->env('SSH_FIXTURE_LOG_MODERN');
        $offset = $this->logOffset($log);
        $secret = 'wrong-password-fixture-value';

        $exception = $this->expectConnectionFailure('authentication_failed', fn () => $this->transport()->authenticate(
            $this->endpoint('SSH_FIXTURE_PORT_MODERN'),
            $this->pin('SSH_FIXTURE_ED25519_HOST_PUB'),
            'password',
            $secret,
            null,
        ));

        self::assertStringNotContainsString($secret, $exception->getMessage());
        $tail = $this->logTail($log, $offset);
        self::assertMatchesRegularExpression('/Failed password/i', $tail);
        self::assertStringNotContainsString($secret, $tail);
    }

    public function test_wrong_host_key_is_rejected_before_any_authentication_event(): void
    {
        $log = $this->env('SSH_FIXTURE_LOG_MODERN');
        $offset = $this->logOffset($log);

        $this->expectConnectionFailure('host_key_mismatch', fn () => $this->transport()->authenticate(
            $this->endpoint('SSH_FIXTURE_PORT_MODERN'),
            $this->pin('SSH_FIXTURE_WRONG_ED25519_HOST_PUB'),
            'password',
            $this->env('SSH_FIXTURE_PASSWORD'),
            null,
        ));

        $this->assertNoAuthenticationEvent($this->logTail($log, $offset));
    }

    public function test_legacy_only_kex_cipher_mac_and_rsa_sha1_hosts_fail_before_authentication(): void
    {
        foreach ([
            ['SSH_FIXTURE_PORT_LEGACY_RSA', 'SSH_FIXTURE_RSA_HOST_PUB', 'SSH_FIXTURE_LOG_LEGACY_RSA'],
            ['SSH_FIXTURE_PORT_WEAK_KEX', 'SSH_FIXTURE_ED25519_HOST_PUB', 'SSH_FIXTURE_LOG_WEAK_KEX'],
            ['SSH_FIXTURE_PORT_WEAK_CIPHER', 'SSH_FIXTURE_ED25519_HOST_PUB', 'SSH_FIXTURE_LOG_WEAK_CIPHER'],
            ['SSH_FIXTURE_PORT_WEAK_MAC', 'SSH_FIXTURE_ED25519_HOST_PUB', 'SSH_FIXTURE_LOG_WEAK_MAC'],
        ] as [$port, $pin, $logName]) {
            $log = $this->env($logName);
            $offset = $this->logOffset($log);

            $this->expectConnectionFailure('ssh_handshake_failed', fn () => $this->transport()->authenticate(
                $this->endpoint($port),
                $this->pin($pin),
                'password',
                $this->env('SSH_FIXTURE_PASSWORD'),
                null,
            ));

            $this->assertNoAuthenticationEvent($this->logTail($log, $offset));
        }
    }

    private function transport(): SshVerifiedTransport
    {
        $policy = new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint): array
            {
                return ['127.0.0.1'];
            }
        };

        return new SshVerifiedTransport($policy, new SshAlgorithmPolicy);
    }

    private function endpoint(string $portName): SshRegisteredEndpoint
    {
        return SshRegisteredEndpoint::fromInput(
            'fixture.example.test',
            (int) $this->env($portName),
            $this->env('SSH_FIXTURE_USER'),
        );
    }

    private function pin(string $pathName): SshHostKeyPin
    {
        return SshHostKeyPin::fromLine(trim((string) file_get_contents($this->env($pathName))));
    }

    private function expectConnectionFailure(string $reason, callable $operation): SshTargetConnectionException
    {
        try {
            $operation();
            self::fail('Expected SSH fixture failure: '.$reason);
        } catch (SshTargetConnectionException $exception) {
            self::assertSame($reason, $exception->reason);

            return $exception;
        }
    }

    private function assertNoAuthenticationEvent(string $log): void
    {
        self::assertDoesNotMatchRegularExpression(
            '/(?:Accepted|Failed) (?:password|publickey)|authentication failure/i',
            $log,
        );
    }

    private function logOffset(string $path): int
    {
        clearstatcache(true, $path);
        $size = filesize($path);

        return is_int($size) ? $size : 0;
    }

    private function logTail(string $path, int $offset): string
    {
        usleep(100000);
        $contents = (string) file_get_contents($path);

        return (string) substr($contents, $offset);
    }

    private function env(string $name): string
    {
        $value = getenv($name);
        self::assertIsString($value, 'Missing SSH fixture environment variable '.$name);
        self::assertNotSame('', $value, 'Empty SSH fixture environment variable '.$name);

        return $value;
    }
}
