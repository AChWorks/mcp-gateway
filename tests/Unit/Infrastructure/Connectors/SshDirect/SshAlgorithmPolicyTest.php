<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Infrastructure\Connectors\SshDirect\SshAlgorithmPolicy;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use PHPUnit\Framework\TestCase;

final class SshAlgorithmPolicyTest extends TestCase
{
    public function test_policy_never_advertises_known_legacy_kex_cipher_mac_or_host_signatures(): void
    {
        $preferred = (new SshAlgorithmPolicy)->preferredAlgorithms($this->pin('ssh-rsa'), false);

        self::assertSame([], array_values(array_intersect([
            'diffie-hellman-group1-sha1',
            'diffie-hellman-group14-sha1',
            'diffie-hellman-group-exchange-sha1',
        ], $preferred['kex'])));

        foreach (['client_to_server', 'server_to_client'] as $direction) {
            self::assertSame([], array_values(array_intersect([
                'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
                '3des-cbc', 'blowfish-cbc',
            ], $preferred[$direction]['crypt'])));
            self::assertSame([], array_values(array_intersect([
                'hmac-sha1', 'hmac-sha1-96', 'hmac-sha1-etm@openssh.com',
                'hmac-md5', 'hmac-md5-96',
            ], $preferred[$direction]['mac'])));
        }

        self::assertNotContains('ssh-rsa', $preferred['hostkey']);
        self::assertNotContains('ssh-dss', $preferred['hostkey']);
    }

    public function test_rsa_pin_requires_rsa_sha2_host_signatures(): void
    {
        self::assertSame(
            ['rsa-sha2-512', 'rsa-sha2-256'],
            (new SshAlgorithmPolicy)->preferredAlgorithms($this->pin('ssh-rsa'), false)['hostkey'],
        );
    }

    public function test_pinned_host_family_stays_first_when_rsa_client_auth_needs_rsa_sha2(): void
    {
        self::assertSame(
            ['ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256'],
            (new SshAlgorithmPolicy)->preferredAlgorithms($this->pin('ssh-ed25519'), true)['hostkey'],
        );
        self::assertSame(
            ['ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256'],
            (new SshAlgorithmPolicy)->preferredAlgorithms($this->pin('ecdsa-sha2-nistp256'), true)['hostkey'],
        );
    }

    public function test_non_rsa_client_auth_does_not_expand_the_pinned_family(): void
    {
        self::assertSame(
            ['ssh-ed25519'],
            (new SshAlgorithmPolicy)->preferredAlgorithms($this->pin('ssh-ed25519'), false)['hostkey'],
        );
    }

    private function pin(string $type): SshHostKeyPin
    {
        $blob = pack('N', strlen($type)).$type.str_repeat("\x42", 48);

        return SshHostKeyPin::fromLine($type.' '.base64_encode($blob));
    }
}
