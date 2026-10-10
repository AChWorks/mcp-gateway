<?php

namespace App\Infrastructure\Connectors\SshDirect;

/**
 * Gateway-owned SSH cryptographic policy.
 *
 * phpseclib intentionally supports legacy interoperability algorithms. Direct SSH
 * credentials must never inherit that full compatibility set implicitly.
 */
final class SshAlgorithmPolicy
{
    /** @var list<string> */
    private const KEX = [
        'curve25519-sha256',
        'curve25519-sha256@libssh.org',
        'ecdh-sha2-nistp256',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp521',
        'diffie-hellman-group14-sha256',
        'diffie-hellman-group16-sha512',
        'diffie-hellman-group18-sha512',
        'diffie-hellman-group-exchange-sha256',
    ];

    /** @var list<string> */
    private const CIPHERS = [
        'aes256-gcm@openssh.com',
        'aes128-gcm@openssh.com',
        'chacha20-poly1305@openssh.com',
        'aes256-ctr',
        'aes192-ctr',
        'aes128-ctr',
    ];

    /** @var list<string> */
    private const MACS = [
        'hmac-sha2-512-etm@openssh.com',
        'hmac-sha2-256-etm@openssh.com',
        'hmac-sha2-512',
        'hmac-sha2-256',
    ];

    /** @var list<string> */
    private const RSA_HOST_SIGNATURES = [
        'rsa-sha2-512',
        'rsa-sha2-256',
    ];

    /**
     * Keep the pinned host-key family first. RSA client authentication needs
     * phpseclib's hostkey preference to include RSA-SHA2 as well, so append
     * those algorithms only after the pinned family. If the pinned key is not
     * available the later exact blob comparison still fails before login.
     *
     * @return array{
     *   kex:list<string>,
     *   hostkey:list<string>,
     *   client_to_server:array{crypt:list<string>,mac:list<string>},
     *   server_to_client:array{crypt:list<string>,mac:list<string>}
     * }
     */
    public function preferredAlgorithms(SshHostKeyPin $pin, bool $rsaClientAuthentication): array
    {
        $hostKey = $pin->type === 'ssh-rsa'
            ? self::RSA_HOST_SIGNATURES
            : [$pin->type];

        if ($rsaClientAuthentication && $pin->type !== 'ssh-rsa') {
            $hostKey = [...$hostKey, ...self::RSA_HOST_SIGNATURES];
        }

        return [
            'kex' => self::KEX,
            'hostkey' => array_values(array_unique($hostKey)),
            'client_to_server' => [
                'crypt' => self::CIPHERS,
                'mac' => self::MACS,
            ],
            'server_to_client' => [
                'crypt' => self::CIPHERS,
                'mac' => self::MACS,
            ],
        ];
    }
}
