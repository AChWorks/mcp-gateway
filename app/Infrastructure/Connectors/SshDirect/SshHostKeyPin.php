<?php

namespace App\Infrastructure\Connectors\SshDirect;

use InvalidArgumentException;

/**
 * An independently authenticated out-of-band SSH host public key. Never TOFU.
 * Compare the SSH wire key blob rather than the negotiated RSA signature name.
 */
final readonly class SshHostKeyPin
{
    private const TYPES = [
        'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    ];

    private function __construct(public string $type, public string $blob) {}

    public static function fromLine(string $line): self
    {
        if (strlen($line) > 4096 || str_contains($line, "\n") || str_contains($line, "\r")) {
            throw new InvalidArgumentException('A single trusted SSH server public key is required.');
        }
        $fields = preg_split('/[ \t]+/', trim($line));
        if (! is_array($fields) || count($fields) !== 2 || ! in_array($fields[0], self::TYPES, true)) {
            throw new InvalidArgumentException('SSH host key must be a supported OpenSSH public key without a comment.');
        }
        $blob = base64_decode($fields[1], true);
        if (! is_string($blob) || strlen($blob) < 16 || strlen($blob) > 3072
            || rtrim(base64_encode($blob), '=') !== rtrim($fields[1], '=')) {
            throw new InvalidArgumentException('SSH host key has invalid base64 encoding.');
        }
        $length = unpack('Nlength', substr($blob, 0, 4));
        $length = $length['length'] ?? 0;
        if ($length !== strlen($fields[0]) || substr($blob, 4, $length) !== $fields[0]) {
            throw new InvalidArgumentException('SSH public-key algorithm does not match its wire format.');
        }

        return new self($fields[0], $blob);
    }

    public function canonicalLine(): string
    {
        return $this->type.' '.base64_encode($this->blob);
    }

    public function fingerprint(): string
    {
        return 'SHA256:'.rtrim(base64_encode(hash('sha256', $this->blob, true)), '=');
    }

    public function matches(string $serverKey): bool
    {
        // phpseclib returns the negotiated RSA *signature algorithm*
        // (rsa-sha2-256/512), while the OpenSSH public host-key blob still
        // begins with "ssh-rsa". Normalize only this verified RSA alias;
        // stored pins must remain canonical OpenSSH public-key lines.
        if ($this->type === 'ssh-rsa'
            && (str_starts_with($serverKey, 'rsa-sha2-256 ')
                || str_starts_with($serverKey, 'rsa-sha2-512 '))) {
            $serverKey = 'ssh-rsa '.substr($serverKey, strpos($serverKey, ' ') + 1);
        }

        try {
            $presented = self::fromLine($serverKey);
        } catch (InvalidArgumentException) {
            return false;
        }

        return hash_equals($this->blob, $presented->blob);
    }
}
