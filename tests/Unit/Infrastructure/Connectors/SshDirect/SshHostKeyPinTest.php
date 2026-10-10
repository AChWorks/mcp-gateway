<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class SshHostKeyPinTest extends TestCase
{
    public function test_canonical_key_and_fingerprint_match_wire_key_not_comment_or_whitespace(): void
    {
        $key = $this->ed25519(str_repeat("\x42", 32));
        $pin = SshHostKeyPin::fromLine('  '.$key.'  ');
        self::assertSame($key, $pin->canonicalLine());
        self::assertSame('SHA256:'.rtrim(base64_encode(hash('sha256', base64_decode(explode(' ', $key)[1], true), true)), '='), $pin->fingerprint());
        self::assertTrue($pin->matches($key));
        self::assertFalse($pin->matches($this->ed25519(str_repeat("\x43", 32))));
        self::assertFalse($pin->matches('ssh-rsa '.explode(' ', $key)[1]));
        self::assertFalse($pin->matches('garbage'));
    }

    public function test_unknown_key_type_wrong_ssh_wire_type_or_trailing_comment_is_denied(): void
    {
        $good = $this->ed25519(str_repeat("\x42", 32));
        $bad = [
            'ssh-dss '.explode(' ', $good)[1],
            $good.' comment',
            "ssh-ed25519\n".$good,
            'ssh-ed25519 !!!',
            'ssh-rsa '.explode(' ', $good)[1],
            str_repeat('A', 4097),
            '',
        ];
        foreach ($bad as $input) {
            try {
                SshHostKeyPin::fromLine($input);
                self::fail('Untrusted key input accepted');
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_verified_rsa_sha2_negotiation_matches_same_pinned_ssh_rsa_wire_key(): void
    {
        $blob = pack('N', 7).'ssh-rsa'.pack('N', 1)."\x03".pack('N', 33).str_repeat("\x11", 33);
        $key = 'ssh-rsa '.base64_encode($blob);
        $pin = SshHostKeyPin::fromLine($key);

        self::assertSame($key, $pin->canonicalLine());
        self::assertTrue($pin->matches('rsa-sha2-256 '.base64_encode($blob)));
        self::assertTrue($pin->matches('rsa-sha2-512 '.base64_encode($blob)));
        self::assertTrue($pin->matches($key));
        self::assertFalse($pin->matches('rsa-sha2-512 '.base64_encode($blob.'x')));
        self::assertFalse($pin->matches('rsa-sha2-512 !!!'));

        // A signature negotiation label is not a valid stored public key.
        try {
            SshHostKeyPin::fromLine('rsa-sha2-512 '.base64_encode($blob));
            self::fail('Accepted signature negotiation as a pinned host-key type.');
        } catch (InvalidArgumentException) {
            self::assertTrue(true);
        }
    }

    private function ed25519(string $raw): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', strlen($raw)).$raw);
    }
}
