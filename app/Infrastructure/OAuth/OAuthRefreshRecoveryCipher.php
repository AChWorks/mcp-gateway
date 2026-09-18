<?php

namespace App\Infrastructure\OAuth;

use League\OAuth2\Server\CryptTrait;

final class OAuthRefreshRecoveryCipher
{
    use CryptTrait {
        decrypt as private decryptPayload;
        encrypt as private encryptPayload;
    }

    public function __construct(OAuthEncryptionKey $keys)
    {
        $this->setEncryptionKey($keys->refreshRecoveryCipher());
    }

    public function seal(string $plaintext): string
    {
        return $this->encryptPayload($plaintext);
    }

    public function open(string $ciphertext): string
    {
        return $this->decryptPayload($ciphertext);
    }
}
