<?php

namespace App\Infrastructure\OAuth;

use League\OAuth2\Server\CryptTrait;

final class RefreshTokenInspector
{
    use CryptTrait;

    public function __construct(OAuthEncryptionKey $keys)
    {
        $this->setEncryptionKey($keys->league());
    }

    /** @return array<string, mixed>|null */
    public function inspect(string $token): ?array
    {
        try {
            $decoded = json_decode($this->decrypt($token), true, flags: JSON_THROW_ON_ERROR);

            return is_array($decoded) ? $decoded : null;
        } catch (\Throwable) {
            return null;
        }
    }
}
