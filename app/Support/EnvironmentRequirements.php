<?php

namespace App\Support;

use Illuminate\Encryption\Encrypter;

final class EnvironmentRequirements
{
    /**
     * @return array<string, bool>
     */
    public function checks(string $databaseDriver, ?string $applicationKey, string $cipher): array
    {
        return [
            'PHP >= 8.4.1' => version_compare((string) phpversion(), '8.4.1', '>='),
            'PDO MySQL extension' => extension_loaded('pdo_mysql'),
            'OpenSSL extension' => extension_loaded('openssl'),
            'Sodium extension' => extension_loaded('sodium'),
            'Valid Laravel encryption key' => $this->validEncryptionKey($applicationKey, $cipher),
            'MySQL is the configured database driver' => $databaseDriver === 'mysql',
        ];
    }

    private function validEncryptionKey(?string $key, string $cipher): bool
    {
        if (! is_string($key) || $key === '') {
            return false;
        }

        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);

            if ($decoded === false) {
                return false;
            }

            $key = $decoded;
        }

        return Encrypter::supported($key, $cipher);
    }
}
