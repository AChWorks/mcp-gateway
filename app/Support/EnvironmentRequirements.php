<?php

namespace App\Support;

use Illuminate\Encryption\Encrypter;

final class EnvironmentRequirements
{
    /** @return array<string, bool> */
    public function checks(string $databaseDriver, ?string $applicationKey, string $cipher): array
    {
        return [
            'PHP >= 8.4.1' => version_compare((string) phpversion(), '8.4.1', '>='),
            'PDO MariaDB/MySQL extension (pdo_mysql)' => extension_loaded('pdo_mysql'),
            'cURL extension with DNS pinning support' => extension_loaded('curl') && defined('CURLOPT_RESOLVE'),
            'OpenSSL extension' => extension_loaded('openssl'),
            'Sodium extension' => extension_loaded('sodium'),
            'Valid Laravel encryption key' => $this->validEncryptionKey($applicationKey, $cipher),
            'MariaDB or MySQL is the configured database driver' => in_array($databaseDriver, ['mariadb', 'mysql'], true),
        ];
    }

    /** @return array<string, bool> */
    public function deploymentSecurityChecks(
        string $environment,
        string $applicationUrl,
        string $oauthPrivateKeyPath,
        string $oauthPublicKeyPath,
        string $bridgePrivateKeyPath,
        string $bridgePublicKeyPath,
        string $publicRoot,
        bool $privateFilesystemServed,
        bool $sessionEncrypted,
        bool $sessionSecure,
    ): array {
        $production = $environment === 'production';

        return [
            'Gateway issuer is a canonical origin' => $this->isCanonicalOrigin($applicationUrl),
            'Production application URL uses HTTPS' => ! $production || $this->usesHttps($applicationUrl),
            'OAuth signing keypair is valid and matched' => $this->validKeypair($oauthPrivateKeyPath, $oauthPublicKeyPath),
            'OAuth signing keys are outside the public web root' => $this->outsidePublicRoot($oauthPrivateKeyPath, $publicRoot)
                && $this->outsidePublicRoot($oauthPublicKeyPath, $publicRoot),
            'OAuth signing key file permissions are restricted' => $this->safeKeyPermissions($oauthPrivateKeyPath)
                && $this->safeKeyPermissions($oauthPublicKeyPath),
            'Bridge client signing keypair is valid and matched' => $this->validKeypair($bridgePrivateKeyPath, $bridgePublicKeyPath),
            'Bridge client signing keypair is distinct from Gateway OAuth signing keys' => $this->distinctKeypairs($oauthPrivateKeyPath, $bridgePrivateKeyPath),
            'Bridge client signing keys are outside the public web root' => $this->outsidePublicRoot($bridgePrivateKeyPath, $publicRoot)
                && $this->outsidePublicRoot($bridgePublicKeyPath, $publicRoot),
            'Bridge client signing key file permissions are restricted' => $this->safeKeyPermissions($bridgePrivateKeyPath)
                && $this->safeKeyPermissions($bridgePublicKeyPath),
            'Private filesystem is not web-served' => ! $privateFilesystemServed,
            'Administrator sessions are encrypted' => $sessionEncrypted,
            'Production session cookie is HTTPS-only' => ! $production || $sessionSecure,
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

    private function isCanonicalOrigin(string $url): bool
    {
        $parts = parse_url($url);
        if (! is_array($parts)
            || ! in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            || ! is_string($parts['host'] ?? null)
            || (string) $parts['host'] === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            return false;
        }

        return ! isset($parts['path']) || $parts['path'] === '' || $parts['path'] === '/';
    }

    private function usesHttps(string $url): bool
    {
        return strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'https';
    }

    private function validKeypair(string $privatePath, string $publicPath): bool
    {
        if (! is_readable($privatePath) || ! is_readable($publicPath)) {
            return false;
        }

        $privateContents = file_get_contents($privatePath);
        $publicContents = file_get_contents($publicPath);
        if ($privateContents === false || $publicContents === false) {
            return false;
        }

        $private = openssl_pkey_get_private($privateContents);
        $public = openssl_pkey_get_public($publicContents);
        if ($private === false || $public === false) {
            return false;
        }

        $privateDetails = openssl_pkey_get_details($private);
        $publicDetails = openssl_pkey_get_details($public);

        return is_array($privateDetails)
            && is_array($publicDetails)
            && isset($privateDetails['key'], $publicDetails['key'])
            && hash_equals(trim((string) $privateDetails['key']), trim((string) $publicDetails['key']));
    }

    private function distinctKeypairs(string $firstPrivatePath, string $secondPrivatePath): bool
    {
        if (! is_readable($firstPrivatePath) || ! is_readable($secondPrivatePath)) {
            return false;
        }

        $firstContents = file_get_contents($firstPrivatePath);
        $secondContents = file_get_contents($secondPrivatePath);
        if ($firstContents === false || $secondContents === false) {
            return false;
        }

        $first = openssl_pkey_get_private($firstContents);
        $second = openssl_pkey_get_private($secondContents);
        if ($first === false || $second === false) {
            return false;
        }

        $firstDetails = openssl_pkey_get_details($first);
        $secondDetails = openssl_pkey_get_details($second);

        return is_array($firstDetails)
            && is_array($secondDetails)
            && is_string($firstDetails['key'] ?? null)
            && is_string($secondDetails['key'] ?? null)
            && ! hash_equals(trim($firstDetails['key']), trim($secondDetails['key']));
    }

    private function outsidePublicRoot(string $path, string $publicRoot): bool
    {
        $lexicalPrefix = rtrim($publicRoot, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        if (str_starts_with($path, $lexicalPrefix)) {
            return false;
        }

        $resolvedPath = realpath($path);
        $resolvedPublicRoot = realpath($publicRoot);

        if ($resolvedPath === false || $resolvedPublicRoot === false) {
            return false;
        }

        $resolvedPrefix = rtrim($resolvedPublicRoot, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

        return ! str_starts_with($resolvedPath, $resolvedPrefix);
    }

    private function safeKeyPermissions(string $path): bool
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return is_readable($path);
        }

        $permissions = fileperms($path);
        if ($permissions === false) {
            return false;
        }

        return ($permissions & 0o077) === 0;
    }
}
