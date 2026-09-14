<?php

namespace Tests\Unit\Support;

use App\Support\EnvironmentRequirements;
use PHPUnit\Framework\TestCase;

final class EnvironmentRequirementsTest extends TestCase
{
    public function test_current_runtime_meets_required_php_extensions_with_mysql_and_a_valid_key(): void
    {
        $requirements = new EnvironmentRequirements;
        $key = 'base64:'.base64_encode(str_repeat('k', 32));
        $checks = $requirements->checks('mysql', $key, 'AES-256-CBC');

        self::assertNotContains(false, $checks, true);
        self::assertFalse($requirements->checks('sqlite', $key, 'AES-256-CBC')['MySQL is the configured database driver']);
        self::assertFalse($requirements->checks('mysql', null, 'AES-256-CBC')['Valid Laravel encryption key']);
        self::assertFalse($requirements->checks('mysql', 'not-a-valid-key', 'AES-256-CBC')['Valid Laravel encryption key']);
    }

    public function test_deployment_security_checks_require_https_and_secure_sessions_in_production(): void
    {
        $directory = sys_get_temp_dir().'/mcp-gateway-env-'.bin2hex(random_bytes(8));
        $publicRoot = $directory.'/public';
        $keyRoot = $directory.'/private';
        self::assertTrue(mkdir($publicRoot, 0700, true));
        self::assertTrue(mkdir($keyRoot, 0700, true));

        try {
            [$privatePath, $publicPath] = $this->createKeypair($keyRoot);
            $requirements = new EnvironmentRequirements;

            $secure = $requirements->deploymentSecurityChecks(
                environment: 'production',
                applicationUrl: 'https://gateway.example.test',
                oauthPrivateKeyPath: $privatePath,
                oauthPublicKeyPath: $publicPath,
                publicRoot: $publicRoot,
                privateFilesystemServed: false,
                sessionEncrypted: true,
                sessionSecure: true,
            );
            self::assertNotContains(false, $secure, true);

            $insecure = $requirements->deploymentSecurityChecks(
                environment: 'production',
                applicationUrl: 'http://gateway.example.test',
                oauthPrivateKeyPath: $privatePath,
                oauthPublicKeyPath: $publicPath,
                publicRoot: $publicRoot,
                privateFilesystemServed: true,
                sessionEncrypted: false,
                sessionSecure: false,
            );
            self::assertFalse($insecure['Production application URL uses HTTPS']);
            self::assertFalse($requirements->deploymentSecurityChecks(
                environment: 'production',
                applicationUrl: 'https://gateway.example.test/subpath?bad=1',
                oauthPrivateKeyPath: $privatePath,
                oauthPublicKeyPath: $publicPath,
                publicRoot: $publicRoot,
                privateFilesystemServed: false,
                sessionEncrypted: true,
                sessionSecure: true,
            )['Gateway issuer is a canonical origin']);
            self::assertFalse($insecure['Private filesystem is not web-served']);
            self::assertFalse($insecure['Administrator sessions are encrypted']);
            self::assertFalse($insecure['Production session cookie is HTTPS-only']);
        } finally {
            @unlink($keyRoot.'/private.key');
            @unlink($keyRoot.'/public.key');
            @rmdir($keyRoot);
            @rmdir($publicRoot);
            @rmdir($directory);
        }
    }

    /** @return array{0: string, 1: string} */
    private function createKeypair(string $directory): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($key);

        $privateKey = '';
        self::assertTrue(openssl_pkey_export($key, $privateKey));
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsString($details['key'] ?? null);

        $privatePath = $directory.'/private.key';
        $publicPath = $directory.'/public.key';
        self::assertNotFalse(file_put_contents($privatePath, $privateKey));
        self::assertNotFalse(file_put_contents($publicPath, $details['key']));
        chmod($privatePath, 0600);
        chmod($publicPath, 0600);

        return [$privatePath, $publicPath];
    }
}
