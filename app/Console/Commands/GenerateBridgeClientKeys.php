<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use RuntimeException;

final class GenerateBridgeClientKeys extends Command
{
    protected $signature = 'gateway:bridge-client-keygen {--force : Replace existing Bridge OAuth client signing keys}';

    protected $description = 'Generate the Gateway private_key_jwt RSA keypair used to authenticate to WP AI Bridge.';

    public function handle(): int
    {
        $privatePath = (string) config('bridge.keys.private');
        $publicPath = (string) config('bridge.keys.public');

        try {
            $this->assertSafePath($privatePath);
            $this->assertSafePath($publicPath);
            $this->assertDistinctPaths($privatePath, $publicPath);

            if (! $this->option('force') && (is_file($privatePath) || is_file($publicPath))) {
                $this->error('Bridge client signing keys already exist. Use --force only for deliberate key rotation.');

                return self::FAILURE;
            }

            $key = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);
            if ($key === false) {
                throw new RuntimeException('OpenSSL could not create the Bridge client RSA keypair.');
            }

            $privateKey = '';
            if (! openssl_pkey_export($key, $privateKey)) {
                throw new RuntimeException('OpenSSL could not export the Bridge client private key.');
            }

            $details = openssl_pkey_get_details($key);
            if (! is_array($details) || ! is_string($details['key'] ?? null)) {
                throw new RuntimeException('OpenSSL could not export the Bridge client public key.');
            }

            $this->atomicWrite($privatePath, $privateKey, 0600);
            $this->atomicWrite($publicPath, $details['key'], 0600);

            $this->info('Bridge OAuth client signing keypair generated.');
            $this->line('Private: '.$privatePath);
            $this->line('Public:  '.$publicPath);

            return self::SUCCESS;
        } catch (\Throwable $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }
    }

    private function assertSafePath(string $path): void
    {
        if ($path === '' || str_contains($path, "\0") || ! str_starts_with($path, DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Bridge client key paths must resolve to absolute paths.');
        }
        if (preg_match('~(?:^|[\\\\/])\.\.(?:[\\\\/]|$)~', $path) === 1) {
            throw new RuntimeException('Bridge client key paths must not contain parent-directory traversal.');
        }

        $publicPath = rtrim(public_path(), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        if (str_starts_with($path, $publicPath)) {
            throw new RuntimeException('Bridge client signing keys must not be stored under the public web root.');
        }
    }

    private function assertDistinctPaths(string $privatePath, string $publicPath): void
    {
        $reserved = array_filter([
            (string) config('oauth.keys.private'),
            (string) config('oauth.keys.public'),
        ]);

        if ($privatePath === $publicPath || in_array($privatePath, $reserved, true) || in_array($publicPath, $reserved, true)) {
            throw new RuntimeException('Bridge client signing keys must use paths distinct from each other and from Gateway OAuth signing keys.');
        }
    }

    private function atomicWrite(string $path, string $contents, int $mode): void
    {
        $directory = dirname($path);
        if (! is_dir($directory) && ! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create Bridge client key directory.');
        }
        $this->assertResolvedDirectoryOutsidePublicRoot($directory);
        chmod($directory, 0700);

        $temporary = tempnam($directory, '.bridge-client-key-');
        if ($temporary === false) {
            throw new RuntimeException('Could not create a temporary Bridge client key file.');
        }

        try {
            if (file_put_contents($temporary, $contents, LOCK_EX) === false) {
                throw new RuntimeException('Could not write Bridge client key material.');
            }
            chmod($temporary, $mode);
            if (! rename($temporary, $path)) {
                throw new RuntimeException('Could not install Bridge client key material atomically.');
            }
            chmod($path, $mode);
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }

    private function assertResolvedDirectoryOutsidePublicRoot(string $directory): void
    {
        $resolvedDirectory = realpath($directory);
        $resolvedPublic = realpath(public_path());
        if ($resolvedDirectory === false || $resolvedPublic === false) {
            throw new RuntimeException('Bridge client key path could not be resolved safely.');
        }

        $publicPrefix = rtrim($resolvedPublic, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        if ($resolvedDirectory === $resolvedPublic || str_starts_with($resolvedDirectory.DIRECTORY_SEPARATOR, $publicPrefix)) {
            throw new RuntimeException('Bridge client signing keys must not resolve under the public web root.');
        }
    }
}
