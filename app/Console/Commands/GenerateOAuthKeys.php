<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use RuntimeException;

final class GenerateOAuthKeys extends Command
{
    protected $signature = 'gateway:oauth-keygen {--force : Replace existing OAuth signing keys}';

    protected $description = 'Generate the Gateway OAuth RSA signing keypair outside the public web root.';

    public function handle(): int
    {
        $privatePath = (string) config('oauth.keys.private');
        $publicPath = (string) config('oauth.keys.public');

        try {
            $this->assertSafePath($privatePath);
            $this->assertSafePath($publicPath);

            if (! $this->option('force') && (is_file($privatePath) || is_file($publicPath))) {
                $this->error('OAuth signing keys already exist. Use --force only for deliberate key rotation.');

                return self::FAILURE;
            }

            $key = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);
            if ($key === false) {
                throw new RuntimeException('OpenSSL could not create the RSA keypair.');
            }

            $privateKey = '';
            if (! openssl_pkey_export($key, $privateKey)) {
                throw new RuntimeException('OpenSSL could not export the private key.');
            }

            $details = openssl_pkey_get_details($key);
            if (! is_array($details) || ! is_string($details['key'] ?? null)) {
                throw new RuntimeException('OpenSSL could not export the public key.');
            }

            $this->atomicWrite($privatePath, $privateKey, 0600);
            $this->atomicWrite($publicPath, $details['key'], 0600);

            $this->info('OAuth signing keypair generated.');
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
        if ($path === '' || ! str_starts_with($path, DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('OAuth key paths must resolve to absolute paths.');
        }

        $publicPath = rtrim(public_path(), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        if (str_starts_with($path, $publicPath)) {
            throw new RuntimeException('OAuth signing keys must not be stored under the public web root.');
        }
    }

    private function atomicWrite(string $path, string $contents, int $mode): void
    {
        $directory = dirname($path);
        if (! is_dir($directory) && ! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create OAuth key directory.');
        }
        chmod($directory, 0700);

        $temporary = tempnam($directory, '.oauth-key-');
        if ($temporary === false) {
            throw new RuntimeException('Could not create a temporary OAuth key file.');
        }

        try {
            if (file_put_contents($temporary, $contents, LOCK_EX) === false) {
                throw new RuntimeException('Could not write OAuth key material.');
            }
            chmod($temporary, $mode);
            if (! rename($temporary, $path)) {
                throw new RuntimeException('Could not install OAuth key material atomically.');
            }
            chmod($path, $mode);
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }
}
