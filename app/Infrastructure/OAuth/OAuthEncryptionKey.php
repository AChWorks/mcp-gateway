<?php

namespace App\Infrastructure\OAuth;

use RuntimeException;

final class OAuthEncryptionKey
{
    public function league(): string
    {
        return $this->derive('mcp-gateway:league-oauth:v1');
    }

    public function refreshRecoveryLookup(): string
    {
        return $this->derive('mcp-gateway:oauth-refresh-recovery:lookup:v1');
    }

    public function refreshRecoveryCipher(): string
    {
        return $this->derive('mcp-gateway:oauth-refresh-recovery:cipher:v1');
    }

    private function derive(string $purpose): string
    {
        return hash_hmac('sha256', $purpose, $this->applicationKey());
    }

    private function applicationKey(): string
    {
        $applicationKey = (string) config('app.key');
        if ($applicationKey === '') {
            throw new RuntimeException('APP_KEY is required for OAuth cryptographic keys.');
        }

        return $applicationKey;
    }
}
