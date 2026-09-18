<?php

namespace App\Infrastructure\OAuth;

use RuntimeException;

final class OAuthEncryptionKey
{
    public function league(): string
    {
        return hash_hmac('sha256', 'mcp-gateway:league-oauth:v1', $this->applicationKey());
    }

    public function refreshRecoveryLookup(): string
    {
        return hash_hmac('sha256', 'mcp-gateway:oauth-refresh-recovery:v1', $this->applicationKey());
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
