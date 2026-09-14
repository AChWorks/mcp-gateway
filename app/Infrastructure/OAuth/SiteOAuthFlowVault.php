<?php

namespace App\Infrastructure\OAuth;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteOAuthFlow;
use Illuminate\Support\Facades\Crypt;
use RuntimeException;

final class SiteOAuthFlowVault
{
    public function seal(
        Site $site,
        string $stateHash,
        string $clientId,
        string $redirectUri,
        string $resourceUrl,
        string $issuerUrl,
        string $tokenUrl,
        string $revocationUrl,
        string $codeVerifier,
        int $expiresAt,
    ): string {
        return Crypt::encryptString(json_encode([
            'v' => 1,
            'site_record_id' => (string) $site->getKey(),
            'state_hash' => $stateHash,
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'resource_url' => $resourceUrl,
            'issuer_url' => $issuerUrl,
            'token_url' => $tokenUrl,
            'revocation_url' => $revocationUrl,
            'code_verifier' => $codeVerifier,
            'expires_at' => $expiresAt,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public function open(SiteOAuthFlow $flow): SiteOAuthFlowContext
    {
        $payload = json_decode(Crypt::decryptString($flow->encrypted_context), true, 32, JSON_THROW_ON_ERROR);
        if (! is_array($payload)) {
            throw new RuntimeException('OAuth flow payload is invalid.');
        }

        if (
            ! hash_equals((string) $flow->site_record_id, (string) ($payload['site_record_id'] ?? ''))
            || ! hash_equals($flow->state_hash, (string) ($payload['state_hash'] ?? ''))
            || ! is_numeric($payload['expires_at'] ?? null)
            || (int) $payload['expires_at'] !== $flow->expires_at->getTimestamp()
        ) {
            throw new RuntimeException('OAuth flow payload binding is invalid.');
        }

        $required = ['client_id', 'redirect_uri', 'resource_url', 'issuer_url', 'token_url', 'revocation_url', 'code_verifier'];
        foreach ($required as $key) {
            if (! is_string($payload[$key] ?? null) || $payload[$key] === '') {
                throw new RuntimeException('OAuth flow payload is incomplete.');
            }
        }

        return new SiteOAuthFlowContext(
            (string) $payload['site_record_id'],
            $payload['client_id'],
            $payload['redirect_uri'],
            $payload['resource_url'],
            $payload['issuer_url'],
            $payload['token_url'],
            $payload['revocation_url'],
            $payload['code_verifier'],
        );
    }
}
