<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use Throwable;

/**
 * Connector-owned encrypted custody, never the generic Target model.
 * The immutable local Target record and stable external slug are both AAD-like
 * authenticated fields within Laravel's authenticated encrypted envelope.
 */
final class WpAiBridgeTargetVault
{
    /** @param array{client_id:string,redirect_uri:string,resource_url:string,issuer_url:string,token_url:string,revocation_url:string,code_verifier:string} $context */
    public function sealFlow(Target $target, string $stateHash, array $context, int $expiresAt): string
    {
        return $this->seal([
            'v' => 1,
            'target_record_id' => (string) $target->getKey(),
            'target_id' => $target->target_id,
            'connector_type' => 'wp_ai_bridge',
            'state_hash' => $stateHash,
            'expires_at' => $expiresAt,
            ...$context,
        ]);
    }

    /**
     * @param  object  $flow  Database row from wp_ai_bridge_oauth_flows
     * @return array{client_id:string,redirect_uri:string,resource_url:string,issuer_url:string,token_url:string,revocation_url:string,code_verifier:string}
     */
    public function openFlow(Target $target, object $flow): array
    {
        $payload = $this->unseal((string) $flow->encrypted_context);
        if (! $this->matchesTarget($target, $payload)
            || ! hash_equals((string) $flow->state_hash, (string) ($payload['state_hash'] ?? ''))
            || (int) ($payload['expires_at'] ?? 0) !== (int) (new DateTimeImmutable((string) $flow->expires_at))->getTimestamp()) {
            throw new RuntimeException('OAuth flow Target/state binding is invalid.');
        }

        $result = [];
        foreach (['client_id', 'redirect_uri', 'resource_url', 'issuer_url', 'token_url', 'revocation_url', 'code_verifier'] as $key) {
            $value = $payload[$key] ?? null;
            if (! is_string($value) || $value === '' || strlen($value) > 2048) {
                throw new RuntimeException('OAuth flow context is incomplete.');
            }
            $result[$key] = $value;
        }

        return $result;
    }

    /** @param list<string> $scopes */
    public function sealCredential(
        Target $target,
        string $clientId,
        string $resourceUrl,
        string $accessToken,
        string $refreshToken,
        ?DateTimeInterface $expiresAt,
        array $scopes,
    ): string {
        if ($accessToken === '' || $refreshToken === '' || strlen($accessToken) > 8192 || strlen($refreshToken) > 8192) {
            throw new RuntimeException('OAuth credential material is invalid.');
        }

        return $this->seal([
            'v' => 1,
            'target_record_id' => (string) $target->getKey(),
            'target_id' => $target->target_id,
            'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth',
            'client_id' => $clientId,
            'resource_url' => $resourceUrl,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'access_expires_at' => $expiresAt?->format(DATE_ATOM),
            'scopes' => array_values(array_unique($scopes)),
        ]);
    }

    /** @return array{client_id:string,resource_url:string,access_token:string,refresh_token:string,access_expires_at:?DateTimeImmutable,scopes:list<string>} */
    public function openCredential(Target $target, TargetCredential $credential): array
    {
        if ((string) $credential->target_record_id !== (string) $target->getKey()
            || $credential->connector_type !== 'wp_ai_bridge'
            || $credential->purpose !== 'wordpress_oauth') {
            throw new RuntimeException('Credential ownership or purpose is invalid.');
        }

        $metadata = DB::table('wp_ai_bridge_credential_metadata')
            ->where('credential_id', $credential->getKey())->first();
        if ($metadata === null) {
            throw new RuntimeException('WordPress credential metadata is missing.');
        }

        $payload = $this->unseal($credential->encrypted_payload);
        $clientId = (string) $metadata->client_id;
        $resourceUrl = (string) $metadata->resource_url;
        $binding = hash('sha256', (string) $target->getKey()."\0".$target->target_id."\0".$clientId."\0".$resourceUrl);
        if (! $this->matchesTarget($target, $payload)
            || ($payload['purpose'] ?? null) !== 'wordpress_oauth'
            || ! hash_equals($binding, (string) $metadata->binding_hash)
            || ! hash_equals($clientId, (string) ($payload['client_id'] ?? ''))
            || ! hash_equals($resourceUrl, (string) ($payload['resource_url'] ?? ''))) {
            throw new RuntimeException('WordPress credential binding is invalid.');
        }

        $accessToken = $payload['access_token'] ?? null;
        $refreshToken = $payload['refresh_token'] ?? null;
        $scopes = $payload['scopes'] ?? null;
        if (! is_string($accessToken) || $accessToken === '' || strlen($accessToken) > 8192
            || ! is_string($refreshToken) || $refreshToken === '' || strlen($refreshToken) > 8192
            || ! is_array($scopes)) {
            throw new RuntimeException('WordPress credential payload is invalid.');
        }
        $scopeValues = [];
        foreach ($scopes as $scope) {
            if (! is_string($scope) || $scope === '' || strlen($scope) > 128) {
                throw new RuntimeException('WordPress credential scope is invalid.');
            }
            $scopeValues[] = $scope;
        }
        $expiresAt = $payload['access_expires_at'] ?? null;
        if ($expiresAt !== null && (! is_string($expiresAt) || strlen($expiresAt) > 80)) {
            throw new RuntimeException('WordPress credential expiration is invalid.');
        }

        return [
            'client_id' => $clientId,
            'resource_url' => $resourceUrl,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'access_expires_at' => $expiresAt === null ? null : new DateTimeImmutable($expiresAt),
            'scopes' => $scopeValues,
        ];
    }

    /** @param array<string,mixed> $data */
    private function seal(array $data): string
    {
        return Crypt::encryptString(json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /** @return array<string,mixed> */
    private function unseal(string $encrypted): array
    {
        try {
            $data = json_decode(Crypt::decryptString($encrypted), true, 32, JSON_THROW_ON_ERROR);
            if (! is_array($data) || ($data['v'] ?? null) !== 1) {
                throw new RuntimeException('Encrypted WordPress payload version is invalid.');
            }

            return $data;
        } catch (Throwable $exception) {
            throw new RuntimeException('Encrypted WordPress credential/flow cannot be opened safely.', previous: $exception);
        }
    }

    /** @param array<string,mixed> $payload */
    private function matchesTarget(Target $target, array $payload): bool
    {
        return $target->connector_type === 'wp_ai_bridge'
            && hash_equals((string) $target->getKey(), (string) ($payload['target_record_id'] ?? ''))
            && hash_equals($target->target_id, (string) ($payload['target_id'] ?? ''))
            && ($payload['connector_type'] ?? null) === 'wp_ai_bridge';
    }
}
