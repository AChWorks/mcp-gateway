<?php

namespace App\Infrastructure\OAuth;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteCredential;
use DateTimeImmutable;
use DateTimeInterface;
use Exception;
use Illuminate\Support\Facades\Crypt;
use RuntimeException;

final class SiteCredentialVault
{
    /** @param list<string> $scopes */
    public function seal(
        Site $site,
        string $clientId,
        string $resourceUrl,
        string $accessToken,
        ?string $refreshToken,
        ?DateTimeInterface $accessExpiresAt,
        array $scopes,
    ): string {
        if ($accessToken === '' || strlen($accessToken) > 8192 || ($refreshToken !== null && strlen($refreshToken) > 8192)) {
            throw new RuntimeException('Remote OAuth credential material is invalid.');
        }

        $payload = [
            'v' => 1,
            'site_record_id' => (string) $site->getKey(),
            'site_id' => $site->site_id,
            'client_id' => $clientId,
            'resource_url' => $resourceUrl,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'access_expires_at' => $accessExpiresAt?->format(DATE_ATOM),
            'scopes' => array_values(array_unique($scopes)),
        ];

        return Crypt::encryptString(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public function open(SiteCredential $credential): SiteCredentialSecret
    {
        $site = $credential->site;
        if (! $site instanceof Site) {
            throw new SiteCredentialVaultException('Credential site binding is unavailable.');
        }

        try {
            $payload = json_decode(Crypt::decryptString($credential->encrypted_payload), true, 32, JSON_THROW_ON_ERROR);
            if (! is_array($payload)) {
                throw new SiteCredentialVaultException('Credential payload is invalid.');
            }

            $expectedBinding = self::bindingHash($site, $credential->client_id, $credential->resource_url);
            $validBinding = hash_equals($expectedBinding, $credential->binding_hash)
                && hash_equals((string) $site->getKey(), (string) ($payload['site_record_id'] ?? ''))
                && hash_equals($site->site_id, (string) ($payload['site_id'] ?? ''))
                && hash_equals($credential->client_id, (string) ($payload['client_id'] ?? ''))
                && hash_equals($credential->resource_url, (string) ($payload['resource_url'] ?? ''));
            if (! $validBinding) {
                throw new SiteCredentialVaultException('Credential payload binding is invalid.');
            }

            $accessToken = $payload['access_token'] ?? null;
            $refreshToken = $payload['refresh_token'] ?? null;
            $scopes = $payload['scopes'] ?? null;
            if (! is_string($accessToken) || $accessToken === '' || ($refreshToken !== null && ! is_string($refreshToken)) || ! is_array($scopes)) {
                throw new SiteCredentialVaultException('Credential payload is incomplete.');
            }

            $scopeValues = [];
            foreach ($scopes as $scope) {
                if (is_string($scope) && $scope !== '') {
                    $scopeValues[] = $scope;
                }
            }

            $expiresAt = null;
            if (is_string($payload['access_expires_at'] ?? null) && $payload['access_expires_at'] !== '') {
                $expiresAt = new DateTimeImmutable($payload['access_expires_at']);
            }

            return new SiteCredentialSecret($accessToken, $refreshToken, $expiresAt, $scopeValues);
        } catch (SiteCredentialVaultException $exception) {
            throw $exception;
        } catch (Exception $exception) {
            throw new SiteCredentialVaultException('Credential payload could not be opened safely.', previous: $exception);
        }
    }

    public static function bindingHash(Site $site, string $clientId, string $resourceUrl): string
    {
        return hash('sha256', (string) $site->getKey()."\0".$site->site_id."\0".$clientId."\0".$resourceUrl);
    }
}
