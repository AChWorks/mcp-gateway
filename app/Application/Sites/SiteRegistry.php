<?php

namespace App\Application\Sites;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscovery;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeDiscovery;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use Illuminate\Database\UniqueConstraintViolationException;
use InvalidArgumentException;

final class SiteRegistry
{
    public function __construct(
        private readonly WpAiBridgeDiscovery $discovery,
        private readonly OutboundTargetPolicy $targets,
        private readonly SiteConnectionService $connections,
    ) {
    }

    public function create(string $siteId, string $displayName, string $baseUrl): Site
    {
        $siteId = $this->validateSiteId($siteId);
        $displayName = $this->validateDisplayName($displayName);
        $discovery = $this->discover($baseUrl);

        try {
            return Site::query()->create([
                ...$this->attributes($siteId, $displayName, $discovery),
                'connection_state' => SiteConnectionState::Disconnected,
            ]);
        } catch (UniqueConstraintViolationException $exception) {
            throw new InvalidArgumentException('The site identifier or canonical target is already registered.');
        }
    }

    public function update(Site $site, string $displayName, string $baseUrl): Site
    {
        $displayName = $this->validateDisplayName($displayName);
        $canonicalBase = $this->canonicalBase($baseUrl);
        $targetChanged = ! hash_equals($site->base_url, $canonicalBase);
        $discovery = $this->discover($canonicalBase);

        if ($targetChanged && $site->credential()->exists()) {
            $this->connections->disconnect($site);
        }
        if ($targetChanged) {
            $site->oauthFlows()->delete();
        }

        $site->forceFill($this->attributes($site->site_id, $displayName, $discovery))->save();

        if ($targetChanged) {
            $site->forceFill([
                'connection_state' => SiteConnectionState::Disconnected,
                'connected_at' => null,
            ])->save();
        }

        return $site->refresh();
    }

    public function test(Site $site): BridgeDiscovery
    {
        try {
            $discovery = $this->discovery->discover($site->base_url);
        } catch (BridgeDiscoveryException $exception) {
            $site->forceFill([
                'last_error_code' => $exception->reason,
                'last_tested_at' => now(),
            ])->save();
            throw new SiteConnectionException($exception->reason, $exception->getMessage());
        }

        $site->forceFill([
            'mcp_resource_url' => $discovery->resourceUrl,
            'oauth_issuer_url' => $discovery->issuerUrl,
            'oauth_authorization_url' => $discovery->authorizationUrl,
            'oauth_token_url' => $discovery->tokenUrl,
            'oauth_revocation_url' => $discovery->revocationUrl,
            'last_error_code' => null,
            'last_tested_at' => now(),
        ])->save();

        return $discovery;
    }

    public function remove(Site $site): void
    {
        if ($site->credential()->exists()) {
            $this->connections->disconnect($site);
        }
        $site->oauthFlows()->delete();
        $site->delete();
    }

    private function discover(string $baseUrl): BridgeDiscovery
    {
        try {
            return $this->discovery->discover($baseUrl);
        } catch (BridgeDiscoveryException $exception) {
            throw new SiteConnectionException($exception->reason, $exception->getMessage());
        }
    }

    private function canonicalBase(string $baseUrl): string
    {
        try {
            return $this->targets->canonicalBaseUrl($baseUrl);
        } catch (UnsafeOutboundTarget $exception) {
            throw new SiteConnectionException('unsafe_target', 'The site base URL is not a safe public HTTPS target.');
        }
    }

    /** @return array<string, mixed> */
    private function attributes(string $siteId, string $displayName, BridgeDiscovery $discovery): array
    {
        return [
            'site_id' => $siteId,
            'display_name' => $displayName,
            'base_url' => $discovery->baseUrl,
            'base_url_hash' => hash('sha256', $discovery->baseUrl),
            'connector_type' => (string) config('bridge.connector_type', 'wp_ai_bridge'),
            'mcp_resource_url' => $discovery->resourceUrl,
            'oauth_issuer_url' => $discovery->issuerUrl,
            'oauth_authorization_url' => $discovery->authorizationUrl,
            'oauth_token_url' => $discovery->tokenUrl,
            'oauth_revocation_url' => $discovery->revocationUrl,
            'last_error_code' => null,
            'last_tested_at' => now(),
        ];
    }

    private function validateSiteId(string $siteId): string
    {
        $siteId = strtolower(trim($siteId));
        if (strlen($siteId) > 64 || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/', $siteId) !== 1) {
            throw new InvalidArgumentException('Site ID must be a stable lowercase slug containing only letters, digits, and hyphens.');
        }

        return $siteId;
    }

    private function validateDisplayName(string $displayName): string
    {
        $displayName = trim($displayName);
        if ($displayName === '' || mb_strlen($displayName) > 160) {
            throw new InvalidArgumentException('Site display name is required and must be at most 160 characters.');
        }

        return $displayName;
    }
}
