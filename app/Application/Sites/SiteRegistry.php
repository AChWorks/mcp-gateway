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
        private readonly SiteLifecycleLock $lifecycle,
        private readonly SiteTargetOwnershipLock $targetOwnership,
    ) {}

    public function create(string $siteId, string $displayName, string $baseUrl): Site
    {
        $siteId = $this->validateSiteId($siteId);
        $displayName = $this->validateDisplayName($displayName);
        $discovery = $this->discover($baseUrl);
        $targetHash = hash('sha256', $discovery->baseUrl);

        return $this->targetOwnership->runForHash($targetHash, function () use ($siteId, $displayName, $discovery): Site {
            try {
                return Site::query()->create([
                    ...$this->attributes($siteId, $displayName, $discovery),
                    'connection_state' => SiteConnectionState::Disconnected,
                ]);
            } catch (UniqueConstraintViolationException $exception) {
                throw new InvalidArgumentException('The site identifier or canonical target is already registered.');
            }
        });
    }

    public function update(Site $site, string $displayName, string $baseUrl): Site
    {
        $displayName = $this->validateDisplayName($displayName);
        $canonicalBase = $this->canonicalBase($baseUrl);
        $discovery = $this->discover($canonicalBase);
        $targetHash = hash('sha256', $discovery->baseUrl);

        return $this->targetOwnership->runForHash($targetHash, function () use ($site, $displayName, $discovery, $targetHash): Site {
            return $this->lifecycle->run($site, function (Site $lockedSite) use ($displayName, $discovery, $targetHash): Site {
                $targetChanged = ! hash_equals($lockedSite->base_url, $discovery->baseUrl);

                if ($targetChanged) {
                    $conflict = Site::query()
                        ->where('base_url_hash', $targetHash)
                        ->where($lockedSite->getKeyName(), '!=', $lockedSite->getKey())
                        ->exists();
                    if ($conflict) {
                        throw new InvalidArgumentException('The canonical target is already registered to another site.');
                    }
                }

                if ($targetChanged && $lockedSite->credential()->exists()) {
                    $this->connections->disconnect($lockedSite);
                    $lockedSite->refresh();
                }
                if ($targetChanged) {
                    $lockedSite->oauthFlows()->delete();
                }

                $lockedSite->forceFill($this->attributes($lockedSite->site_id, $displayName, $discovery))->save();

                if ($targetChanged) {
                    $lockedSite->forceFill([
                        'connection_state' => SiteConnectionState::Disconnected,
                        'connected_at' => null,
                    ])->save();
                }

                return $lockedSite->refresh();
            });
        });
    }

    public function test(Site $site): BridgeDiscovery
    {
        return $this->lifecycle->run($site, function (Site $lockedSite): BridgeDiscovery {
            try {
                $discovery = $this->discovery->discover($lockedSite->base_url);
            } catch (BridgeDiscoveryException $exception) {
                $lockedSite->forceFill([
                    'last_error_code' => $exception->reason,
                    'last_tested_at' => now(),
                ])->save();
                throw new SiteConnectionException($exception->reason, $exception->getMessage());
            }

            $lockedSite->forceFill([
                'mcp_resource_url' => $discovery->resourceUrl,
                'oauth_issuer_url' => $discovery->issuerUrl,
                'oauth_authorization_url' => $discovery->authorizationUrl,
                'oauth_token_url' => $discovery->tokenUrl,
                'oauth_revocation_url' => $discovery->revocationUrl,
                'last_error_code' => null,
                'last_tested_at' => now(),
            ])->save();

            return $discovery;
        });
    }

    public function remove(Site $site): void
    {
        $this->lifecycle->run($site, function (Site $lockedSite): void {
            if ($lockedSite->credential()->exists()) {
                $this->connections->disconnect($lockedSite);
                $lockedSite->refresh();
            }
            $lockedSite->oauthFlows()->delete();
            $lockedSite->delete();
        });
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
