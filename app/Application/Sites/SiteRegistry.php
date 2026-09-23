<?php

namespace App\Application\Sites;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Domain\Sites\SiteRevocationIntent;
use App\Domain\Sites\SiteTargetReservation;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscovery;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeDiscovery;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

final class SiteRegistry
{
    public function __construct(
        private readonly WpAiBridgeDiscovery $discovery,
        private readonly OutboundTargetPolicy $targets,
        private readonly SiteConnectionService $connections,
        private readonly SiteLifecycleLock $lifecycle,
    ) {}

    public function create(string $siteId, string $displayName, string $baseUrl): Site
    {
        $siteId = $this->validateSiteId($siteId);
        $displayName = $this->validateDisplayName($displayName);
        $discovery = $this->discover($baseUrl);
        $targetHash = hash('sha256', $discovery->baseUrl);

        try {
            return DB::transaction(function () use ($siteId, $displayName, $discovery, $targetHash): Site {
                $reservation = SiteTargetReservation::query()->create([
                    'target_hash' => $targetHash,
                    'target_url' => $discovery->baseUrl,
                    'owner_site_id' => $siteId,
                    'site_record_id' => null,
                ]);

                if (Site::query()->where('base_url_hash', $targetHash)->lockForUpdate()->first() instanceof Site) {
                    throw new InvalidArgumentException('The canonical target is already registered to another site.');
                }

                $site = Site::query()->create([
                    ...$this->attributes($siteId, $displayName, $discovery),
                    'connection_state' => SiteConnectionState::Disconnected,
                ]);
                $reservation->delete();

                return $site;
            });
        } catch (UniqueConstraintViolationException $exception) {
            if (SiteTargetReservation::query()->whereKey($targetHash)->exists()) {
                throw new SiteConnectionException('target_busy', 'The canonical target is currently reserved by another site operation.');
            }

            throw new InvalidArgumentException('The site identifier or canonical target is already registered.');
        }
    }

    public function update(Site $site, string $displayName, string $baseUrl): Site
    {
        $displayName = $this->validateDisplayName($displayName);
        $canonicalBase = $this->canonicalBase($baseUrl);
        $discovery = $this->discover($canonicalBase);
        $targetHash = hash('sha256', $discovery->baseUrl);

        $targetChanged = $this->lifecycle->run($site, function (Site $lockedSite) use ($displayName, $discovery, $targetHash): bool {
            if ($lockedSite->revocationIntent()->exists()) {
                throw new SiteConnectionException('revocation_pending', 'Complete the pending credential revocation before changing this site.');
            }

            $reservation = $lockedSite->targetReservation()->first();
            $targetChanged = ! hash_equals($lockedSite->base_url, $discovery->baseUrl);

            if (! $targetChanged) {
                if ($reservation instanceof SiteTargetReservation) {
                    throw new SiteConnectionException('target_reassignment_pending', 'Complete the pending target reassignment before changing this site.');
                }

                $lockedSite->forceFill($this->attributes($lockedSite->site_id, $displayName, $discovery))->save();

                return false;
            }

            if ($reservation instanceof SiteTargetReservation) {
                if (! $this->reservationMatches($reservation, $lockedSite, $targetHash, $discovery->baseUrl)) {
                    throw new SiteConnectionException('target_reassignment_pending', 'Complete the existing target reassignment before choosing another target.');
                }
            } else {
                try {
                    $reservation = SiteTargetReservation::query()->create([
                        'target_hash' => $targetHash,
                        'target_url' => $discovery->baseUrl,
                        'owner_site_id' => $lockedSite->site_id,
                        'site_record_id' => (string) $lockedSite->getKey(),
                    ]);
                } catch (UniqueConstraintViolationException $exception) {
                    throw new SiteConnectionException('target_busy', 'The canonical target is currently reserved by another site operation.');
                }

                if ($this->targetOwnedByAnotherSite($lockedSite, $targetHash)) {
                    throw new InvalidArgumentException('The canonical target is already registered to another site.');
                }
            }

            $lockedSite->oauthFlows()->delete();
            $lockedSite->forceFill([
                'connection_state' => SiteConnectionState::Reassigning,
                'last_error_code' => null,
                'connected_at' => null,
            ])->save();

            return true;
        });

        if (! $targetChanged) {
            return $site->refresh();
        }

        $this->connections->disconnect($site->refresh());

        return $this->lifecycle->run($site, function (Site $lockedSite) use ($displayName, $discovery, $targetHash): Site {
            if ($lockedSite->revocationIntent()->exists()) {
                throw new SiteConnectionException('revocation_pending', 'Target reassignment cannot finalize while credential revocation is pending.');
            }

            $reservation = $lockedSite->targetReservation()->first();
            if (! $reservation instanceof SiteTargetReservation || ! $this->reservationMatches($reservation, $lockedSite, $targetHash, $discovery->baseUrl)) {
                throw new SiteConnectionException('target_reassignment_lost', 'The target reassignment reservation is no longer authoritative.');
            }

            if ($this->targetOwnedByAnotherSite($lockedSite, $targetHash)) {
                $reservation->delete();
                $lockedSite->forceFill([
                    'connection_state' => SiteConnectionState::Disconnected,
                    'last_error_code' => 'target_conflict',
                    'connected_at' => null,
                ])->save();
                throw new SiteConnectionException('target_conflict', 'The canonical target became owned by another site.');
            }

            $lockedSite->oauthFlows()->delete();
            $lockedSite->forceFill([
                ...$this->attributes($lockedSite->site_id, $displayName, $discovery),
                'connection_state' => SiteConnectionState::Disconnected,
                'connected_at' => null,
            ])->save();
            $reservation->delete();

            return $lockedSite->refresh();
        });
    }

    public function test(Site $site): BridgeDiscovery
    {
        return $this->lifecycle->run($site, function (Site $lockedSite): BridgeDiscovery {
            if ($lockedSite->revocationIntent()->exists()) {
                throw new SiteConnectionException('revocation_pending', 'Complete the pending credential revocation before testing this site.');
            }
            if ($lockedSite->targetReservation()->exists()) {
                throw new SiteConnectionException('target_reassignment_pending', 'Complete the pending target reassignment before testing this site.');
            }

            try {
                $discovery = $this->discovery->discover($lockedSite->base_url);
            } catch (BridgeDiscoveryException $exception) {
                $checkedAt = now();
                $lockedSite->forceFill([
                    'last_error_code' => $exception->reason,
                    'last_tested_at' => $checkedAt,
                    'last_failure_at' => $checkedAt,
                    'last_failure_code' => $exception->reason,
                ])->save();
                throw new SiteConnectionException($exception->reason, $exception->getMessage());
            }

            $checkedAt = now();
            $lockedSite->forceFill([
                'mcp_resource_url' => $discovery->resourceUrl,
                'oauth_issuer_url' => $discovery->issuerUrl,
                'oauth_authorization_url' => $discovery->authorizationUrl,
                'oauth_token_url' => $discovery->tokenUrl,
                'oauth_revocation_url' => $discovery->revocationUrl,
                'last_error_code' => null,
                'last_tested_at' => $checkedAt,
                'last_success_at' => $checkedAt,
            ])->save();

            return $discovery;
        });
    }

    public function remove(Site $site): void
    {
        $this->connections->revokeForRemoval($site);

        $this->lifecycle->run($site, function (Site $lockedSite): void {
            $intent = $lockedSite->revocationIntent()->first();
            if (! $intent instanceof SiteRevocationIntent || $intent->kind !== SiteRevocationIntent::KIND_REMOVE) {
                throw new SiteConnectionException('revocation_intent_lost', 'The durable site-removal intent is no longer authoritative.');
            }
            if ($lockedSite->credential()->exists()) {
                throw new SiteConnectionException('credential_still_present', 'The site cannot be removed before its remote credential is finalized locally.');
            }

            $lockedSite->oauthFlows()->delete();
            $lockedSite->delete();
        });
    }

    private function targetOwnedByAnotherSite(Site $site, string $targetHash): bool
    {
        return Site::query()
            ->where('base_url_hash', $targetHash)
            ->where($site->getKeyName(), '!=', $site->getKey())
            ->lockForUpdate()
            ->first() instanceof Site;
    }

    private function reservationMatches(SiteTargetReservation $reservation, Site $site, string $targetHash, string $targetUrl): bool
    {
        return hash_equals($reservation->target_hash, $targetHash)
            && hash_equals($reservation->target_url, $targetUrl)
            && hash_equals($reservation->owner_site_id, $site->site_id)
            && hash_equals((string) $reservation->site_record_id, (string) $site->getKey());
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
