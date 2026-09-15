<?php

namespace App\Application\Mcp;

use App\Application\Sites\SiteConnectionException;
use App\Domain\Sites\Site;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpClient;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpException;
use Illuminate\Support\Str;

final class PendingGatewayToolHandlers
{
    private const SITE_LIST_LIMIT = 100;

    public function __construct(private readonly WpAiBridgeMcpClient $bridge) {}

    /** @return array<string, mixed> */
    public function sitesList(): array
    {
        $correlationId = (string) Str::uuid();
        $sites = Site::query()
            ->orderBy('site_id')
            ->limit(self::SITE_LIST_LIMIT + 1)
            ->get();
        $truncated = $sites->count() > self::SITE_LIST_LIMIT;

        return [
            'ok' => true,
            'correlation_id' => $correlationId,
            'sites' => $sites
                ->take(self::SITE_LIST_LIMIT)
                ->map(static fn (Site $site): array => [
                    'site_id' => $site->site_id,
                    'display_name' => $site->display_name,
                    'connector_type' => $site->connector_type,
                    'connection_state' => $site->connection_state->value,
                ])
                ->values()
                ->all(),
            'truncated' => $truncated,
        ];
    }

    /** @return array<string, mixed> */
    public function siteContext(string $site_id): array
    {
        $correlationId = (string) Str::uuid();
        $site = $this->findSite($site_id);
        if (! $site instanceof Site) {
            return $this->error($correlationId, 'site_not_found', 'The requested site_id is not configured.');
        }

        return [
            'ok' => true,
            'correlation_id' => $correlationId,
            'site' => [
                'site_id' => $site->site_id,
                'display_name' => $site->display_name,
                'connector_type' => $site->connector_type,
                'base_url' => $site->base_url,
                'mcp_resource_url' => $site->mcp_resource_url,
                'connection_state' => $site->connection_state->value,
                'last_error_code' => $site->last_error_code,
                'connected_at' => $site->connected_at?->toIso8601String(),
            ],
        ];
    }

    /** @return array<string, mixed> */
    public function siteAbilitiesRead(
        string $site_id,
        ?string $ability = null,
        int $page = 1,
        int $per_page = 25,
        ?string $namespace = null,
        ?string $search = null,
    ): array {
        $correlationId = (string) Str::uuid();
        $site = $this->findSite($site_id);
        if (! $site instanceof Site) {
            return $this->error($correlationId, 'site_not_found', 'The requested site_id is not configured.');
        }

        $ability = $this->nullableTrim($ability);
        $namespace = $this->nullableTrim($namespace);
        $search = $this->nullableTrim($search);

        if ($page < 1 || $per_page < 1 || $per_page > 100) {
            return $this->error($correlationId, 'invalid_input', 'page must be at least 1 and per_page must be between 1 and 100.');
        }
        if ($this->tooLong($ability, 255) || $this->tooLong($namespace, 255) || $this->tooLong($search, 255)) {
            return $this->error($correlationId, 'invalid_input', 'Ability catalog filters exceed the supported length.');
        }
        if ($ability !== null && ($namespace !== null || $search !== null || $page !== 1 || $per_page !== 25)) {
            return $this->error($correlationId, 'invalid_input', 'Exact ability inspection cannot be combined with list pagination or filters.');
        }

        try {
            $catalog = $this->bridge->readAbilities(
                $site,
                $correlationId,
                $ability,
                $page,
                $per_page,
                $namespace,
                $search,
            );
        } catch (SiteConnectionException $exception) {
            return $this->connectionError($correlationId, $exception);
        } catch (WpAiBridgeMcpException $exception) {
            return $this->error($correlationId, $exception->reason, $exception->getMessage());
        }

        return [
            'ok' => true,
            'correlation_id' => $correlationId,
            'site_id' => $site->site_id,
            'catalog' => $catalog,
        ];
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array<string, mixed>
     */
    public function siteAbilityExecute(string $site_id, string $ability, array $input): array
    {
        $correlationId = (string) Str::uuid();
        $site = $this->findSite($site_id);
        if (! $site instanceof Site) {
            return $this->error($correlationId, 'site_not_found', 'The requested site_id is not configured.');
        }

        $ability = trim($ability);
        if ($ability === '' || mb_strlen($ability) > 255) {
            return $this->error($correlationId, 'invalid_input', 'ability must be a non-empty string of at most 255 characters.');
        }

        try {
            $result = $this->bridge->executeAbility($site, $ability, $input, $correlationId);
        } catch (SiteConnectionException $exception) {
            return $this->connectionError($correlationId, $exception);
        } catch (WpAiBridgeMcpException $exception) {
            return $this->error($correlationId, $exception->reason, $exception->getMessage());
        }

        return [
            'ok' => true,
            'correlation_id' => $correlationId,
            'site_id' => $site->site_id,
            'ability' => $ability,
            'result' => $result,
        ];
    }

    private function findSite(string $siteId): ?Site
    {
        $siteId = trim($siteId);
        if ($siteId === '' || mb_strlen($siteId) > 128) {
            return null;
        }

        return Site::query()->where('site_id', $siteId)->first();
    }

    private function nullableTrim(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }

    private function tooLong(?string $value, int $max): bool
    {
        return $value !== null && mb_strlen($value) > $max;
    }

    /** @return array<string, mixed> */
    private function connectionError(string $correlationId, SiteConnectionException $exception): array
    {
        $message = match ($exception->reason) {
            'missing_credential' => 'The selected site is not connected.',
            'refresh_failed' => 'The selected site authorization must be reconnected.',
            'revocation_pending' => 'The selected site is completing credential revocation.',
            'target_reassignment_pending' => 'The selected site is completing target reassignment.',
            default => 'The selected site connection is not usable for this request.',
        };

        return $this->error($correlationId, $exception->reason, $message);
    }

    /** @return array<string, mixed> */
    private function error(string $correlationId, string $code, string $message): array
    {
        return [
            'ok' => false,
            'correlation_id' => $correlationId,
            'error' => [
                'code' => $code,
                'message' => $message,
            ],
        ];
    }
}
