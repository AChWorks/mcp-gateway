<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Sites\SiteConnectionException;
use App\Application\Sites\SiteHealth;
use App\Application\Sites\SiteInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpClient;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpException;
use App\Models\User;
use App\Support\CorrelationId;
use DateTimeInterface;
use InvalidArgumentException;
use LogicException;

final class PendingGatewayToolHandlers
{
    public function __construct(
        private readonly WpAiBridgeMcpClient $bridge,
        private readonly ActivityRecorder $activity,
        private readonly SiteInventory $inventory,
        private readonly AccessControl $access,
        private readonly SiteHealth $health,
    ) {}

    /** @return array<string, mixed> */
    public function sitesList(
        User $user,
        ?string $cursor = null,
        int $limit = SiteInventory::MCP_DEFAULT_LIMIT,
        ?string $search = null,
        ?string $connection_state = null,
    ): array {
        $correlationId = CorrelationId::current();

        if (! $this->access->allows($user, GatewayPermission::SitesView)) {
            return $this->forbidden($correlationId, 'sites-list');
        }

        try {
            $page = $this->inventory->mcpPage($user, $cursor, $limit, $search, $connection_state);
        } catch (InvalidArgumentException $exception) {
            return $this->recordedError(
                $correlationId,
                'sites-list',
                null,
                'invalid_input',
                $exception->getMessage(),
            );
        }

        $serializedSites = [];

        foreach ($page['items'] as $site) {
            $serializedSites[] = [
                'site_id' => $site->site_id,
                'display_name' => $site->display_name,
                'connector_type' => $site->connector_type,
                'connection_state' => $this->connectionState($site),
            ];
        }

        $this->activity->record($correlationId, 'sites-list', 'success');

        return [
            'ok' => true,
            'correlation_id' => $correlationId,
            'sites' => $serializedSites,
            'truncated' => $page['has_more'],
            'next_cursor' => $page['next_cursor'],
        ];
    }

    /** @return array<string, mixed> */
    public function siteContext(User $user, string $site_id): array
    {
        $correlationId = CorrelationId::current();
        $site = $this->findSite($user, $site_id, GatewayPermission::SitesView);
        if (! $site instanceof Site) {
            return $this->siteNotFound($correlationId, 'site-context');
        }

        $this->activity->record($correlationId, 'site-context', 'success', $site->site_id);

        return [
            'ok' => true,
            'correlation_id' => $correlationId,
            'site' => [
                'site_id' => $site->site_id,
                'display_name' => $site->display_name,
                'connector_type' => $site->connector_type,
                'base_url' => $site->base_url,
                'mcp_resource_url' => $site->mcp_resource_url,
                'connection_state' => $this->connectionState($site),
                'last_error_code' => $site->last_error_code,
                'connected_at' => $this->connectedAt($site),
            ],
        ];
    }

    /** @return array<string, mixed> */
    public function siteAbilitiesRead(
        User $user,
        string $site_id,
        ?string $ability = null,
        int $page = 1,
        int $per_page = 10,
        ?string $namespace = null,
        ?string $search = null,
    ): array {
        $correlationId = CorrelationId::current();
        $site = $this->findSite($user, $site_id, GatewayPermission::AbilitiesInspect);
        if (! $site instanceof Site) {
            return $this->siteNotFound($correlationId, 'site-abilities-read');
        }

        $ability = $this->nullableTrim($ability);
        $namespace = $this->nullableTrim($namespace);
        $search = $this->nullableTrim($search);

        if ($page < 1 || $per_page < 1 || $per_page > 100) {
            return $this->recordedError($correlationId, 'site-abilities-read', $site->site_id, 'invalid_input', 'page must be at least 1 and per_page must be between 1 and 100.');
        }
        if ($this->tooLong($ability, 255) || $this->tooLong($namespace, 255) || $this->tooLong($search, 255)) {
            return $this->recordedError($correlationId, 'site-abilities-read', $site->site_id, 'invalid_input', 'Ability catalog filters exceed the supported length.');
        }
        if ($ability !== null && ($namespace !== null || $search !== null || $page !== 1 || $per_page !== 10)) {
            return $this->recordedError($correlationId, 'site-abilities-read', $site->site_id, 'invalid_input', 'Exact ability inspection cannot be combined with list pagination or filters.');
        }

        try {
            $catalog = $this->bridge->readAbilities($site, $correlationId, $ability, $page, $per_page, $namespace, $search);
        } catch (SiteConnectionException $exception) {
            $this->health->recordOperationFailure($site, $exception->reason);
            $this->recordFailure($correlationId, 'site-abilities-read', $site->site_id, $exception->reason);

            return $this->connectionError($correlationId, $exception);
        } catch (WpAiBridgeMcpException $exception) {
            $this->health->recordOperationFailure($site, $exception->reason);
            $this->recordFailure($correlationId, 'site-abilities-read', $site->site_id, $exception->reason);

            return $this->error($correlationId, $exception->reason, $exception->getMessage());
        }

        $this->health->recordOperationSuccess($site);
        $this->activity->record($correlationId, 'site-abilities-read', 'success', $site->site_id);

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
    public function siteAbilityExecute(User $user, string $site_id, string $ability, array $input): array
    {
        $correlationId = CorrelationId::current();
        $site = $this->findScopedSite($user, $site_id);
        if (! $site instanceof Site) {
            return $this->siteNotFound($correlationId, 'site-ability-execute');
        }

        $ability = trim($ability);
        if ($ability === '' || mb_strlen($ability) > 255) {
            return $this->recordedError($correlationId, 'site-ability-execute', $site->site_id, 'invalid_input', 'ability must be a non-empty string of at most 255 characters.');
        }

        if (! $this->hasAnyExecutionPermission($user, $site)) {
            return $this->forbidden($correlationId, 'site-ability-execute', $site->site_id);
        }

        try {
            $executionClass = $this->bridge->classifyAbility($site, $ability, $correlationId);
            $this->health->recordOperationSuccess($site);
            if (! $this->access->allows($user, $executionClass->permission(), $site)) {
                return $this->forbidden($correlationId, 'site-ability-execute', $site->site_id);
            }

            $result = $this->bridge->executeAbility(
                $site,
                $ability,
                $input,
                $correlationId,
                $executionClass,
            );
        } catch (SiteConnectionException $exception) {
            $this->health->recordOperationFailure($site, $exception->reason);
            $this->recordFailure($correlationId, 'site-ability-execute', $site->site_id, $exception->reason);

            return $this->connectionError($correlationId, $exception);
        } catch (WpAiBridgeMcpException $exception) {
            $this->health->recordOperationFailure($site, $exception->reason);
            $this->recordFailure($correlationId, 'site-ability-execute', $site->site_id, $exception->reason);

            return $this->error($correlationId, $exception->reason, $exception->getMessage());
        }

        $this->health->recordOperationSuccess($site);
        $this->activity->record($correlationId, 'site-ability-execute', 'success', $site->site_id);

        return [
            'ok' => true,
            'correlation_id' => $correlationId,
            'site_id' => $site->site_id,
            'ability' => $ability,
            'result' => $result,
        ];
    }

    private function findSite(
        User $user,
        string $siteId,
        GatewayPermission $permission,
    ): ?Site {
        $siteId = $this->siteId($siteId);
        if ($siteId === null) {
            return null;
        }

        return $this->access
            ->scopeSites(Site::query(), $user, $permission)
            ->where('site_id', $siteId)
            ->first();
    }

    private function findScopedSite(User $user, string $siteId): ?Site
    {
        $siteId = $this->siteId($siteId);
        if ($siteId === null) {
            return null;
        }

        return $this->access
            ->scopePrincipalSites(Site::query(), $user)
            ->where('site_id', $siteId)
            ->first();
    }

    private function siteId(string $siteId): ?string
    {
        $siteId = trim($siteId);

        return $siteId === '' || mb_strlen($siteId) > 128 ? null : $siteId;
    }

    private function hasAnyExecutionPermission(User $user, Site $site): bool
    {
        foreach ([
            GatewayPermission::AbilitiesExecuteReadonly,
            GatewayPermission::AbilitiesExecuteMutating,
            GatewayPermission::AbilitiesExecuteDestructive,
            GatewayPermission::AbilitiesExecuteUnclassified,
        ] as $permission) {
            if ($this->access->allows($user, $permission, $site)) {
                return true;
            }
        }

        return false;
    }

    private function connectionState(Site $site): string
    {
        $state = $site->getAttribute('connection_state');
        if (! $state instanceof SiteConnectionState) {
            throw new LogicException('Site connection_state cast is invalid.');
        }

        return $state->value;
    }

    private function connectedAt(Site $site): ?string
    {
        $connectedAt = $site->getAttribute('connected_at');
        if ($connectedAt === null) {
            return null;
        }
        if (! $connectedAt instanceof DateTimeInterface) {
            throw new LogicException('Site connected_at cast is invalid.');
        }

        return $connectedAt->format(DATE_ATOM);
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
    private function forbidden(string $correlationId, string $operation, ?string $siteId = null): array
    {
        return $this->recordedError(
            $correlationId,
            $operation,
            $siteId,
            'forbidden',
            'The current Gateway user is not allowed to perform this operation.',
        );
    }

    /** @return array<string, mixed> */
    private function siteNotFound(string $correlationId, string $operation): array
    {
        $this->activity->record($correlationId, $operation, 'failure', null, 'site_not_found');

        return $this->error($correlationId, 'site_not_found', 'The requested site_id is not configured.');
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
    private function recordedError(string $correlationId, string $operation, ?string $siteId, string $code, string $message): array
    {
        $this->recordFailure($correlationId, $operation, $siteId, $code);

        return $this->error($correlationId, $code, $message);
    }

    private function recordFailure(string $correlationId, string $operation, ?string $siteId, string $code): void
    {
        $outcome = $code === 'outcome_unknown' ? 'unknown' : 'failure';
        $this->activity->record($correlationId, $operation, $outcome, $siteId, $code);
    }

    /** @return array<string, mixed> */
    private function error(string $correlationId, string $code, string $message): array
    {
        return [
            'ok' => false,
            'correlation_id' => $correlationId,
            'error' => ['code' => $code, 'message' => $message],
        ];
    }
}
