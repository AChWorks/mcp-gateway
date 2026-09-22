<?php

namespace App\Application\Sites;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use InvalidArgumentException;

final class SiteInventory
{
    public function __construct(private readonly AccessControl $access) {}

    public const ADMIN_PAGE_SIZE = 50;

    public const MCP_DEFAULT_LIMIT = 100;

    public const MCP_MAX_LIMIT = 100;

    /**
     * @return array{items:list<Site>,page:int,per_page:int,has_more:bool}
     */
    public function adminPage(
        User $user,
        int $page = 1,
        ?string $search = null,
        ?string $connectionState = null,
    ): array {
        $page = max(1, $page);
        $search = $this->search($search);
        $connectionState = $this->connectionState($connectionState);

        $query = $this->access->scopeSites(
            Site::query()->select([
                'id',
                'site_id',
                'display_name',
            ]),
            $user,
            GatewayPermission::SitesView,
        );

        $this->applyFilters($query, $search, $connectionState);

        $rows = $query
            ->orderBy('display_name')
            ->orderBy('site_id')
            ->offset(($page - 1) * self::ADMIN_PAGE_SIZE)
            ->limit(self::ADMIN_PAGE_SIZE + 1)
            ->get();
        $hasMore = $rows->count() > self::ADMIN_PAGE_SIZE;
        $pageRows = $rows->take(self::ADMIN_PAGE_SIZE)->values();

        if ($pageRows->isEmpty()) {
            $items = [];
        } else {
            $detailQuery = Site::query()->select([
                'id',
                'site_id',
                'display_name',
                'base_url',
                'connector_type',
                'connection_state',
                'last_error_code',
                'last_tested_at',
                'connected_at',
            ]);
            $sitesById = $this->access
                ->scopeSites($detailQuery, $user, GatewayPermission::SitesView)
                ->whereIn('id', $pageRows->pluck('id')->all())
                ->get()
                ->keyBy('id');

            $items = $pageRows
                ->map(static fn (Site $row): ?Site => $sitesById->get($row->id))
                ->filter(static fn (?Site $site): bool => $site instanceof Site)
                ->values()
                ->all();
        }

        return [
            'items' => $items,
            'page' => $page,
            'per_page' => self::ADMIN_PAGE_SIZE,
            'has_more' => $hasMore,
        ];
    }

    /**
     * @return array{items:list<Site>,limit:int,has_more:bool,next_cursor:?string}
     */
    public function mcpPage(
        User $user,
        ?string $cursor = null,
        int $limit = self::MCP_DEFAULT_LIMIT,
        ?string $search = null,
        ?string $connectionState = null,
    ): array {
        if ($limit < 1 || $limit > self::MCP_MAX_LIMIT) {
            throw new InvalidArgumentException(sprintf(
                'limit must be between 1 and %d.',
                self::MCP_MAX_LIMIT,
            ));
        }

        $cursor = $this->cursor($cursor);
        $search = $this->search($search);
        $connectionState = $this->connectionState($connectionState);

        $query = $this->access->scopeSites(
            Site::query()->select([
                'site_id',
                'display_name',
                'connector_type',
                'connection_state',
            ]),
            $user,
            GatewayPermission::SitesView,
        );

        $this->applyFilters($query, $search, $connectionState);

        if ($cursor !== null) {
            $query->where('site_id', '>', $cursor);
        }

        $rows = $query
            ->orderBy('site_id')
            ->limit($limit + 1)
            ->get();
        $items = $rows->take($limit)->values();
        $hasMore = $rows->count() > $limit;
        $last = $items->last();

        return [
            'items' => $items->all(),
            'limit' => $limit,
            'has_more' => $hasMore,
            'next_cursor' => $hasMore && $last instanceof Site ? $last->site_id : null,
        ];
    }

    /** @param Builder<Site> $query */
    private function applyFilters(Builder $query, ?string $search, ?string $connectionState): void
    {
        if ($search !== null) {
            $query->where(function (Builder $query) use ($search): void {
                $query
                    ->where('display_name', 'like', '%'.$search.'%')
                    ->orWhere('site_id', 'like', '%'.$search.'%');
            });
        }

        if ($connectionState !== null) {
            $query->where('connection_state', $connectionState);
        }
    }

    private function cursor(?string $value): ?string
    {
        $value = $this->nullableTrim($value);

        if ($value !== null && mb_strlen($value) > 64) {
            throw new InvalidArgumentException('cursor exceeds the supported site ID length.');
        }

        return $value;
    }

    private function search(?string $value): ?string
    {
        $value = $this->nullableTrim($value);

        if ($value !== null && mb_strlen($value) > 160) {
            throw new InvalidArgumentException('search exceeds the supported length.');
        }

        return $value;
    }

    private function connectionState(?string $value): ?string
    {
        $value = $this->nullableTrim($value);

        if ($value !== null && SiteConnectionState::tryFrom($value) === null) {
            throw new InvalidArgumentException('connection_state is not supported.');
        }

        return $value;
    }

    private function nullableTrim(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
