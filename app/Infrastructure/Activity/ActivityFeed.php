<?php

namespace App\Infrastructure\Activity;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Sites\Site;
use App\Models\User;
use DateTimeInterface;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

final readonly class ActivityFeed
{
    public function __construct(private AccessControl $access) {}

    /** @return array{items:list<array<string,mixed>>,page:int,per_page:int,has_more:bool} */
    public function page(
        User $user,
        int $page = 1,
        int $perPage = 25,
        ?string $siteId = null,
        ?string $operation = null,
    ): array {
        if (! $this->access->allows($user, GatewayPermission::ActivityView)) {
            throw new AuthorizationException;
        }

        $perPage = max(1, min((int) config('activity.page_size_max', 100), $perPage));
        $maxRows = max(1, (int) config('activity.max_rows', 5000));
        $maxPage = intdiv($maxRows + $perPage - 1, $perPage) + 1;
        $page = max(1, min($maxPage, $page));
        $siteId = $this->filter($siteId, 128);
        $operation = $this->filter($operation, 128);

        $allowedSites = $this->access->scopeSites(
            Site::query()->select('site_id'),
            $user,
            GatewayPermission::SitesView,
        );

        $query = DB::table('activity_events')
            ->select([
                'id',
                'correlation_id',
                'actor_type',
                'actor_id',
                'site_id',
                'operation',
                'outcome',
                'error_code',
                'created_at',
            ]);

        if (! $this->access->hasUnrestrictedSiteScope($user)) {
            $query->where(function ($query) use ($user, $allowedSites): void {
                if ($this->access->hasAllSiteScope($user)) {
                    $query->whereNull('site_id')
                        ->orWhereIn('site_id', $allowedSites);
                } else {
                    $query->whereIn('site_id', $allowedSites);
                }
            });
        }

        $query
            ->when($siteId !== null, fn ($query) => $query->where('site_id', $siteId))
            ->when($operation !== null, fn ($query) => $query->where('operation', $operation))
            ->orderByDesc('created_at')
            ->orderByDesc('id');

        $rows = $query
            ->offset(($page - 1) * $perPage)
            ->limit($perPage + 1)
            ->get();
        $hasMore = $rows->count() > $perPage;
        $items = [];

        foreach ($rows->take($perPage) as $row) {
            $createdAt = $row->created_at;
            $items[] = [
                'id' => (string) $row->id,
                'correlation_id' => (string) $row->correlation_id,
                'actor_type' => (string) $row->actor_type,
                'actor_id' => $row->actor_id === null ? null : (string) $row->actor_id,
                'site_id' => $row->site_id === null ? null : (string) $row->site_id,
                'operation' => (string) $row->operation,
                'outcome' => (string) $row->outcome,
                'error_code' => $row->error_code === null ? null : (string) $row->error_code,
                'created_at' => $createdAt instanceof DateTimeInterface
                    ? $createdAt->format(DATE_ATOM)
                    : (string) $createdAt,
            ];
        }

        return [
            'items' => $items,
            'page' => $page,
            'per_page' => $perPage,
            'has_more' => $hasMore,
        ];
    }

    private function filter(?string $value, int $max): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);
        if ($value === '') {
            return null;
        }
        if (mb_strlen($value) > $max) {
            throw new InvalidArgumentException('Activity filter exceeds the supported length.');
        }

        return $value;
    }
}
