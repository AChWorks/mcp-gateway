<?php

namespace App\Infrastructure\Activity;

use DateTimeInterface;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

final class ActivityFeed
{
    /** @return array{items:list<array<string,mixed>>,page:int,per_page:int,has_more:bool} */
    public function page(
        int $page = 1,
        int $perPage = 25,
        ?string $siteId = null,
        ?string $operation = null,
    ): array {
        $perPage = max(1, min((int) config('activity.page_size_max', 100), $perPage));
        $maxRows = max(1, (int) config('activity.max_rows', 5000));
        $maxPage = intdiv($maxRows + $perPage - 1, $perPage) + 1;
        $page = max(1, min($maxPage, $page));
        $siteId = $this->filter($siteId, 128);
        $operation = $this->filter($operation, 128);

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
            ])
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
