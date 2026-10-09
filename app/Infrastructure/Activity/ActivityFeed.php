<?php

namespace App\Infrastructure\Activity;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
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
        ?string $targetId = null,
        ?string $operation = null,
    ): array {
        if (! $this->access->allows($user, GatewayPermission::ActivityView)) {
            throw new AuthorizationException;
        }

        $perPage = max(1, min((int) config('activity.page_size_max', 100), $perPage));
        $maxRows = max(1, (int) config('activity.max_rows', 5000));
        $maxPage = intdiv($maxRows + $perPage - 1, $perPage) + 1;
        $page = max(1, min($maxPage, $page));
        $targetId = $this->filter($targetId, 64);
        $operation = $this->filter($operation, 128);

        $allowedTargets = $this->access->scopeTargets(
            Target::query()->select('id'),
            $user,
            GatewayPermission::TargetsView,
        );

        $query = DB::table('activity_events')
            ->select([
                'id',
                'correlation_id',
                'actor_type',
                'actor_id',
                'client_profile_key',
                'target_id',
                'target_record_id',
                'connector_type_snapshot',
                'operation',
                'outcome',
                'error_code',
                'created_at',
            ]);

        if (! $this->access->hasUnrestrictedTargetScope($user)) {
            $query->where(function ($query) use ($user, $allowedTargets): void {
                if ($this->access->hasAllTargetScope($user)) {
                    $query->whereNull('target_record_id')
                        ->orWhereIn('target_record_id', $allowedTargets);
                } else {
                    $query->whereIn('target_record_id', $allowedTargets);
                }
            });
        }

        if ($targetId !== null) {
            if ($this->access->hasUnrestrictedTargetScope($user)) {
                // Owners can inspect retained snapshots even after Target removal.
                $query->where('target_id', $targetId);
            } else {
                $scopedTarget = $this->access->scopeTargets(
                    Target::query()->where('target_id', $targetId),
                    $user,
                    GatewayPermission::TargetsView,
                )->first(['id']);
                $query->where('target_record_id', $scopedTarget?->getKey() ?? '');
            }
        }

        $query
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
                'client_profile_key' => $row->client_profile_key === null ? null : (string) $row->client_profile_key,
                'target_id' => $row->target_id === null ? null : (string) $row->target_id,
                'target_record_id' => $row->target_record_id === null ? null : (string) $row->target_record_id,
                'connector_type_snapshot' => $row->connector_type_snapshot === null ? null : (string) $row->connector_type_snapshot,
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
