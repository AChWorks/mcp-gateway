<?php

namespace App\Infrastructure\Activity;

use Illuminate\Support\Facades\DB;
use RuntimeException;

final class ActivityRetention
{
    private const PRUNE_BATCH_SIZE = 1000;

    /** @return array{expired_deleted:int,overflow_deleted:int,remaining:int} */
    public function prune(): array
    {
        return DB::transaction(function (): array {
            $this->lock();

            return $this->pruneLocked();
        });
    }

    private function lock(): void
    {
        $lock = DB::table('activity_retention_state')
            ->where('id', 1)
            ->lockForUpdate()
            ->first();

        if ($lock === null) {
            throw new RuntimeException('Activity retention state is unavailable.');
        }
    }

    /** @return array{expired_deleted:int,overflow_deleted:int,remaining:int} */
    private function pruneLocked(): array
    {
        $retentionDays = max(1, (int) config('activity.retention_days', 30));
        $maxRows = max(1, (int) config('activity.max_rows', 5000));
        $cutoff = now()->subDays($retentionDays);
        $expiredDeleted = 0;

        while (true) {
            $ids = DB::table('activity_events')
                ->where('created_at', '<', $cutoff)
                ->orderBy('created_at')
                ->orderBy('id')
                ->limit(self::PRUNE_BATCH_SIZE)
                ->pluck('id')
                ->all();

            if ($ids === []) {
                break;
            }

            $deleted = DB::table('activity_events')->whereIn('id', $ids)->delete();
            $expiredDeleted += $deleted;

            if ($deleted === 0 || count($ids) < self::PRUNE_BATCH_SIZE) {
                break;
            }
        }

        $remaining = DB::table('activity_events')->count();
        $overflow = max(0, $remaining - $maxRows);
        $overflowDeleted = 0;

        while ($overflow > 0) {
            $ids = DB::table('activity_events')
                ->orderBy('created_at')
                ->orderBy('id')
                ->limit(min(self::PRUNE_BATCH_SIZE, $overflow))
                ->pluck('id')
                ->all();

            if ($ids === []) {
                break;
            }

            $deleted = DB::table('activity_events')->whereIn('id', $ids)->delete();
            $overflowDeleted += $deleted;
            $remaining -= $deleted;
            $overflow -= $deleted;

            if ($deleted === 0) {
                break;
            }
        }

        return [
            'expired_deleted' => $expiredDeleted,
            'overflow_deleted' => $overflowDeleted,
            'remaining' => max(0, $remaining),
        ];
    }
}
