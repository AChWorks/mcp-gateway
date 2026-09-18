<?php

namespace App\Infrastructure\Activity;

use Illuminate\Support\Facades\DB;
use RuntimeException;

final class ActivityRetention
{
    /**
     * @param array{
     *   id:string,
     *   correlation_id:string,
     *   actor_type:string,
     *   actor_id:?string,
     *   client_id_hash:?string,
     *   site_id:?string,
     *   operation:string,
     *   outcome:string,
     *   error_code:?string,
     *   created_at:mixed
     * } $event
     */
    public function store(array $event): void
    {
        DB::transaction(function () use ($event): void {
            $this->lock();
            DB::table('activity_events')->insert($event);
            $this->pruneLocked();
        });
    }

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

        $expiredDeleted = DB::table('activity_events')
            ->where('created_at', '<', now()->subDays($retentionDays))
            ->delete();

        $remaining = DB::table('activity_events')->count();
        $overflow = max(0, $remaining - $maxRows);
        $overflowDeleted = 0;

        if ($overflow > 0) {
            $ids = DB::table('activity_events')
                ->orderBy('created_at')
                ->orderBy('id')
                ->limit($overflow)
                ->pluck('id')
                ->all();

            if ($ids !== []) {
                $overflowDeleted = DB::table('activity_events')->whereIn('id', $ids)->delete();
                $remaining -= $overflowDeleted;
            }
        }

        return [
            'expired_deleted' => $expiredDeleted,
            'overflow_deleted' => $overflowDeleted,
            'remaining' => $remaining,
        ];
    }
}
