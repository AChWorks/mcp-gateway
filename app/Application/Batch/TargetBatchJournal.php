<?php

namespace App\Application\Batch;

use Illuminate\Support\Facades\DB;

/** Canonical aggregate from durable child states. Call with the parent locked. */
final class TargetBatchJournal
{
    public function aggregate(string $id): void
    {
        $batch = DB::table('target_batches')->where('id', $id)->first();
        if ($batch === null) {
            return;
        }
        $counts = DB::table('target_batch_items')->where('batch_id', $id)
            ->selectRaw('status, count(*) as total')->groupBy('status')->pluck('total', 'status')->all();
        $pending = (int) ($counts['queued'] ?? 0) + (int) ($counts['dispatching'] ?? 0)
            + (int) ($counts['cancel_requested'] ?? 0);
        $succeeded = (int) ($counts['completed'] ?? 0);
        $unknown = (int) ($counts['outcome_unknown'] ?? 0);
        $canceled = (int) ($counts['canceled'] ?? 0);
        $state = $pending > 0
            ? ($batch->cancel_requested_at !== null ? 'cancel_requested'
                : ((int) $batch->last_dispatch_turn > 0 || (int) ($counts['dispatching'] ?? 0) > 0
                    || $batch->status === 'running' ? 'running' : 'queued'))
            : ($unknown > 0 ? 'outcome_unknown'
                : ($succeeded === (int) $batch->target_count ? 'completed'
                    : ($canceled === (int) $batch->target_count ? 'canceled'
                        : ($succeeded > 0 || $canceled > 0 ? 'partial' : 'failed'))));
        DB::table('target_batches')->where('id', $id)->update([
            'status' => $state, 'updated_at' => now(),
            'finished_at' => $pending === 0 ? ($batch->finished_at ?? now()) : null,
        ]);
    }

    /** Expire only exact active claims; absence of a historical marker is uncertain. */
    public function expireClaims(string $batchId): int
    {
        $now = now();
        $expired = DB::table('target_batch_items')->where('batch_id', $batchId)
            ->whereIn('status', ['dispatching', 'cancel_requested'])
            ->whereNotNull('lease_expires_at')->where('lease_expires_at', '<=', $now);
        $blocked = (clone $expired)->where('effect_admitted', false)->update([
            'status' => 'blocked', 'error_code' => 'dispatch_lease_expired',
            'finished_at' => $now, 'updated_at' => $now,
        ]);
        $unknown = $expired->update([
            'status' => 'outcome_unknown', 'error_code' => 'dispatch_lease_expired',
            'finished_at' => $now, 'updated_at' => $now,
        ]);

        return $blocked + $unknown;
    }
}
