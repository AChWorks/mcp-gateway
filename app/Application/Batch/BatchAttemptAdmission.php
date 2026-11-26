<?php

namespace App\Application\Batch;

use App\Application\Access\AccessControl;
use App\Domain\Targets\Target;
use App\Models\User;
use Closure;
use Illuminate\Support\Facades\DB;

/** One current Batch attempt. A committed admission marker is not a remote acknowledgement. */
final class BatchAttemptAdmission
{
    private ?string $denial = null;

    public function __construct(
        private readonly object $batch,
        private readonly object $item,
        private readonly string $attempt,
        private readonly TargetBatchOperationProvider $provider,
        private readonly DeferredBatchAuthority $authority,
        private readonly TargetBatchBinding $bindings,
        private readonly AccessControl $access,
    ) {}

    public function denial(): ?string
    {
        return $this->denial;
    }

    public function allows(): bool
    {
        $batch = DB::table('target_batches')->where('id', $this->batch->id)->first();
        $item = DB::table('target_batch_items')->where('id', $this->item->id)->first();
        $this->denial = $this->reason($batch, $item);

        return $this->denial === null;
    }

    /**
     * Serialize with cancellation and expiry reconciliation using the existing
     * parent -> child lock order. Finish all possibly delaying local checks
     * before the final lease decision. No network call is made under a lock.
     */
    public function admit(Closure $verifyConnector): bool
    {
        return DB::transaction(function () use ($verifyConnector): bool {
            $batch = DB::table('target_batches')->where('id', $this->batch->id)->lockForUpdate()->first();
            $item = DB::table('target_batch_items')->where('id', $this->item->id)->lockForUpdate()->first();
            $this->denial = $this->reason($batch, $item);
            if ($this->denial !== null) {
                return false;
            }
            // A connector revalidates the exact route/material and actor
            // after any wait for the parent lock. Its callback performs
            // local checks only; never invoke a remote operation here.
            $verifyConnector();

            // Time moves during those checks, so the authoritative final
            // lease read/conditional marker follows all of them.
            $item = DB::table('target_batch_items')->where('id', $this->item->id)
                ->lockForUpdate()->first();
            $now = now();
            if ($item === null || $item->status !== 'dispatching'
                || ! hash_equals((string) $item->dispatch_attempt_id, $this->attempt)) {
                $this->denial = 'dispatch_attempt_retired';

                return false;
            }
            if ($item->lease_expires_at === null || $now->gte($item->lease_expires_at)) {
                $this->denial = 'dispatch_lease_expired';

                return false;
            }
            if (! (bool) $item->effect_admitted) {
                $updated = DB::table('target_batch_items')->where('id', $item->id)
                    ->where('batch_id', $this->batch->id)
                    ->where('status', 'dispatching')->where('dispatch_attempt_id', $this->attempt)
                    ->where('lease_expires_at', '>', $now)
                    ->update(['effect_admitted' => true, 'updated_at' => $now]);
                if ($updated !== 1) {
                    $this->denial = 'dispatch_attempt_retired';

                    return false;
                }
            }

            return true;
        }, 3);
    }

    private function reason(?object $batch, ?object $item): ?string
    {
        if ($batch === null || $item === null || $item->batch_id !== $batch->id
            || ! hash_equals((string) $item->dispatch_attempt_id, $this->attempt)) {
            return 'dispatch_attempt_retired';
        }
        if ($batch->cancel_requested_at !== null || in_array($item->status, ['cancel_requested', 'canceled'], true)) {
            return 'batch_canceled';
        }
        if ($item->lease_expires_at === null || now()->gte($item->lease_expires_at)) {
            return 'dispatch_lease_expired';
        }
        if ($item->status !== 'dispatching' || $batch->finished_at !== null) {
            return 'dispatch_attempt_retired';
        }
        $user = User::query()->find($batch->actor_user_id);
        if (! $user instanceof User || ! $this->authority->allows($batch, $user)) {
            return 'authorization_revoked';
        }
        $target = Target::query()->find($item->target_record_id);
        if (! $target instanceof Target
            || (string) $target->getKey() !== (string) $this->item->target_record_id
            || ! hash_equals((string) $target->target_id, (string) $this->item->target_id_snapshot)
            || $target->connector_type !== $this->provider->connectorType()) {
            return 'target_changed';
        }
        if (! $this->access->allows($user, $this->provider->permission(), $target)) {
            return 'authorization_revoked';
        }
        if ($target->operations_paused) {
            return 'target_paused';
        }
        $binding = $this->bindings->hash($target);
        if (! is_string($binding)) {
            return 'target_unavailable';
        }
        if (! hash_equals((string) $this->item->target_binding_hash, $binding)) {
            return 'target_changed';
        }

        return now()->gte($item->lease_expires_at) ? 'dispatch_lease_expired' : null;
    }
}
