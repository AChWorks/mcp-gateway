<?php

namespace App\Application\Batch;

use App\Application\Access\AccessControl;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/**
 * Database-coordinated worker. Claim is durable before any remote operation;
 * crash/timeout leaves an honest unknown outcome, NEVER an auto replay.
 * Multiple CLI worker processes can claim different Targets concurrently.
 */
final readonly class TargetBatchWorker
{
    public function __construct(
        private BatchProviderResolver $providers,
        private DeferredBatchAuthority $authority,
        private TargetBatchBinding $bindings,
        private AccessControl $access,
        private ActivityRecorder $activity,
    ) {}

    /** @return array<string,mixed>|null A single durable child attempt, or idle */
    public function workOnce(): ?array
    {
        // Cursor avoids materializing a fleet-sized Batch list. Another
        // worker may advance state between cursor and transaction; row locks
        // and exact status checks are authoritative.
        $candidates = DB::table('target_batches')
            ->whereIn('status', ['queued', 'running', 'cancel_requested'])
            ->orderBy('created_at')->orderBy('id')->cursor();
        foreach ($candidates as $candidate) {
            $claimed = DB::transaction(function () use ($candidate): ?array {
                // A shared singleton lock serializes global/user capacity
                // admission across concurrent Laravel worker processes.
                if (DB::table('operational_settings')->where('id', 1)->lockForUpdate()->first() === null) {
                    throw new \RuntimeException(
                        'Batch worker admission lock is unavailable: operational_settings row 1 is missing. No new remote effect was dispatched.',
                    );
                }
                $batch = DB::table('target_batches')->where('id', $candidate->id)->lockForUpdate()->first();
                if ($batch === null || $batch->finished_at !== null) {
                    return null;
                }
                $now = now();
                DB::table('target_batch_items')->where('batch_id', $batch->id)
                    ->whereIn('status', ['dispatching', 'cancel_requested'])
                    ->whereNotNull('lease_expires_at')
                    ->where('lease_expires_at', '<=', $now)
                    ->update([
                        'status' => 'outcome_unknown', 'error_code' => 'dispatch_lease_expired',
                        'finished_at' => $now, 'updated_at' => $now,
                    ]);
                if ($batch->cancel_requested_at !== null) {
                    DB::table('target_batch_items')->where('batch_id', $batch->id)
                        ->where('status', 'queued')->update([
                            'status' => 'canceled', 'finished_at' => $now, 'updated_at' => $now,
                        ]);
                    $this->aggregate($batch->id);

                    return null;
                }
                if ($batch->stop_on_failure && DB::table('target_batch_items')
                    ->where('batch_id', $batch->id)
                    ->whereIn('status', ['failed', 'blocked', 'outcome_unknown'])->exists()) {
                    DB::table('target_batch_items')->where('batch_id', $batch->id)
                        ->where('status', 'queued')->update([
                            'status' => 'blocked', 'error_code' => 'stopped_after_failure',
                            'finished_at' => $now, 'updated_at' => $now,
                        ]);
                    $this->aggregate($batch->id);

                    return null;
                }
                $activeBatch = DB::table('target_batch_items')->where('batch_id', $batch->id)
                    ->whereIn('status', ['dispatching', 'cancel_requested'])->count();
                if ($activeBatch >= ($batch->execution_mode === 'rolling' ? 1 : (int) $batch->parallelism)) {
                    return null;
                }
                $globalActive = DB::table('target_batch_items')
                    ->whereIn('status', ['dispatching', 'cancel_requested'])->count();
                if ($globalActive >= max(1, (int) config('batch.global_active', 4))) {
                    return null;
                }
                $userActive = DB::table('target_batch_items as items')
                    ->join('target_batches as batches', 'batches.id', '=', 'items.batch_id')
                    ->where('batches.actor_user_id', $batch->actor_user_id)
                    ->whereIn('items.status', ['dispatching', 'cancel_requested'])->count();
                if ($userActive >= max(1, (int) config('batch.user_active', 2))) {
                    return null;
                }
                $item = DB::table('target_batch_items')->where('batch_id', $batch->id)
                    ->where('status', 'queued')->orderBy('position')->lockForUpdate()->first();
                if ($item === null) {
                    $this->aggregate($batch->id);

                    return null;
                }
                if (DB::table('target_batch_items')->where('target_record_id', $item->target_record_id)
                    ->whereIn('status', ['dispatching', 'cancel_requested'])->exists()) {
                    return null;
                }
                $timeout = $batch->capability_key === 'ssh.command.run'
                    ? $this->sshTimeoutFromEncryptedArguments($batch->arguments_ciphertext)
                    : max(30, (int) config('bridge.http.request_timeout_seconds', 30));
                $attemptId = (string) Str::uuid();
                DB::table('target_batch_items')->where('id', $item->id)->where('status', 'queued')
                    ->update([
                        'status' => 'dispatching', 'dispatch_attempt_id' => $attemptId,
                        'started_at' => $now,
                        'lease_expires_at' => $now->copy()->addSeconds(
                            $timeout + max(30, (int) config('batch.lease_margin_seconds', 90)),
                        ),
                        'updated_at' => $now,
                    ]);
                DB::table('target_batches')->where('id', $batch->id)->update([
                    'status' => 'running', 'updated_at' => $now,
                ]);

                return ['batch' => $batch, 'item' => $item, 'attempt' => $attemptId];
            }, 3);
            if ($claimed !== null) {
                return $this->perform($claimed['batch'], $claimed['item'], $claimed['attempt']);
            }
        }

        return null;
    }

    private function sshTimeoutFromEncryptedArguments(string $encrypted): int
    {
        try {
            $input = json_decode(Crypt::decryptString($encrypted), true, 512, JSON_THROW_ON_ERROR);

            return max(1, (int) ($input['timeout_seconds'] ?? 10));
        } catch (Throwable) {
            // Invalid encrypted input is reconciled as blocked before dispatch;
            // this duration only bounds the crash recovery lease.
            return 10;
        }
    }

    /** @return array<string,mixed> */
    private function perform(object $batch, object $item, string $attempt): array
    {
        $provider = $this->providers->find((string) $batch->capability_key);
        $user = User::query()->find($batch->actor_user_id);
        $target = Target::query()->find($item->target_record_id);
        $before = function () use ($batch, $item, $attempt): bool {
            $currentBatch = DB::table('target_batches')->where('id', $batch->id)->first();
            $currentItem = DB::table('target_batch_items')->where('id', $item->id)->first();
            $currentUser = User::query()->find($batch->actor_user_id);
            $currentTarget = Target::query()->find($item->target_record_id);
            $provider = $this->providers->find((string) $batch->capability_key);
            if ($currentBatch === null || $currentBatch->cancel_requested_at !== null
                || $currentItem === null || $currentItem->status !== 'dispatching'
                || ! hash_equals((string) $currentItem->dispatch_attempt_id, $attempt)
                || $provider === null
                || ! $currentUser instanceof User || ! $currentTarget instanceof Target
                || ! $this->authority->allows($currentBatch, $currentUser)
                || (string) $currentTarget->getKey() !== (string) $item->target_record_id
                || ! hash_equals((string) $currentTarget->target_id, (string) $item->target_id_snapshot)
                || $currentTarget->connector_type !== $provider->connectorType()
                || ! $this->access->allows($currentUser, $provider->permission(), $currentTarget)) {
                return false;
            }
            $binding = $this->bindings->hash($currentTarget);

            return is_string($binding)
                && hash_equals((string) $item->target_binding_hash, $binding);
        };
        $outcome = ['ok' => false, 'status' => 'blocked', 'error_code' => 'authorization_revoked'];
        if ($provider !== null && $user instanceof User && $target instanceof Target && $before()) {
            try {
                $arguments = json_decode(Crypt::decryptString($batch->arguments_ciphertext), true, 512, JSON_THROW_ON_ERROR);
                if (is_array($arguments) && $provider->validArguments($arguments)) {
                    // The provider will re-run $before immediately before its
                    // native transport's first remote effect as well.
                    $outcome = $provider->execute($user, $target, $arguments, $before, $batch->source_channel === 'mcp');
                } else {
                    $outcome = ['ok' => false, 'status' => 'blocked', 'error_code' => 'invalid_stored_arguments'];
                }
            } catch (Throwable $exception) {
                $outcome = ['ok' => false, 'status' => 'outcome_unknown',
                    'error_code' => 'worker_exception_after_claim',
                    'diagnostics' => ['exception_class' => $exception::class, 'effect_unconfirmed' => true]];
            }
        }
        $state = in_array($outcome['status'] ?? null, ['completed', 'failed', 'blocked', 'outcome_unknown'], true)
            ? $outcome['status'] : 'outcome_unknown';
        $error = isset($outcome['error_code']) && is_string($outcome['error_code'])
            ? $outcome['error_code'] : null;
        $reference = (string) Str::uuid();
        $effect = $state === 'completed' ? 'success' : ($state === 'outcome_unknown' ? 'unknown' : 'failure');
        $this->activity->record($reference, 'target-batch-'.$batch->capability_key, $effect, $target, $error, [
            'batch_id' => $batch->id, 'batch_child_id' => $item->id, 'batch_status' => $state,
            'source_channel' => $batch->source_channel, 'attempt_id' => $attempt,
            'retry_safe' => false,
            ...($outcome['diagnostics'] ?? []),
        ]);
        $encoded = Crypt::encryptString(json_encode($outcome, JSON_THROW_ON_ERROR));
        DB::transaction(function () use ($batch, $item, $attempt, $state, $error, $encoded, $reference): void {
            $current = DB::table('target_batches')->where('id', $batch->id)->lockForUpdate()->first();
            if ($current === null) {
                return;
            }
            $updated = DB::table('target_batch_items')->where('id', $item->id)
                ->where('dispatch_attempt_id', $attempt)
                ->whereIn('status', ['dispatching', 'cancel_requested'])->update([
                    'status' => $state, 'error_code' => $error,
                    'result_ciphertext' => $encoded,
                    'diagnostic_reference' => $reference,
                    'finished_at' => now(), 'updated_at' => now(),
                ]);
            if ($updated === 1) {
                // Never let a stale worker overwrite an unknown result after
                // its lease expired and another observer reconciled it.
                $this->aggregate($current->id);
            }
        }, 3);

        return ['batch_id' => $batch->id, 'target_id' => $item->target_id_snapshot,
            'status' => $state, 'error_code' => $error, 'diagnostic_reference' => $reference];
    }

    /** Update an already locked parent's aggregate from durable child states. */
    private function aggregate(string $id): void
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
            ? ($batch->cancel_requested_at !== null ? 'cancel_requested' : 'running')
            : ($unknown > 0 ? 'outcome_unknown'
                : ($succeeded === (int) $batch->target_count ? 'completed'
                    : ($canceled === (int) $batch->target_count ? 'canceled'
                        : ($succeeded > 0 || $canceled > 0 ? 'partial' : 'failed'))));
        DB::table('target_batches')->where('id', $id)->update([
            'status' => $state, 'updated_at' => now(),
            'finished_at' => $pending === 0 ? now() : null,
        ]);
    }
}
