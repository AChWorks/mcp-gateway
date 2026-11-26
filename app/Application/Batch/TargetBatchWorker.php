<?php

namespace App\Application\Batch;

use App\Application\Access\AccessControl;
use App\Application\Operations\OperationalSettings;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityAttribution;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\OperationDiagnostics;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/**
 * Database-coordinated worker. Claim is durable before any remote operation;
 * a retired claim is blocked only when no effect admission is proven;
 * otherwise retain an honest unknown outcome, NEVER an auto replay.
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
        private OperationalSettings $settings,
        private TargetBatchJournal $journal,
    ) {}

    /** @return array<string,mixed>|null A single durable child attempt, or idle */
    public function workOnce(): ?array
    {
        // Persisted round-robin fairness across runnable parent Batches.
        // A successful claim moves its Batch to the end using a strictly
        // increasing turn allocated under the existing global admission lock.
        // Bounded keyset pages avoid holding an unbuffered DB cursor while
        // issuing nested transactional/row-lock queries.
        // Re-fetch from the beginning when a different worker moved a
        // pre-lock candidate. A stale parent must never spend the next
        // admission slot ahead of its siblings. Bound contention rescans to
        // the already-configured global active budget; a later invocation
        // can retry if contention persists, without spinning indefinitely.
        $limits = $this->settings->batchLimits();
        $rescanLimit = $limits['global_active'];
        for ($rescan = 0; $rescan <= $rescanLimit; $rescan++) {
            $stale = false;
            $afterTurn = null;
            $afterCreatedAt = null;
            $afterId = null;
            do {
                $query = DB::table('target_batches')
                    ->whereIn('status', ['queued', 'running', 'cancel_requested']);
                if ($afterId !== null) {
                    $query->where(static function ($page) use ($afterTurn, $afterCreatedAt, $afterId): void {
                        $page->where('last_dispatch_turn', '>', $afterTurn)
                            ->orWhere(static function ($sameTurn) use ($afterTurn, $afterCreatedAt): void {
                                $sameTurn->where('last_dispatch_turn', $afterTurn)
                                    ->where('created_at', '>', $afterCreatedAt);
                            })
                            ->orWhere(static function ($sameTime) use ($afterTurn, $afterCreatedAt, $afterId): void {
                                $sameTime->where('last_dispatch_turn', $afterTurn)
                                    ->where('created_at', $afterCreatedAt)->where('id', '>', $afterId);
                            });
                    });
                }
                $candidates = $query->orderBy('last_dispatch_turn')->orderBy('created_at')
                    ->orderBy('id')->limit(64)->get();
                foreach ($candidates as $candidate) {
                    $afterTurn = (int) $candidate->last_dispatch_turn;
                    $afterCreatedAt = $candidate->created_at;
                    $afterId = $candidate->id;
                    $claimed = DB::transaction(function () use ($candidate, $limits): ?array {
                        // A shared singleton lock serializes global/user capacity
                        // admission across concurrent Laravel worker processes.
                        $admission = DB::table('operational_settings')->where('id', 1)
                            ->lockForUpdate()->first(['batch_dispatch_turn']);
                        if ($admission === null) {
                            throw new \RuntimeException(
                                'Batch worker admission lock is unavailable: operational_settings row 1 is missing. No new remote effect was dispatched.',
                            );
                        }
                        $batch = DB::table('target_batches')->where('id', $candidate->id)->lockForUpdate()->first();
                        if ($batch === null || $batch->finished_at !== null) {
                            return null;
                        }
                        // The ordered page was read before the admission lock.
                        // Another Worker may have claimed this same parent and
                        // moved it behind an independent waiting parent. A fresh
                        // page, not this now-stale snapshot, must decide priority.
                        if ((int) $batch->last_dispatch_turn !== (int) $candidate->last_dispatch_turn) {
                            return ['rescan' => true];
                        }
                        $now = now();
                        if ($this->journal->expireClaims($batch->id) > 0) {
                            $this->journal->aggregate($batch->id);
                        }
                        if ($batch->cancel_requested_at !== null) {
                            DB::table('target_batch_items')->where('batch_id', $batch->id)
                                ->where('status', 'queued')->update([
                                    'status' => 'canceled', 'finished_at' => $now, 'updated_at' => $now,
                                ]);
                            $this->journal->aggregate($batch->id);

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
                            $this->journal->aggregate($batch->id);

                            return null;
                        }
                        $activeBatch = DB::table('target_batch_items')->where('batch_id', $batch->id)
                            ->whereIn('status', ['dispatching', 'cancel_requested'])->count();
                        if ($activeBatch >= ($batch->execution_mode === 'rolling' ? 1 : (int) $batch->parallelism)) {
                            return null;
                        }
                        $globalActive = DB::table('target_batch_items')
                            ->whereIn('status', ['dispatching', 'cancel_requested'])->count();
                        if ($globalActive >= $limits['global_active']) {
                            return null;
                        }
                        $userActive = DB::table('target_batch_items as items')
                            ->join('target_batches as batches', 'batches.id', '=', 'items.batch_id')
                            ->where('batches.actor_user_id', $batch->actor_user_id)
                            ->whereIn('items.status', ['dispatching', 'cancel_requested'])->count();
                        if ($userActive >= $limits['user_active']) {
                            return null;
                        }
                        // Concurrent Batches may bypass a busy child to use
                        // independent available Targets. Rolling is different:
                        // preserve the exact selected order and wait until the
                        // first queued Target is free before continuing.
                        $itemQuery = DB::table('target_batch_items as queued')
                            ->where('queued.batch_id', $batch->id)
                            ->where('queued.status', 'queued');
                        if ($batch->execution_mode !== 'rolling') {
                            $itemQuery->whereNotExists(static function ($query): void {
                                $query->selectRaw('1')->from('target_batch_items as active')
                                    ->whereColumn('active.target_record_id', 'queued.target_record_id')
                                    ->whereIn('active.status', ['dispatching', 'cancel_requested']);
                            });
                        }
                        $item = $itemQuery->orderBy('queued.position')->lockForUpdate()->first();
                        if ($item !== null && $batch->execution_mode === 'rolling'
                            && DB::table('target_batch_items')->where('target_record_id', $item->target_record_id)
                                ->whereIn('status', ['dispatching', 'cancel_requested'])->exists()) {
                            return null;
                        }
                        if ($item === null) {
                            // This may be a genuinely finished Batch OR one with
                            // queued work temporarily blocked by other active Batches.
                            $this->journal->aggregate($batch->id);

                            return null;
                        }
                        $timeout = $this->remoteTimeoutSeconds($batch->capability_key, $batch->arguments_ciphertext);
                        $attemptId = (string) Str::uuid();
                        DB::table('target_batch_items')->where('id', $item->id)->where('status', 'queued')
                            ->update([
                                'status' => 'dispatching', 'dispatch_attempt_id' => $attemptId, 'effect_admitted' => false,
                                'started_at' => $now,
                                'lease_expires_at' => $now->copy()->addSeconds(
                                    $timeout + max(30, (int) config('batch.lease_margin_seconds', 90)),
                                ),
                                'updated_at' => $now,
                            ]);
                        // The same transaction commits both the durable child
                        // claim and the next parent turn. Crashes cannot consume
                        // a turn without a claim or allow concurrent workers to
                        // allocate the same turn. No wall-clock precision needed.
                        $nextTurn = (int) $admission->batch_dispatch_turn + 1;
                        DB::table('operational_settings')->where('id', 1)->update([
                            'batch_dispatch_turn' => $nextTurn,
                        ]);
                        DB::table('target_batches')->where('id', $batch->id)->update([
                            'status' => 'running', 'last_dispatch_turn' => $nextTurn, 'updated_at' => $now,
                        ]);

                        return ['batch' => $batch, 'item' => $item, 'attempt' => $attemptId];
                    }, 3);
                    if (($claimed['rescan'] ?? false) === true) {
                        $stale = true;
                        break;
                    }
                    if ($claimed !== null) {
                        return $this->perform($claimed['batch'], $claimed['item'], $claimed['attempt']);
                    }
                }
            } while (! $stale && $candidates->count() === 64);
            if (! $stale) {
                break;
            }
        }

        return null;
    }

    private function remoteTimeoutSeconds(string $capability, string $encrypted): int
    {
        try {
            $input = json_decode(Crypt::decryptString($encrypted), true, 512, JSON_THROW_ON_ERROR);
            $provider = $this->providers->find($capability);
            if ($provider === null || ! is_array($input) || ! $provider->validArguments($input)) {
                return 30; // Invalid payload is blocked before any new remote effect.
            }

            return max(1, $provider->remoteTimeoutSeconds($input));
        } catch (Throwable) {
            // No optimistic replay when the sealed input/provider cannot be
            // resolved. The post-claim execution gate will block it safely.
            return 30;
        }
    }

    /** @return array<string,mixed> */
    private function perform(object $batch, object $item, string $attempt): array
    {
        $provider = $this->providers->find((string) $batch->capability_key);
        $user = User::query()->find($batch->actor_user_id);
        $target = Target::query()->find($item->target_record_id);
        $gate = $provider === null ? null : new BatchAttemptAdmission(
            $batch, $item, $attempt, $provider, $this->authority, $this->bindings, $this->access,
        );
        $outcome = ['ok' => false, 'status' => 'blocked', 'error_code' => 'unsupported_connector'];
        if ($gate !== null && $user instanceof User && $target instanceof Target && $gate->allows()) {
            try {
                $arguments = json_decode(Crypt::decryptString($batch->arguments_ciphertext), true, 512, JSON_THROW_ON_ERROR);
                if (is_array($arguments) && $provider->validArguments($arguments)) {
                    $outcome = $provider->execute(
                        $user, $target, $arguments, $gate->allows(...), $batch->source_channel === 'mcp',
                        $gate->admit(...), ActivityAttribution::fromBatch($batch),
                    );
                } else {
                    $outcome = ['ok' => false, 'status' => 'blocked', 'error_code' => 'invalid_stored_arguments'];
                }
            } catch (Throwable $exception) {
                $outcome = ['ok' => false, 'status' => 'outcome_unknown',
                    'error_code' => 'worker_exception_after_claim',
                    'diagnostics' => ['exception_class' => $exception::class, 'effect_unconfirmed' => true]];
            }
        } elseif ($gate !== null) {
            $outcome['error_code'] = $gate->denial() ?? ($user === null ? 'authorization_revoked' : 'target_changed');
        }
        if ($gate?->denial() !== null
            && in_array($outcome['error_code'] ?? null, ['forbidden', 'authorization_revoked', 'dispatch_lease_expired', 'batch_canceled', 'dispatch_attempt_retired', 'target_changed', 'target_paused', 'target_unavailable'], true)) {
            $outcome['error_code'] = $gate->denial();
            $outcome['diagnostics'] = [
                ...($outcome['diagnostics'] ?? []),
                'failure_origin' => 'gateway_admission', 'failure_stage' => 'admission',
                'source_error_code' => $gate->denial(),
            ];
        }
        $reference = (string) Str::uuid();

        // Commit native result/evidence before any best-effort Activity.
        $journal = DB::transaction(function () use ($batch, $item, $attempt, $outcome, $reference): array {
            $current = DB::table('target_batches')->where('id', $batch->id)->lockForUpdate()->first();
            $child = DB::table('target_batch_items')->where('id', $item->id)->lockForUpdate()->first();
            $same = $current !== null && $child !== null
                && hash_equals((string) $child->dispatch_attempt_id, $attempt);
            $accepted = $same && in_array($child->status, ['dispatching', 'cancel_requested'], true);
            $neverAdmitted = $same && $child->effect_admitted !== null && ! (bool) $child->effect_admitted;
            $state = in_array($outcome['status'] ?? null, ['completed', 'failed', 'blocked', 'outcome_unknown'], true)
                ? $outcome['status'] : 'outcome_unknown';
            $error = is_string($outcome['error_code'] ?? null) ? $outcome['error_code'] : null;
            $providerState = $state;
            if ($neverAdmitted && $state === 'completed') {
                // A provider reporting success without the mandatory marker
                // is contradictory evidence, not proof of an unsent request.
                $state = 'outcome_unknown';
                $error = 'dispatch_evidence_missing';
                $outcome['diagnostics'] = [...($outcome['diagnostics'] ?? []), 'effect_unconfirmed' => true];
                $neverAdmitted = false;
            }
            if ($neverAdmitted) {
                if ($state === 'outcome_unknown' && in_array($error, ['worker_exception_after_claim', 'ssh_execution_unexpected'], true)) {
                    // No new protected effect was admitted by this attempt.
                    // Do not erase provider-native recovery/transport evidence.
                    $state = 'blocked';
                    $outcome['diagnostics']['effect_unconfirmed'] = false;
                }
                if ($error === 'batch_canceled') {
                    $state = 'canceled';
                    $error = null;
                } elseif (in_array($error, ['dispatch_lease_expired', 'dispatch_attempt_retired', 'authorization_revoked', 'target_changed', 'target_paused', 'target_unavailable'], true)) {
                    $state = 'blocked';
                }
            }
            if ($same && $child->effect_admitted !== null) {
                $outcome['diagnostics']['batch_effect_admitted'] = (bool) $child->effect_admitted;
            }
            $outcome['status'] = $state;
            $outcome['ok'] = $state === 'completed';
            $outcome['error_code'] = $error;
            if ($accepted) {
                DB::table('target_batch_items')->where('id', $child->id)->update([
                    'status' => $state, 'error_code' => $error,
                    'result_ciphertext' => Crypt::encryptString(json_encode($outcome, JSON_THROW_ON_ERROR)),
                    'diagnostic_reference' => $reference,
                    'finished_at' => now(), 'updated_at' => now(),
                ]);
                $this->journal->aggregate($batch->id);
            } elseif ($same && $child->late_observation_ciphertext === null) {
                DB::table('target_batch_items')->where('id', $child->id)->update([
                    'late_observation_ciphertext' => Crypt::encryptString(json_encode([
                        'attempt_id' => $attempt, 'observed_at' => now()->toISOString(),
                        'diagnostic_reference' => $reference, 'observation' => $outcome,
                    ], JSON_THROW_ON_ERROR)),
                    'diagnostic_reference' => $child->diagnostic_reference ?? $reference,
                    'updated_at' => now(),
                ]);
            }
            $authoritative = DB::table('target_batch_items')->where('id', $item->id)->first();

            return [
                'accepted' => $accepted, 'never_admitted' => $neverAdmitted,
                'provider_status' => $providerState, 'diagnostics' => $outcome['diagnostics'] ?? [],
                'status' => $authoritative === null ? 'outcome_unknown' : $authoritative->status,
                'error_code' => $authoritative === null
                    ? 'batch_journal_unavailable' : $authoritative->error_code,
                'diagnostic_reference' => $authoritative?->diagnostic_reference,
            ];
        }, 3);

        $accepted = $journal['accepted'];
        $actualState = $journal['status'];
        $actualError = $journal['error_code'];
        $details = [
            'batch_id' => $batch->id,
            'batch_child_id' => $item->id,
            'batch_status' => $actualState,
            'source_channel' => $batch->source_channel,
            'attempt_id' => $attempt,
            'retry_safe' => false,
        ];
        if ($accepted) {
            $details = [...$details, ...$journal['diagnostics']];
            $activityOutcome = $actualState === 'completed' ? 'success'
                : ($actualState === 'outcome_unknown' ? 'unknown' : 'failure');
            $activityOperation = 'target-batch-'.$batch->capability_key;
        } else {
            // The journal has already been reconciled. Retain the separate
            // provider observation without changing the authoritative outcome
            // or authorizing a replay.
            $details = [
                ...$details, ...$journal['diagnostics'], 'failure_stage' => 'batch_reconciliation',
                'late_response_after_lease' => $actualError === 'dispatch_lease_expired',
                'late_provider_status' => $journal['provider_status'],
                'authoritative_status' => $actualState,
                'authoritative_error_code' => $actualError,
                'effect_unconfirmed' => ! $journal['never_admitted'],
            ];
            $activityOutcome = $journal['never_admitted'] ? 'failure' : 'unknown';
            $activityOperation = 'target-batch-late-result';
        }

        // The worker has no HTTP request. Restore the *persisted* originating
        // User/Client identity explicitly, without bearer or refresh tokens.
        // Diagnostics remain best-effort; finalized Journal truth is not.
        try {
            $this->activity->record(
                $reference, $activityOperation, $activityOutcome,
                $target, $accepted ? $actualError : 'late_result_ignored',
                $details, ActivityAttribution::fromBatch($batch),
            );
        } catch (Throwable $exception) {
            // A corrupt provenance witness cannot roll back a remote effect.
            // The durable journal stays authoritative and the worker returns
            // its persisted state, not a fabricated local result.
            OperationDiagnostics::failure(
                'target-batch-attribution', 'batch_diagnostic_unavailable', $target, [
                    'batch_id' => $batch->id, 'batch_child_id' => $item->id,
                    'exception_class' => $exception::class,
                ], $reference,
            );
        }

        return [
            'batch_id' => $batch->id, 'target_id' => $item->target_id_snapshot,
            'status' => $actualState, 'error_code' => $actualError,
            'diagnostic_reference' => $journal['diagnostic_reference'] ?? $reference,
        ];
    }
}
