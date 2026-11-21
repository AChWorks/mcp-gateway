<?php

namespace App\Application\Batch;

use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Throwable;

/**
 * Connector-neutral, bounded-memory durable Batch journal and admission.
 * No network effect occurs inside a DB transaction; a committed dispatch
 * claim is NEVER automatically requeued after an uncertain worker crash.
 */
final readonly class TargetBatchCoordinator
{
    public function __construct(
        private TargetBatchPlanner $planner,
    ) {}

    /**
     * @param  array<string,mixed>  $origin  Produced only by DeferredBatchAuthority
     * @param  list<string>  $targetIds
     * @param  array<string,mixed>  $arguments
     * @return array<string,mixed>
     */
    public function preview(
        User $user, array $origin, string $capability, array $targetIds,
        array $arguments, string $mode = 'concurrent', bool $stopOnFailure = false,
        int $parallelism = 1,
    ): array {
        return $this->planner->preview(
            $user, $origin, $capability, $targetIds, $arguments, $mode, $stopOnFailure, $parallelism,
        );
    }

    /**
     * @param  array<string,mixed>  $origin
     * @param  list<string>  $targetIds
     * @param  array<string,mixed>  $arguments
     * @return array<string,mixed>
     */
    public function create(
        User $user, array $origin, string $requestId, string $capability,
        array $targetIds, array $arguments, string $previewToken,
        string $mode = 'concurrent', bool $stopOnFailure = false, int $parallelism = 1,
    ): array {
        if (! Str::isUuid($requestId)) {
            throw new InvalidArgumentException('request_id must be a stable UUID.');
        }
        $preview = $this->preview(
            $user, $origin, $capability, $targetIds, $arguments, $mode, $stopOnFailure, $parallelism,
        );
        if (! $this->planner->tokenValid($previewToken, $preview['fingerprint'])) {
            throw new InvalidArgumentException('Batch preview expired or exact Target, binding, operation or arguments changed. Preview again.');
        }
        if ($preview['eligible_count'] === 0) {
            throw new InvalidArgumentException('No currently authorized, connected Target supports this operation.');
        }
        $existing = DB::table('target_batches')
            ->where('actor_user_id', $user->getKey())
            ->where('client_identity_hash', $origin['client_identity_hash'])
            ->where('request_id', $requestId)->first();
        if ($existing !== null) {
            if (! hash_equals((string) $existing->request_fingerprint, $preview['fingerprint'])) {
                throw new InvalidArgumentException('request_id is already bound to a different Batch plan.');
            }

            return $this->summary($existing);
        }

        $id = (string) Str::ulid();
        $now = now();
        try {
            DB::transaction(static function () use (
                $user, $origin, $requestId, $capability, $arguments, $preview,
                $mode, $stopOnFailure, $parallelism, $id, $now,
            ): void {
                DB::table('target_batches')->insert([
                    'id' => $id, 'actor_user_id' => $user->getKey(),
                    'source_channel' => $origin['source_channel'],
                    'client_id' => $origin['client_id'],
                    'client_identity_hash' => $origin['client_identity_hash'],
                    'client_profile_key' => $origin['client_profile_key'],
                    'client_profile_generation' => $origin['client_profile_generation'],
                    'authorization_id' => $origin['authorization_id'],
                    'resource_hash' => $origin['resource_hash'],
                    'request_id' => $requestId,
                    'request_fingerprint' => $preview['fingerprint'],
                    'capability_key' => $capability,
                    'arguments_ciphertext' => Crypt::encryptString(json_encode($arguments, JSON_THROW_ON_ERROR)),
                    'execution_mode' => $mode, 'stop_on_failure' => $stopOnFailure,
                    'parallelism' => $parallelism, 'target_count' => $preview['selected_count'],
                    'status' => 'queued', 'created_at' => $now, 'updated_at' => $now,
                ]);
                // Chunk inserts to avoid SQL parameter and packet limits when
                // selecting hundreds or thousands of recorded Targets.
                $rows = [];
                foreach ($preview['items'] as $position => $item) {
                    $rows[] = [
                        'id' => (string) Str::ulid(), 'batch_id' => $id,
                        'target_record_id' => $item['target_record_id'],
                        'target_id_snapshot' => $item['target_id'],
                        'connector_type_snapshot' => $item['connector_type'] ?? 'unknown',
                        'target_binding_hash' => $item['binding_hash'],
                        'position' => $position, 'status' => $item['status'],
                        'error_code' => $item['error_code'],
                        'created_at' => $now, 'updated_at' => $now,
                        ...($item['status'] === 'blocked' ? ['finished_at' => $now] : []),
                    ];
                    if (count($rows) >= 100) {
                        DB::table('target_batch_items')->insert($rows);
                        $rows = [];
                    }
                }
                if ($rows !== []) {
                    DB::table('target_batch_items')->insert($rows);
                }
            }, 3);
        } catch (QueryException $exception) {
            // An exact concurrent retry may have won the unique request key.
            $existing = DB::table('target_batches')
                ->where('actor_user_id', $user->getKey())
                ->where('client_identity_hash', $origin['client_identity_hash'])
                ->where('request_id', $requestId)->first();
            if ($existing === null) {
                throw $exception;
            }
            if (! hash_equals((string) $existing->request_fingerprint, $preview['fingerprint'])) {
                throw new InvalidArgumentException('Concurrent request_id reused with different Batch input.', previous: $exception);
            }

            return $this->summary($existing);
        }

        return $this->summary(DB::table('target_batches')->where('id', $id)->firstOrFail());
    }

    /** @param array<string,mixed> $origin
     * @return array<string,mixed>
     */
    public function status(User $user, array $origin, string $id, int $offset = 0, int $limit = 50): array
    {
        $batch = $this->owned($user, $origin, $id);
        if ($offset < 0 || $limit < 1 || $limit > 100) {
            throw new InvalidArgumentException('Invalid Batch result window.');
        }
        $rows = DB::table('target_batch_items')->where('batch_id', $batch->id)
            ->orderBy('position')->offset($offset)->limit($limit)->get();
        $items = [];
        foreach ($rows as $item) {
            $result = null;
            if (is_string($item->result_ciphertext) && $item->result_ciphertext !== '') {
                try {
                    $result = json_decode(Crypt::decryptString($item->result_ciphertext), true, 512, JSON_THROW_ON_ERROR);
                } catch (Throwable) {
                    $result = ['unavailable' => 'Encrypted result could not be decoded; do not assume success.'];
                }
            }
            $items[] = [
                'target_id' => $item->target_id_snapshot,
                'status' => $item->status, 'error_code' => $item->error_code,
                'started_at' => $item->started_at, 'finished_at' => $item->finished_at,
                'diagnostic_reference' => $item->diagnostic_reference,
                'result' => $result,
            ];
        }

        return [...$this->summary($batch), 'items' => $items,
            'offset' => $offset, 'next_offset' => $offset + count($items) < (int) $batch->target_count
                ? $offset + count($items) : null];
    }

    /** @param array<string,mixed> $origin
     * @return array<string,mixed>
     */
    public function cancel(User $user, array $origin, string $id): array
    {
        $batch = $this->owned($user, $origin, $id);
        DB::transaction(function () use ($batch): void {
            $current = DB::table('target_batches')->where('id', $batch->id)->lockForUpdate()->first();
            if ($current === null || $current->finished_at !== null) {
                return;
            }
            $now = now();
            DB::table('target_batches')->where('id', $batch->id)->update([
                'cancel_requested_at' => $now, 'status' => 'cancel_requested', 'updated_at' => $now,
            ]);
            // Queued = definitely not dispatched. In-flight means only a
            // cancellation REQUEST, not remote process termination.
            DB::table('target_batch_items')->where('batch_id', $batch->id)->where('status', 'queued')
                ->update(['status' => 'canceled', 'finished_at' => $now, 'updated_at' => $now]);
            DB::table('target_batch_items')->where('batch_id', $batch->id)->where('status', 'dispatching')
                ->update(['status' => 'cancel_requested', 'updated_at' => $now]);
            $this->aggregate($current->id);
        }, 3);

        return $this->summary(DB::table('target_batches')->where('id', $id)->firstOrFail());
    }

    /** @param array<string,mixed> $origin
     * @return array<string,mixed>
     */
    public function list(User $user, array $origin, ?string $cursor = null, int $limit = 20): array
    {
        if ($limit < 1 || $limit > 100 || ($cursor !== null && ! Str::isUlid($cursor))) {
            throw new InvalidArgumentException('Invalid Batch history cursor or page size.');
        }
        $query = DB::table('target_batches')
            ->where('actor_user_id', $user->getKey())
            ->where('source_channel', $origin['source_channel'])
            ->where('client_identity_hash', $origin['client_identity_hash'])
            ->orderByDesc('id');
        if ($cursor !== null) {
            $query->where('id', '<', $cursor);
        }
        $rows = $query->limit($limit + 1)->get();
        $hasMore = $rows->count() > $limit;
        $items = $rows->take($limit)->map(fn ($row): array => $this->summary($row))->all();

        return ['ok' => true, 'batches' => $items,
            'next_cursor' => $hasMore ? $rows->get($limit - 1)->id : null];
    }

    /** @return array<string,mixed> */
    private function summary(object $batch): array
    {
        $counts = DB::table('target_batch_items')->where('batch_id', $batch->id)
            ->selectRaw('status, count(*) as total')->groupBy('status')->pluck('total', 'status')->all();

        return [
            'ok' => true, 'batch_id' => $batch->id, 'capability' => $batch->capability_key,
            'status' => $batch->status, 'execution_mode' => $batch->execution_mode,
            'parallelism' => (int) $batch->parallelism,
            'target_count' => (int) $batch->target_count, 'counts' => $counts,
            'cancel_requested' => $batch->cancel_requested_at !== null,
            'created_at' => $batch->created_at, 'finished_at' => $batch->finished_at,
        ];
    }

    /** @param array<string,mixed> $origin */
    private function owned(User $user, array $origin, string $id): object
    {
        if (! Str::isUlid($id)) {
            throw new InvalidArgumentException('Batch not found or not authorized.');
        }
        $batch = DB::table('target_batches')->where('id', $id)
            ->where('actor_user_id', $user->getKey())
            ->where('source_channel', $origin['source_channel'])
            ->where('client_identity_hash', $origin['client_identity_hash'])->first();
        if ($batch === null) {
            throw new InvalidArgumentException('Batch not found or not authorized.');
        }

        return $batch;
    }

    /** Locked parent context; recompute parent state from real child evidence. */
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
            ? ($batch->cancel_requested_at !== null ? 'cancel_requested' : ($succeeded > 0 ? 'running' : 'queued'))
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
