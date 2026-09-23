<?php

namespace App\Application\Sites;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteCheckOperation;
use App\Domain\Sites\SiteCheckOperationStatus;
use App\Domain\Sites\SiteCheckOperationTarget;
use App\Domain\Sites\SiteCheckTargetStatus;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

final readonly class SiteCheckOperationService
{
    public const MIN_TARGETS = 2;

    public const MAX_TARGETS = SiteInventory::ADMIN_PAGE_SIZE;

    public const MAX_ATTEMPTS = 3;

    public const RETENTION_DAYS = 30;

    public function __construct(
        private AccessControl $access,
        private SiteRegistry $registry,
        private ActivityRecorder $activity,
    ) {}

    /**
     * @param list<string> $siteIds
     */
    public function start(User $creator, array $siteIds, string $idempotencyKey): SiteCheckOperation
    {
        $siteIds = $this->normalizedSiteIds($siteIds);
        if (! Str::isUuid($idempotencyKey)) {
            throw new SiteCheckOperationException('invalid_idempotency_key', 'The bulk-check request identity is invalid.');
        }

        $this->pruneCompleted();

        return DB::transaction(function () use ($creator, $siteIds, $idempotencyKey): SiteCheckOperation {
            $lockedCreator = User::query()->whereKey($creator->getKey())->lockForUpdate()->first();
            if (! $lockedCreator instanceof User || ! (bool) $lockedCreator->access_enabled) {
                throw new SiteCheckOperationException('creator_unavailable', 'The operator account is not available.');
            }

            $existing = SiteCheckOperation::query()
                ->where('creator_user_id', $lockedCreator->getKey())
                ->where('idempotency_key', $idempotencyKey)
                ->first();
            if ($existing instanceof SiteCheckOperation) {
                $existingSiteIds = $existing->targets()
                    ->orderBy('position')
                    ->pluck('site_id_snapshot')
                    ->map(static fn ($siteId): string => (string) $siteId)
                    ->all();

                if ($existingSiteIds !== $siteIds) {
                    throw new SiteCheckOperationException(
                        'idempotency_conflict',
                        'The bulk-check request identity was already used for a different target selection.',
                    );
                }

                return $existing;
            }

            $active = SiteCheckOperation::query()
                ->where('creator_user_id', $lockedCreator->getKey())
                ->where('active_slot', 1)
                ->first();
            if ($active instanceof SiteCheckOperation) {
                throw new SiteCheckOperationException(
                    'active_operation',
                    'Finish or resume the existing bulk site check before starting another.',
                    (string) $active->getKey(),
                );
            }

            $sites = $this->access
                ->scopeSites(
                    Site::query()->select(['id', 'site_id', 'display_name']),
                    $lockedCreator,
                    GatewayPermission::ConnectionsTest,
                )
                ->whereIn('site_id', $siteIds)
                ->get()
                ->keyBy('site_id');

            if ($sites->count() !== count($siteIds)) {
                throw new SiteCheckOperationException(
                    'invalid_target_selection',
                    'One or more selected sites are unavailable or not authorized for connection testing.',
                );
            }

            $operation = SiteCheckOperation::query()->create([
                'creator_user_id' => $lockedCreator->getKey(),
                'idempotency_key' => $idempotencyKey,
                'active_slot' => 1,
                'status' => SiteCheckOperationStatus::Pending,
            ]);

            $createdAt = now();
            $targetRows = [];
            foreach ($siteIds as $offset => $siteId) {
                $site = $sites->get($siteId);
                if (! $site instanceof Site) {
                    throw new SiteCheckOperationException(
                        'invalid_target_selection',
                        'One or more selected sites are unavailable or not authorized for connection testing.',
                    );
                }

                $targetRows[] = [
                    'id' => (string) Str::ulid(),
                    'operation_id' => $operation->getKey(),
                    'site_record_id' => $site->getKey(),
                    'position' => $offset + 1,
                    'site_id_snapshot' => $site->site_id,
                    'display_name_snapshot' => $site->display_name,
                    'status' => SiteCheckTargetStatus::Pending->value,
                    'attempts' => 0,
                    'created_at' => $createdAt,
                    'updated_at' => $createdAt,
                ];
            }
            SiteCheckOperationTarget::query()->insert($targetRows);

            return $operation->refresh();
        }, 3);
    }

    public function activeFor(User $creator): ?SiteCheckOperation
    {
        return SiteCheckOperation::query()
            ->where('creator_user_id', $creator->getKey())
            ->where('active_slot', 1)
            ->latest('created_at')
            ->first();
    }

    public function advance(User $actor, SiteCheckOperation $operation): SiteCheckOperation
    {
        $claim = DB::transaction(function () use ($actor, $operation): ?array {
            $lockedOperation = SiteCheckOperation::query()->whereKey($operation->getKey())->lockForUpdate()->firstOrFail();
            $this->assertOwned($actor, $lockedOperation);

            $this->markStaleRunningTargets($lockedOperation);

            if ($lockedOperation->statusValue() === SiteCheckOperationStatus::Completed
                && $lockedOperation->active_slot === null) {
                return null;
            }

            if (SiteCheckOperationTarget::query()
                ->where('operation_id', $lockedOperation->getKey())
                ->where('status', SiteCheckTargetStatus::Running->value)
                ->exists()) {
                return null;
            }

            $target = SiteCheckOperationTarget::query()
                ->where('operation_id', $lockedOperation->getKey())
                ->where('status', SiteCheckTargetStatus::Pending->value)
                ->orderBy('position')
                ->lockForUpdate()
                ->first();

            if (! $target instanceof SiteCheckOperationTarget) {
                $this->finalizeIfIdle($lockedOperation);

                return null;
            }

            $attemptToken = (string) Str::uuid();
            $startedAt = now();
            $target->forceFill([
                'status' => SiteCheckTargetStatus::Running,
                'attempt_token' => $attemptToken,
                'error_code' => null,
                'started_at' => $startedAt,
                'finished_at' => null,
            ])->save();

            $lockedOperation->forceFill([
                'status' => SiteCheckOperationStatus::Running,
                'active_slot' => 1,
                'started_at' => $lockedOperation->started_at ?? $startedAt,
                'completed_at' => null,
            ])->save();

            return [
                'operation_id' => (string) $lockedOperation->getKey(),
                'target_id' => (string) $target->getKey(),
                'attempt_token' => $attemptToken,
                'creator_user_id' => (int) $lockedOperation->creator_user_id,
                'site_record_id' => $target->site_record_id === null ? null : (string) $target->site_record_id,
                'site_id' => (string) $target->site_id_snapshot,
            ];
        }, 3);

        if (! is_array($claim)) {
            return $operation->refresh();
        }

        $this->executeClaim($claim);

        return $operation->refresh();
    }

    public function retry(
        User $actor,
        SiteCheckOperation $operation,
        SiteCheckOperationTarget $target,
    ): SiteCheckOperation {
        return DB::transaction(function () use ($actor, $operation, $target): SiteCheckOperation {
            $lockedCreator = User::query()->whereKey($actor->getKey())->lockForUpdate()->first();
            if (! $lockedCreator instanceof User || ! (bool) $lockedCreator->access_enabled) {
                throw new SiteCheckOperationException('creator_unavailable', 'The operator account is not available.');
            }

            $lockedOperation = SiteCheckOperation::query()->whereKey($operation->getKey())->lockForUpdate()->firstOrFail();
            $this->assertOwned($lockedCreator, $lockedOperation);

            $lockedTarget = SiteCheckOperationTarget::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            if ((string) $lockedTarget->operation_id !== (string) $lockedOperation->getKey()) {
                throw new SiteCheckOperationException('target_mismatch', 'The selected target does not belong to this bulk check.');
            }

            $status = $lockedTarget->statusValue();
            if (! $status->isRetryable()
                || $lockedTarget->attempts >= self::MAX_ATTEMPTS) {
                throw new SiteCheckOperationException('retry_unavailable', 'This target is not eligible for another retry.');
            }

            $otherActive = SiteCheckOperation::query()
                ->where('creator_user_id', $lockedCreator->getKey())
                ->where('active_slot', 1)
                ->where($lockedOperation->getKeyName(), '!=', $lockedOperation->getKey())
                ->first();
            if ($otherActive instanceof SiteCheckOperation) {
                throw new SiteCheckOperationException(
                    'active_operation',
                    'Finish or resume the existing bulk site check before retrying this one.',
                    (string) $otherActive->getKey(),
                );
            }

            $lockedTarget->forceFill([
                'status' => SiteCheckTargetStatus::Pending,
                'attempt_token' => null,
                'error_code' => null,
                'started_at' => null,
                'finished_at' => null,
            ])->save();

            $lockedOperation->forceFill([
                'status' => SiteCheckOperationStatus::Running,
                'active_slot' => 1,
                'completed_at' => null,
            ])->save();

            return $lockedOperation->refresh();
        }, 3);
    }

    public function assertOwned(User $actor, SiteCheckOperation $operation): void
    {
        if ((string) $operation->creator_user_id !== (string) $actor->getKey()) {
            throw new SiteCheckOperationException('not_owned', 'The bulk site check is not available to this operator.');
        }
    }

    /**
     * @return array{
     *     total:int,
     *     pending:int,
     *     running:int,
     *     succeeded:int,
     *     failed:int,
     *     authorization_blocked:int,
     *     missing:int,
     *     interrupted:int
     * }
     */
    public function summary(SiteCheckOperation $operation): array
    {
        $counts = SiteCheckOperationTarget::query()
            ->where('operation_id', $operation->getKey())
            ->selectRaw('status, COUNT(*) AS aggregate')
            ->groupBy('status')
            ->pluck('aggregate', 'status')
            ->map(static fn ($value): int => (int) $value);

        $value = static fn (SiteCheckTargetStatus $status): int => (int) ($counts[$status->value] ?? 0);

        return [
            'total' => $counts->sum(),
            'pending' => $value(SiteCheckTargetStatus::Pending),
            'running' => $value(SiteCheckTargetStatus::Running),
            'succeeded' => $value(SiteCheckTargetStatus::Succeeded),
            'failed' => $value(SiteCheckTargetStatus::Failed),
            'authorization_blocked' => $value(SiteCheckTargetStatus::AuthorizationBlocked),
            'missing' => $value(SiteCheckTargetStatus::Missing),
            'interrupted' => $value(SiteCheckTargetStatus::Interrupted),
        ];
    }

    /**
     * @param array{
     *     operation_id:string,
     *     target_id:string,
     *     attempt_token:string,
     *     creator_user_id:int,
     *     site_record_id:?string,
     *     site_id:string
     * } $claim
     */
    private function executeClaim(array $claim): void
    {
        $creator = User::query()->find($claim['creator_user_id']);
        if (! $creator instanceof User || ! (bool) $creator->access_enabled) {
            $this->recordAndComplete(
                $claim,
                SiteCheckTargetStatus::AuthorizationBlocked,
                'blocked',
                'creator_unavailable',
            );

            return;
        }

        $site = $claim['site_record_id'] === null
            ? null
            : Site::query()->find($claim['site_record_id']);
        if (! $site instanceof Site) {
            $this->recordAndComplete(
                $claim,
                SiteCheckTargetStatus::Missing,
                'failure',
                'target_missing',
            );

            return;
        }

        if (! $this->access->allows($creator, GatewayPermission::ConnectionsTest, $site)) {
            $this->recordAndComplete(
                $claim,
                SiteCheckTargetStatus::AuthorizationBlocked,
                'blocked',
                'authorization_revoked',
            );

            return;
        }

        if (! $this->beginRemoteAttempt($claim)) {
            $this->recordAndComplete(
                $claim,
                SiteCheckTargetStatus::Failed,
                'failure',
                'attempt_limit_reached',
            );

            return;
        }

        try {
            $this->registry->test($site);
        } catch (SiteConnectionException $exception) {
            $this->recordAndComplete(
                $claim,
                SiteCheckTargetStatus::Failed,
                'failure',
                $exception->reason,
            );

            return;
        }

        $this->recordAndComplete(
            $claim,
            SiteCheckTargetStatus::Succeeded,
            'success',
            null,
        );
    }

    /**
     * @param array{
     *     operation_id:string,
     *     target_id:string,
     *     attempt_token:string,
     *     creator_user_id:int,
     *     site_record_id:?string,
     *     site_id:string
     * } $claim
     */
    private function beginRemoteAttempt(array $claim): bool
    {
        return DB::transaction(function () use ($claim): bool {
            $target = SiteCheckOperationTarget::query()
                ->whereKey($claim['target_id'])
                ->where('operation_id', $claim['operation_id'])
                ->lockForUpdate()
                ->first();

            if (! $target instanceof SiteCheckOperationTarget
                || $target->statusValue() !== SiteCheckTargetStatus::Running
                || ! is_string($target->attempt_token)
                || ! hash_equals($target->attempt_token, $claim['attempt_token'])
                || $target->attempts >= self::MAX_ATTEMPTS) {
                return false;
            }

            $target->forceFill([
                'attempts' => $target->attempts + 1,
                'updated_at' => now(),
            ])->save();

            return true;
        }, 3);
    }

    /**
     * @param array{
     *     operation_id:string,
     *     target_id:string,
     *     attempt_token:string,
     *     creator_user_id:int,
     *     site_record_id:?string,
     *     site_id:string
     * } $claim
     */
    private function recordAndComplete(
        array $claim,
        SiteCheckTargetStatus $status,
        string $activityOutcome,
        ?string $errorCode,
    ): void {
        $errorCode = $this->safeErrorCode($errorCode);
        $applied = DB::transaction(function () use ($claim, $status, $errorCode): bool {
            $operation = SiteCheckOperation::query()
                ->whereKey($claim['operation_id'])
                ->lockForUpdate()
                ->first();
            if (! $operation instanceof SiteCheckOperation) {
                return false;
            }

            $target = SiteCheckOperationTarget::query()
                ->whereKey($claim['target_id'])
                ->where('operation_id', $operation->getKey())
                ->lockForUpdate()
                ->first();
            if (! $target instanceof SiteCheckOperationTarget
                || $target->statusValue() !== SiteCheckTargetStatus::Running
                || ! is_string($target->attempt_token)
                || ! hash_equals($target->attempt_token, $claim['attempt_token'])) {
                return false;
            }

            $target->forceFill([
                'status' => $status,
                'attempt_token' => null,
                'error_code' => $errorCode,
                'finished_at' => now(),
            ])->save();

            $this->finalizeIfIdle($operation);

            return true;
        }, 3);

        if ($applied) {
            $this->activity->record(
                $claim['operation_id'],
                'bulk-site-connection-test',
                $activityOutcome,
                $claim['site_id'],
                $errorCode,
            );
        }
    }

    private function finalizeIfIdle(SiteCheckOperation $operation): void
    {
        $hasOpenTarget = SiteCheckOperationTarget::query()
            ->where('operation_id', $operation->getKey())
            ->whereIn('status', [
                SiteCheckTargetStatus::Pending->value,
                SiteCheckTargetStatus::Running->value,
            ])
            ->exists();

        if ($hasOpenTarget) {
            $operation->forceFill([
                'status' => SiteCheckOperationStatus::Running,
                'active_slot' => 1,
                'completed_at' => null,
            ])->save();

            return;
        }

        $operation->forceFill([
            'status' => SiteCheckOperationStatus::Completed,
            'active_slot' => null,
            'completed_at' => now(),
        ])->save();
    }

    private function markStaleRunningTargets(SiteCheckOperation $operation): void
    {
        $requestTimeout = max(1, (int) config('bridge.http.request_timeout_seconds', 5));
        $staleAfterSeconds = max(60, ($requestTimeout * 4) + 15);
        $staleBefore = now()->subSeconds($staleAfterSeconds);

        SiteCheckOperationTarget::query()
            ->where('operation_id', $operation->getKey())
            ->where('status', SiteCheckTargetStatus::Running->value)
            ->whereNotNull('started_at')
            ->where('started_at', '<=', $staleBefore)
            ->update([
                'status' => SiteCheckTargetStatus::Interrupted->value,
                'attempt_token' => null,
                'error_code' => 'request_interrupted',
                'finished_at' => now(),
                'updated_at' => now(),
            ]);
    }

    /**
     * @param list<string> $siteIds
     * @return list<string>
     */
    private function normalizedSiteIds(array $siteIds): array
    {
        $normalized = [];
        foreach ($siteIds as $siteId) {
            $value = trim($siteId);
            if ($value === '' || mb_strlen($value) > 64) {
                throw new SiteCheckOperationException('invalid_target_selection', 'The selected site set is invalid.');
            }
            $normalized[] = $value;
        }

        if (count($normalized) < self::MIN_TARGETS
            || count($normalized) > self::MAX_TARGETS
            || count(array_unique($normalized)) !== count($normalized)) {
            throw new SiteCheckOperationException(
                'invalid_target_selection',
                sprintf('Select between %d and %d distinct sites.', self::MIN_TARGETS, self::MAX_TARGETS),
            );
        }

        return $normalized;
    }

    private function pruneCompleted(): void
    {
        $operationIds = SiteCheckOperation::query()
            ->whereNotNull('completed_at')
            ->where('completed_at', '<', now()->subDays(self::RETENTION_DAYS))
            ->orderBy('completed_at')
            ->orderBy('id')
            ->limit(100)
            ->pluck('id');

        if ($operationIds->isNotEmpty()) {
            SiteCheckOperation::query()->whereIn('id', $operationIds)->delete();
        }
    }

    private function safeErrorCode(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = preg_replace('/[^A-Za-z0-9._:-]+/', '_', trim($value)) ?? '';
        $value = trim($value, '_');

        return $value === '' ? 'failure' : mb_substr($value, 0, 64);
    }
}
