<?php

namespace App\Infrastructure\Activity;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Models\User;
use App\Support\OperationDiagnostics;
use DateTimeInterface;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;

final readonly class ActivityFeed
{
    public function __construct(private AccessControl $access) {}

    /**
     * @param  array{client_id:string,profile_key:string}|null  $oauthReader
     * @return array{items:list<array<string,mixed>>,page:int,per_page:int,has_more:bool}
     */
    public function page(
        User $user,
        int $page = 1,
        int $perPage = 25,
        ?string $targetId = null,
        ?string $operation = null,
        ?string $correlationId = null,
        bool $failuresOnly = false,
        ?array $oauthReader = null,
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
        if ($correlationId !== null && ! Str::isUuid($correlationId)) {
            throw new InvalidArgumentException('Invalid diagnostic reference.');
        }

        // Activity visibility is the intersection of Target visibility AND
        // current per-Target activity.view. A direct/group activity denial
        // must hide both the Admin row and the new AI diagnostic details.
        $allowedTargets = $this->access->scopeTargets(
            $this->access->scopeTargets(
                Target::query()->select('id'),
                $user,
                GatewayPermission::TargetsView,
            ),
            $user,
            GatewayPermission::ActivityView,
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
                'diagnostic_context',
                'created_at',
            ]);

        // MCP's richer error evidence is isolated to its original OAuth
        // actor AND verified client/profile, even for users with All Targets.
        // The browser Admin Activity feed keeps its existing policy. Only
        // Owner's explicit recovery authority permits cross-actor MCP reads.
        if ($oauthReader !== null && ! $this->access->hasUnrestrictedTargetScope($user)) {
            $query
                ->where('actor_type', 'oauth_user')
                ->where('actor_id', (string) $user->getAuthIdentifier())
                ->where('client_id_hash', hash('sha256', $oauthReader['client_id']))
                ->where('client_profile_key', $oauthReader['profile_key']);
        }

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
                    $this->access->scopeTargets(
                        Target::query()->where('target_id', $targetId),
                        $user,
                        GatewayPermission::TargetsView,
                    ),
                    $user,
                    GatewayPermission::ActivityView,
                )->first(['id']);
                $query->where('target_record_id', $scopedTarget?->getKey() ?? '');
            }
        }

        $query
            ->when($operation !== null, fn ($query) => $query->where('operation', $operation))
            ->when($correlationId !== null, fn ($query) => $query->where('correlation_id', $correlationId))
            ->when($failuresOnly, fn ($query) => $query->whereIn('outcome', ['failure', 'unknown']))
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
            $stored = is_string($row->diagnostic_context)
                ? json_decode($row->diagnostic_context, true) : null;
            $diagnostics = is_array($stored)
                ? OperationDiagnostics::safeContext($stored) : [];
            // Preserve the historical cross-actor Activity metadata feed,
            // without extending it into cross-actor rich provider diagnostics
            // for Operator/Viewer roles. Owner/Admin retains scoped recovery.
            $privileged = in_array($user->getAttribute('role'), [
                GatewayRole::Owner, GatewayRole::Administrator,
            ], true);
            $ownActor = in_array($row->actor_type, ['oauth_user', 'administrator'], true)
                && (string) ($row->actor_id ?? '') === (string) $user->getAuthIdentifier();
            if (! $privileged && ! $ownActor) {
                $diagnostics = [];
            }
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
                'diagnostics' => $diagnostics,
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
