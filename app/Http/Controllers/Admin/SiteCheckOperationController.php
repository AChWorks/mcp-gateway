<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Sites\SiteCheckOperationException;
use App\Application\Sites\SiteCheckOperationService;
use App\Domain\Access\GatewayPermission;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteCheckOperation;
use App\Domain\Sites\SiteCheckOperationTarget;
use App\Domain\Sites\SiteCheckTargetStatus;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class SiteCheckOperationController extends Controller
{
    public function store(Request $request, SiteCheckOperationService $siteChecks): RedirectResponse
    {
        Gate::authorize(GatewayPermission::ConnectionsTest->value);
        $user = $this->user($request);
        $validated = $request->validate([
            'site_ids' => [
                'required',
                'array',
                'min:'.SiteCheckOperationService::MIN_TARGETS,
                'max:'.SiteCheckOperationService::MAX_TARGETS,
            ],
            'site_ids.*' => ['required', 'string', 'max:64', 'distinct'],
            'idempotency_key' => ['required', 'uuid'],
        ]);

        /** @var list<string> $siteIds */
        $siteIds = array_values($validated['site_ids']);

        try {
            $operation = $siteChecks->start(
                $user,
                $siteIds,
                (string) $validated['idempotency_key'],
            );
        } catch (SiteCheckOperationException $exception) {
            if ($exception->reason === 'active_operation' && $exception->operationId !== null) {
                return redirect()
                    ->route('admin.site-checks.show', ['operation' => $exception->operationId])
                    ->with('status', __('Resume the active bulk site check before starting another.'));
            }

            return back()
                ->withInput()
                ->withErrors(['bulk_check' => $exception->getMessage()]);
        }

        return redirect()
            ->route('admin.site-checks.show', ['operation' => $operation->getKey()])
            ->with('status', __('Bulk site check created. Run the next check when ready.'));
    }

    public function show(
        Request $request,
        SiteCheckOperation $operation,
        SiteCheckOperationService $siteChecks,
        AccessControl $access,
    ): View {
        Gate::authorize(GatewayPermission::ConnectionsTest->value);
        $user = $this->user($request);
        $this->assertOwned($siteChecks, $user, $operation);

        $targets = $operation->targets()->orderBy('position')->get();
        $siteRecordIds = $targets
            ->pluck('site_record_id')
            ->filter(static fn ($value): bool => is_string($value) && $value !== '')
            ->values()
            ->all();

        $visibleSiteRecordIds = $siteRecordIds === []
            ? collect()
            : $access
                ->scopeSites(
                    Site::query()->select('id'),
                    $user,
                    GatewayPermission::ConnectionsTest,
                )
                ->whereIn('id', $siteRecordIds)
                ->pluck('id')
                ->map(static fn ($id): string => (string) $id)
                ->flip();

        $targetViews = $targets->map(static function (SiteCheckOperationTarget $target) use ($visibleSiteRecordIds): array {
            $siteRecordId = $target->site_record_id === null ? null : (string) $target->site_record_id;
            $visible = $siteRecordId !== null && $visibleSiteRecordIds->has($siteRecordId);
            $status = $target->statusValue();
            [$statusLabel, $statusTone] = match ($status) {
                SiteCheckTargetStatus::Pending => [(string) __('Pending'), 'neutral'],
                SiteCheckTargetStatus::Running => [(string) __('Running'), 'warning'],
                SiteCheckTargetStatus::Succeeded => [(string) __('Succeeded'), 'success'],
                SiteCheckTargetStatus::Failed => [(string) __('Failed'), 'danger'],
                SiteCheckTargetStatus::AuthorizationBlocked => [(string) __('Access blocked'), 'warning'],
                SiteCheckTargetStatus::Missing => [(string) __('Site unavailable'), 'danger'],
                SiteCheckTargetStatus::Interrupted => [(string) __('Interrupted'), 'warning'],
            };

            return [
                'target' => $target,
                'visible' => $visible,
                'display_name' => $visible ? $target->display_name_snapshot : null,
                'site_id' => $visible ? $target->site_id_snapshot : null,
                'status_label' => $statusLabel,
                'status_tone' => $statusTone,
                'retryable' => $visible
                    && $status->isRetryable()
                    && $target->attempts < SiteCheckOperationService::MAX_ATTEMPTS,
            ];
        });

        return view('admin.site-checks.show', [
            'operation' => $operation->refresh(),
            'targets' => $targetViews,
            'summary' => $siteChecks->summary($operation),
            'maxAttempts' => SiteCheckOperationService::MAX_ATTEMPTS,
        ]);
    }

    public function advance(
        Request $request,
        SiteCheckOperation $operation,
        SiteCheckOperationService $siteChecks,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::ConnectionsTest->value);
        $user = $this->user($request);
        $this->assertOwned($siteChecks, $user, $operation);

        $siteChecks->advance($user, $operation);

        return redirect()
            ->route('admin.site-checks.show', ['operation' => $operation->getKey()]);
    }

    public function retry(
        Request $request,
        SiteCheckOperation $operation,
        SiteCheckOperationTarget $target,
        SiteCheckOperationService $siteChecks,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::ConnectionsTest->value);
        $user = $this->user($request);
        $this->assertOwned($siteChecks, $user, $operation);

        try {
            $siteChecks->retry($user, $operation, $target);
        } catch (SiteCheckOperationException $exception) {
            if ($exception->reason === 'active_operation' && $exception->operationId !== null) {
                return redirect()
                    ->route('admin.site-checks.show', ['operation' => $exception->operationId])
                    ->withErrors(['bulk_check' => __('Finish the active bulk site check before retrying this one.')]);
            }

            return redirect()
                ->route('admin.site-checks.show', ['operation' => $operation->getKey()])
                ->withErrors(['bulk_check' => $exception->getMessage()]);
        }

        return redirect()
            ->route('admin.site-checks.show', ['operation' => $operation->getKey()])
            ->with('status', __('Target queued for an explicit retry.'));
    }

    private function assertOwned(
        SiteCheckOperationService $siteChecks,
        User $user,
        SiteCheckOperation $operation,
    ): void {
        try {
            $siteChecks->assertOwned($user, $operation);
        } catch (SiteCheckOperationException) {
            abort(404);
        }
    }

    private function user(Request $request): User
    {
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        return $user;
    }
}
