<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\TargetConnectorAdapter;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorRegistry;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use App\Support\TargetRecoveryPresentation;
use DomainException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;
use RuntimeException;

final class TargetController extends Controller
{
    public function index(Request $request, TargetInventory $inventory): View
    {
        Gate::authorize(GatewayPermission::TargetsView->value);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'connection_state' => ['nullable', 'string', Rule::enum(TargetConnectionState::class)],
            'page' => ['nullable', 'integer', 'min:1'],
        ]);

        $page = (int) ($validated['page'] ?? 1);
        $search = $this->trimmed($validated['search'] ?? null);
        $state = $this->trimmed($validated['connection_state'] ?? null);

        $pageData = $inventory->adminPage($user, $page, $search, $state);
        $wpIds = array_map(static fn (Target $target): string => (string) $target->getKey(),
            array_filter($pageData['items'], static fn (Target $target): bool => $target->connector_type === 'wp_ai_bridge'));
        $revokeById = $wpIds === [] ? collect() : DB::table('wp_ai_bridge_revocation_intents')
            ->whereIn('target_record_id', $wpIds)->get()->keyBy('target_record_id');
        $refreshIds = $wpIds === [] ? [] : DB::table('wp_ai_bridge_refresh_intents')
            ->whereIn('target_record_id', $wpIds)->pluck('target_record_id')->all();
        $configById = $wpIds === [] ? collect() : DB::table('wp_ai_bridge_target_configs')
            ->whereIn('target_record_id', $wpIds)
            ->get(['target_record_id', 'metadata_checked_at', 'metadata_reachable'])
            ->keyBy('target_record_id');
        // Only inspect credential presence for Targets on this authorized page.
        // Stored OAuth authorization is not proof of a live remote token.
        $credentialIds = $wpIds === [] ? [] : TargetCredential::query()
            ->whereIn('target_record_id', $wpIds)
            ->where('connector_type', 'wp_ai_bridge')
            ->where('purpose', 'wordpress_oauth')
            ->pluck('target_record_id')->all();
        $recoveries = [];
        foreach ($pageData['items'] as $item) {
            $hasCredential = in_array((string) $item->getKey(), $credentialIds, true);
            $recoveries[$item->target_id] = TargetRecoveryPresentation::describe(
                $item, $revokeById->get($item->getKey()),
                in_array($item->getKey(), $refreshIds, true),
                $hasCredential,
                $configById->get($item->getKey()),
            );
            $recoveries[$item->target_id]['credential_present'] = $hasCredential;
        }

        return view('admin.targets.index', [
            'inventory' => $pageData,
            'recoveries' => $recoveries,
            'filters' => ['search' => $search, 'connection_state' => $state],
            'connectionStates' => TargetConnectionState::cases(),
            'baseQuery' => array_filter([
                'search' => $search,
                'connection_state' => $state,
            ], static fn (?string $value): bool => $value !== null),
        ]);
    }

    public function create(Request $request, TargetConnectorRegistry $connectors): View
    {
        Gate::authorize(GatewayPermission::TargetsCreate->value);

        // Never offer a paused/historical connector for enrollment. A new
        // adapter must also have a reviewed connector-specific form panel.
        $labels = [
            'wp_ai_bridge' => __('WordPress (WP AI Bridge)'),
            'ssh_direct' => __('Direct SSH'),
        ];
        $options = array_intersect_key($labels, array_flip($connectors->types()));
        $requested = $request->query('connector_type');
        $selected = is_string($requested) && array_key_exists($requested, $options) ? $requested : '';

        return view('admin.targets.create', [
            'connectorOptions' => $options,
            'selectedConnector' => $selected,
        ]);
    }

    public function store(
        Request $request,
        TargetConnectorRegistry $connectors,
        AccessControl $access,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsCreate->value);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        // Validate the actual connector type before its own fields. This avoids
        // making unrelated connector fields mandatory for every new adapter.
        $adapter = null;
        try {
            $choice = $request->validate([
                'connector_type' => ['required', Rule::in($connectors->types())],
            ]);
            $adapter = $connectors->forType((string) $choice['connector_type']);
            $validated = $request->validate([
                'target_id' => ['required', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
                'display_name' => ['required', 'string', 'max:160'],
                'ai_guidance' => ['nullable', 'string', 'max:'.Target::AI_GUIDANCE_MAX_LENGTH,
                    'not_regex:/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]/'],
                ...$adapter->registrationRules(),
            ]);
        } catch (ValidationException $exception) {
            // No SSH private key, password or passphrase in session old input.
            // Preserve JSON validation behavior for API-shaped requests.
            if ($request->expectsJson()) {
                throw $exception;
            }

            return back()->withInput($this->safeOldInput($request, $adapter))->withErrors($exception->errors());
        }

        try {
            $target = $adapter->register($validated);
        } catch (TargetConnectorFailure $exception) {
            $code = $exception->reason ?? 'registration_rejected';
            $reference = OperationDiagnostics::failure('target-registration', $code, null, $exception->diagnostics);

            return back()->withInput($this->safeOldInput($request, $adapter))
                ->withErrors([$exception->field ?? 'target_id' => $exception->getMessage()])
                ->with('diagnostic_code', $code)
                ->with('diagnostic_reference', $reference);
        }

        // Enrollment is not an authorization grant. Selected-scope creators
        // cannot inspect or operate the new endpoint until the Owner explicitly
        // assigns it through User -> Target access or an approved Target Group.
        if (! $access->allows($user, GatewayPermission::TargetsView, $target)) {
            return redirect()->route('admin.targets.index')
                ->with('status', $adapter->registrationStatus().' '.__(
                    'Target :id was registered but is outside your permitted scope. Ask an Owner to assign access before using it.',
                    ['id' => $target->target_id],
                ));
        }

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', $adapter->registrationStatus());
    }

    public function show(Target $target, TargetConnectorRegistry $connectors): View
    {
        Gate::authorize(GatewayPermission::TargetsView->value, $target);

        $adapter = $connectors->availableForTarget($target);
        $id = $target->getKey();

        $canRemoveSafely = ! TargetCredential::query()->where('target_record_id', $id)->exists()
            && ! $connectors->hasPendingDeletion($target)
            && ! in_array($target->getAttribute('connection_state'), [
                TargetConnectionState::Connected,
                TargetConnectionState::Pending,
                TargetConnectionState::Reassigning,
            ], true);

        // Keep the current WordPress/SSH Blade keys without leaking connector
        // credentials or teaching this controller their storage protocols.
        return view('admin.targets.show', [
            'target' => $target,
            'wpConfig' => null,
            'sshConfig' => null,
            'sshFingerprint' => null,
            'sshHasCredential' => false,
            'hasCredential' => false,
            'revocationPending' => false,
            'revocationIntent' => null,
            'refreshIntent' => null,
            'refreshPending' => false,
            'canRemoveSafely' => $canRemoveSafely,
            ...($details = $adapter?->adminDetails($target) ?? []),
            'recovery' => TargetRecoveryPresentation::describe(
                $target,
                $details['revocationIntent'] ?? null,
                $details['refreshPending'] ?? false,
                $details['hasCredential'] ?? false,
                $details['wpConfig'] ?? null,
                $details['credentialMetadata'] ?? null,
                $details['oauthFlowPending'] ?? false,
            ),
        ]);
    }

    public function edit(Target $target, TargetConnectorRegistry $connectors): View
    {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);

        $adapter = Gate::allows(GatewayPermission::SecurityManage->value)
            ? $connectors->availableForTarget($target) : null;

        $details = $adapter?->adminDetails($target) ?? [];
        $hasConfig = ($details['sshConfig'] ?? null) !== null || ($details['wpConfig'] ?? null) !== null;

        return view('admin.targets.edit', [
            'target' => $target,
            'configurationRevision' => $hasConfig ? $adapter?->configurationRevision($target) : null,
            ...$details,
        ]);
    }

    public function update(Request $request, Target $target): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);
        $validated = $request->validate([
            'display_name' => ['required', 'string', 'max:160'],
            'ai_guidance' => ['nullable', 'string', 'max:'.Target::AI_GUIDANCE_MAX_LENGTH,
                'not_regex:/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]/'],
        ]);

        DB::transaction(static function () use ($target, $validated): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $fields = ['display_name' => (string) $validated['display_name']];
            if (array_key_exists('ai_guidance', $validated)) {
                $value = $validated['ai_guidance'];
                $fields['ai_guidance'] = is_string($value) && trim($value) !== '' ? trim($value) : null;
            }
            $locked->forceFill($fields)->save();
        });

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', __('Target details updated.'));
    }

    public function destroy(Request $request, Target $target, ActivityRecorder $activity, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsRemove->value, $target);
        $request->validate(['confirm_remove' => ['required', 'in:yes']]);

        try {
            DB::transaction(static function () use ($target, $activity, $connectors): void {
                $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
                $id = $locked->getKey();

                if (TargetCredential::query()->where('target_record_id', $id)->exists()
                    || $connectors->hasPendingDeletion($locked)
                    || in_array($locked->getAttribute('connection_state'), [
                        TargetConnectionState::Connected,
                        TargetConnectionState::Pending,
                        TargetConnectionState::Reassigning,
                    ], true)) {
                    throw new DomainException('connection_cleanup_required');
                }

                $activity->recordRequired(CorrelationId::current(), 'target-remove', 'success', $locked);
                if (! $locked->delete()) {
                    throw new RuntimeException('target_delete_failed');
                }
            });
        } catch (DomainException) {
            return back()->withErrors([
                'target' => __('Disconnect and reconcile any pending connector credential or authorization before removing the Target.'),
            ]);
        }

        return redirect()->route('admin.targets.index')
            ->with('status', __('Target removed.'));
    }

    /**
     * Last-resort Owner action: erase this Target ONLY from Gateway.
     *
     * Never attempt a remote revoke or claim its success. Cascading deletes
     * remove local credentials, intents, configurations and scoped ACLs;
     * the required activity snapshot survives the deleted Target record.
     * No provider I/O occurs under the Target lock (or at all).
     */
    public function forget(
        Request $request,
        Target $target,
        ActivityRecorder $activity,
        AdministratorPasswordConfirmation $confirmation,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsRemove->value, $target);
        Gate::authorize(GatewayPermission::SecurityManage->value);
        $user = $request->user();
        abort_unless($user instanceof User && $user->getRawOriginal('role') === GatewayRole::Owner->value, 403);

        $validated = $request->validate([
            'confirm_target_id' => ['required', 'string', 'max:64'],
            'confirm_local_only' => ['required', 'in:yes'],
            'confirm_remote_revocation_unknown' => ['required', 'in:yes'],
        ]);
        if (! hash_equals($target->target_id, (string) $validated['confirm_target_id'])) {
            throw ValidationException::withMessages([
                'confirm_target_id' => __('Type the exact Target ID to confirm local removal.'),
            ]);
        }
        $confirmation->confirm($request);

        DB::transaction(static function () use ($target, $activity): void {
            // Lock the original immutable record, not a potentially reused
            // public target_id. Deleting/re-enrolling is never permission reuse.
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();

            $activity->recordRequired(
                CorrelationId::current(),
                'target-forget-local',
                'success',
                $locked,
                'remote_revocation_unverified',
            );
            if (! $locked->delete()) {
                throw new RuntimeException('target_local_delete_failed');
            }
        });

        return redirect()->route('admin.targets.index')
            ->with('status', __('Target removed from this Gateway. Remote WordPress OAuth authorization or SSH access was NOT revoked. Revoke it separately at the remote service if still applicable.'));
    }

    /** @return array<string, mixed> */
    private function safeOldInput(
        Request $request,
        ?TargetConnectorAdapter $adapter,
    ): array {
        // Allowlist replayable fields; new connector secrets stay private by
        // default even when the adapter introduces an unfamiliar form field.
        return $request->only([
            'connector_type',
            'target_id',
            'display_name',
            'ai_guidance',
            ...($adapter?->safeOldInputFields() ?? []),
        ]);
    }

    private function trimmed(?string $text): ?string
    {
        $trimmed = $text === null ? null : trim($text);

        return $trimmed === '' ? null : $trimmed;
    }
}
