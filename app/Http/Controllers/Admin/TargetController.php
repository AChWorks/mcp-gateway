<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Admin\TargetConnectorAdmin;
use App\Application\Targets\TargetConnectorAdapter;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorRegistry;
use App\Application\Targets\TargetEnrollmentPreflight;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use App\Support\TargetFormInput;
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
    public function index(Request $request, TargetInventory $inventory, TargetConnectorAdmin $connectorAdmin, TargetConnectorRegistry $connectors): View
    {
        Gate::authorize(GatewayPermission::TargetsView->value);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:160'],
            'connection_state' => ['nullable', 'string', Rule::enum(TargetConnectionState::class)],
            'page' => ['nullable', 'integer', 'min:1'],
            'connector_type' => ['nullable', 'string', Rule::in($connectors->types())],
            'needs_review' => ['nullable', 'boolean'],
        ]);

        $page = (int) ($validated['page'] ?? 1);
        $search = $this->trimmed($validated['search'] ?? null);
        $state = $this->trimmed($validated['connection_state'] ?? null);
        $connectorType = $this->trimmed($validated['connector_type'] ?? null);
        $needsReview = $request->boolean('needs_review');

        $pageData = $inventory->adminPage($user, $page, $search, $state, $connectorType, needsReview: $needsReview);
        $presentations = $connectorAdmin->inventory($pageData['items']);

        return view('admin.targets.index', [
            'inventory' => $pageData,
            'presentations' => $presentations,
            'filters' => [
                'search' => $search, 'connection_state' => $state,
                'connector_type' => $connectorType, 'needs_review' => $needsReview,
            ],
            'connectorOptions' => array_combine($connectors->types(), array_map($connectorAdmin->label(...), $connectors->types())),
            'connectionStates' => TargetConnectionState::cases(),
            'baseQuery' => array_filter([
                'search' => $search,
                'connection_state' => $state,
                'connector_type' => $connectorType,
                'needs_review' => $needsReview ? '1' : null,
            ], static fn (?string $value): bool => $value !== null),
        ]);
    }

    public function create(Request $request, TargetConnectorAdmin $connectorAdmin): View
    {
        Gate::authorize(GatewayPermission::TargetsCreate->value);

        $options = $connectorAdmin->options();
        $definitions = [];
        foreach (array_keys($options) as $type) {
            $definitions[] = $connectorAdmin->forType($type)?->definition();
        }
        $requested = $request->query('connector_type');
        $selected = is_string($requested) && array_key_exists($requested, $options) ? $requested : '';
        $requestedMode = $request->query('ssh_mode', 'direct');
        $sshMode = in_array($requestedMode, ['direct', 'managed', 'manual'], true)
            ? $requestedMode : 'direct';
        if ($sshMode !== 'direct' && $selected === 'ssh_direct') {
            Gate::authorize(GatewayPermission::SecurityManage->value);
            abort_unless($request->user()?->getRawOriginal('role') === GatewayRole::Owner->value, 403);
        }

        return view('admin.targets.create', [
            'connectorOptions' => $options,
            'connectorDefinitions' => $definitions,
            'selectedConnector' => $selected,
            'sshMode' => $sshMode,
            'managedConfigured' => SshManagedReverseGateway::active(),
        ]);
    }

    /**
     * One authenticated enrollment preflight path for all supported connector
     * families. Each adapter opts in and owns its protocol validation; neither
     * submitted field names nor a connector label can choose an arbitrary probe.
     */
    public function preflight(Request $request, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsCreate->value);

        $adapter = null;
        $selected = $request->input('connector_type');
        $query = is_string($selected) && in_array($selected, $connectors->types(), true)
            ? ['connector_type' => $selected] : [];

        try {
            $choice = $request->validate([
                'connector_type' => ['required', Rule::in($connectors->types())],
            ]);
            $adapter = $connectors->forType((string) $choice['connector_type']);
            if (! $adapter instanceof TargetEnrollmentPreflight) {
                throw ValidationException::withMessages([
                    'connector_type' => __('This connector does not support endpoint preflight.'),
                ]);
            }
            $validated = $request->validate($adapter->preflightRules());
        } catch (ValidationException $exception) {
            if ($request->expectsJson()) {
                throw $exception;
            }

            return redirect()->route('admin.targets.create', $query)
                ->withInput($this->safeOldInput($request, $adapter))
                ->withErrors($exception->errors())
                ->with('target_preflight_validation_failed', true);
        }

        try {
            $checked = $adapter->preflight($validated);
            $result = [
                'ok' => true,
                'message' => $checked->message,
                'limitation' => $checked->limitation,
                'checked_subject' => $checked->checkedSubject,
                'checked_connector' => $adapter->type(),
                'checked_fields' => $checked->checkedFields,
            ];
        } catch (TargetConnectorFailure $exception) {
            $code = $exception->reason ?? 'invalid_input';
            // DNS is an observation, never a remote operation. No new Target,
            // credential or authorized connection is created, even on success.
            $context = [
                ...$exception->diagnostics,
                'pre_dispatch' => true,
                'retry_safe' => true,
            ];
            $reference = OperationDiagnostics::failure('target-endpoint-preflight-'.$adapter->type(), $code, null, $context);
            $result = [
                'ok' => false,
                'message' => $exception->getMessage(),
                'next_step' => OperationDiagnostics::nextStep($code, $context),
                'reference' => $reference,
            ];
        }

        return redirect()->route('admin.targets.create', $query)
            ->withInput($this->safeOldInput($request, $adapter))
            ->with('target_endpoint_preflight', $result);
    }

    public function store(
        Request $request,
        TargetConnectorRegistry $connectors,
        AccessControl $access,
        AdministratorPasswordConfirmation $confirmation,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsCreate->value);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        // Validate the actual connector type before its own fields. This avoids
        // making unrelated connector fields mandatory for every new adapter.
        $adapter = null;
        $selected = $request->input('connector_type');
        $createQuery = is_string($selected) && in_array($selected, $connectors->types(), true)
            ? ['connector_type' => $selected] : [];
        if ($selected === 'ssh_direct' && $request->input('ssh_mode') === 'manual') {
            $createQuery['ssh_mode'] = 'manual';
        }
        try {
            $choice = $request->validate([
                'connector_type' => ['required', Rule::in($connectors->types())],
            ]);
            $adapter = $connectors->forType((string) $choice['connector_type']);
            if ($adapter->type() === 'ssh_direct' && $request->input('ssh_mode') === 'managed') {
                throw ValidationException::withMessages([
                    'ssh_mode' => __('For Managed Reverse SSH, open the selected Managed connection mode and use Create Pending Setup. No Target was registered.'),
                ]);
            }
            $validated = $request->validate([
                'target_id' => ['required', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
                'display_name' => ['required', 'string', 'max:160'],
                'ai_guidance' => ['nullable', 'string', 'max:'.Target::AI_GUIDANCE_MAX_LENGTH,
                    'not_regex:/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]/'],
                ...$adapter->registrationRules(),
            ]);
            if ($adapter->type() === 'ssh_direct'
                && ($validated['ssh_route_mode'] ?? 'direct') === 'reverse') {
                // Enrollment over an inbound-blocked route is an explicit
                // Owner/password-gated act, not an Administrator's ordinary
                // TargetsCreate permission.
                Gate::authorize(GatewayPermission::SecurityManage->value);
                $confirmation->confirm($request);
            }
        } catch (ValidationException $exception) {
            // No SSH private key, password or passphrase in session old input.
            // Preserve JSON validation behavior for API-shaped requests.
            if ($request->expectsJson()) {
                throw $exception;
            }

            $context = ['failure_origin' => 'gateway_admission', 'failure_stage' => 'admission', 'pre_dispatch' => true];
            $reference = OperationDiagnostics::failure('target-registration', 'invalid_input', null, $context);

            return redirect()->route('admin.targets.create', $createQuery)
                ->withInput($this->safeOldInput($request, $adapter))
                ->withErrors($exception->errors())
                ->with('diagnostic_code', 'invalid_input')
                ->with('diagnostic_context', $context)
                ->with('diagnostic_reference', $reference);
        }

        try {
            $target = $adapter->register($validated);
        } catch (TargetConnectorFailure $exception) {
            $code = $exception->reason ?? 'registration_rejected';
            // An adapter can establish whether an outbound request happened;
            // this connector-neutral boundary cannot. In particular, WP
            // discovery may have received an HTTP response already.
            $context = [
                'failure_origin' => 'unknown',
                'failure_stage' => 'operation',
                ...$exception->diagnostics,
            ];
            $reference = OperationDiagnostics::failure('target-registration', $code, null, $context);

            return redirect()->route('admin.targets.create', $createQuery)
                ->withInput($this->safeOldInput($request, $adapter))
                ->withErrors([$exception->field ?? 'target_id' => $exception->getMessage()])
                ->with('diagnostic_code', $code)
                ->with('diagnostic_context', OperationDiagnostics::safeContext($context))
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

    public function show(Target $target, TargetConnectorRegistry $connectors, TargetConnectorAdmin $connectorAdmin): View
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

        $presenter = $connectorAdmin->forType($target->connector_type);
        $details = $adapter?->adminDetails($target) ?? [];

        return view('admin.targets.show', [
            'target' => $target,
            'connectorUi' => $presenter?->definition(),
            'canRemoveSafely' => $canRemoveSafely,
            ...$details,
            'recovery' => $presenter?->recovery($target, $details)
                ?? TargetRecoveryPresentation::describe($target),
        ]);
    }

    public function edit(Target $target, TargetConnectorRegistry $connectors, TargetConnectorAdmin $connectorAdmin): View
    {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);

        $adapter = Gate::allows(GatewayPermission::SecurityManage->value)
            ? $connectors->availableForTarget($target) : null;

        $details = $adapter?->adminDetails($target) ?? [];
        $presenter = $connectorAdmin->forType($target->connector_type);
        $hasConfig = $presenter?->hasConfiguration($details) ?? false;

        return view('admin.targets.edit', [
            'target' => $target,
            'configurationRevision' => $hasConfig ? $adapter?->configurationRevision($target) : null,
            'connectorUi' => $presenter?->definition(),
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

                if (SshManagedReverseEnrollment::query()
                    ->where('target_record_id', $id)
                    ->where(static fn ($query) => $query->where('state', '!=', 'revoked')
                        ->orWhere('publication_pending', true))->exists()
                    || TargetCredential::query()->where('target_record_id', $id)->exists()
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
        // A local-only forget must not leave a live control key installed in
        // the host reader file after the enrollment DB row cascades away.
        if (SshManagedReverseEnrollment::query()
            ->where('target_record_id', $target->getKey())
            ->where(static fn ($query) => $query->where('state', '!=', 'revoked')
                ->orWhere('publication_pending', true))->exists()) {
            throw ValidationException::withMessages([
                'target' => __('Revoke the managed Reverse SSH route first. Forgetting locally cannot silently leave its host control key active.'),
            ]);
        }

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
        return TargetFormInput::replayable($request, [
            'connector_type',
            'ssh_mode',
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
