<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorRegistry;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
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

        return view('admin.targets.index', [
            'inventory' => $inventory->adminPage($user, $page, $search, $state),
            'filters' => ['search' => $search, 'connection_state' => $state],
            'connectionStates' => TargetConnectionState::cases(),
            'baseQuery' => array_filter([
                'search' => $search,
                'connection_state' => $state,
            ], static fn (?string $value): bool => $value !== null),
        ]);
    }

    public function create(): View
    {
        Gate::authorize(GatewayPermission::TargetsCreate->value);

        // Enrollment only presents implemented connector-specific forms.
        return view('admin.targets.create');
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
        try {
            $choice = $request->validate([
                'connector_type' => ['required', Rule::in($connectors->types())],
            ]);
            $adapter = $connectors->forType((string) $choice['connector_type']);
            $validated = $request->validate([
                'target_id' => ['required', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
                'display_name' => ['required', 'string', 'max:160'],
                ...$adapter->registrationRules(),
            ]);
        } catch (ValidationException $exception) {
            // No SSH private key, password or passphrase in session old input.
            // Preserve JSON validation behavior for API-shaped requests.
            if ($request->expectsJson()) {
                throw $exception;
            }

            return back()->withInput($this->safeOldInput($request))->withErrors($exception->errors());
        }

        try {
            $target = $adapter->register($validated);
        } catch (TargetConnectorFailure $exception) {
            return back()->withInput($this->safeOldInput($request))
                ->withErrors([$exception->field ?? 'target_id' => $exception->getMessage()]);
        }

        $access->includeCreatedTarget($user, $target);

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', $adapter->registrationStatus());
    }

    public function show(Target $target, TargetConnectorRegistry $connectors): View
    {
        Gate::authorize(GatewayPermission::TargetsView->value, $target);

        $adapter = $connectors->forTarget($target);
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
            'refreshIntent' => null,
            'refreshPending' => false,
            'canRemoveSafely' => $canRemoveSafely,
            ...$adapter->adminDetails($target),
        ]);
    }

    public function edit(Target $target): View
    {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);

        return view('admin.targets.edit', ['target' => $target]);
    }

    public function update(Request $request, Target $target): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);
        $validated = $request->validate([
            'display_name' => ['required', 'string', 'max:160'],
        ]);

        DB::transaction(static function () use ($target, $validated): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $locked->forceFill(['display_name' => (string) $validated['display_name']])->save();
        });

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', __('Target display name updated.'));
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

    /** @return array<string, mixed> */
    private function safeOldInput(Request $request): array
    {
        return $request->except(['ssh_password', 'ssh_private_key', 'ssh_passphrase']);
    }

    private function trimmed(?string $text): ?string
    {
        $trimmed = $text === null ? null : trim($text);

        return $trimmed === '' ? null : $trimmed;
    }
}
