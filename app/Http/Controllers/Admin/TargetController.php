<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Targets\TargetInventory;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Http\Controllers\Controller;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;
use InvalidArgumentException;

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

        // Only the WordPress connector has its initial registration path yet.
        // Do not present fake enrollment controls for Agent or SSH.
        return view('admin.targets.create');
    }

    public function store(
        Request $request,
        WpAiBridgeTargetRegistration $registration,
        AccessControl $access,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsCreate->value);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $validated = $request->validate([
            'connector_type' => ['required', Rule::in(['wp_ai_bridge'])],
            'target_id' => ['required', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
            'display_name' => ['required', 'string', 'max:160'],
            'base_url' => ['required', 'string', 'url:https', 'max:2048'],
        ]);

        try {
            $target = $registration->register(
                (string) $validated['target_id'],
                (string) $validated['display_name'],
                (string) $validated['base_url'],
            );
        } catch (BridgeDiscoveryException $exception) {
            // Never reflect remote response payload or a requested URL in errors.
            return back()->withInput()->withErrors([
                'base_url' => __('The WordPress connector metadata could not be verified (:reason).', [
                    'reason' => $exception->reason,
                ]),
            ]);
        } catch (InvalidArgumentException) {
            return back()->withInput()->withErrors([
                'target_id' => __('The Target ID or WordPress endpoint is invalid or already registered.'),
            ]);
        }

        $access->includeCreatedTarget($user, $target);

        return redirect()
            ->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', __('WordPress Target registered. Connection authorization is not yet configured.'));
    }

    public function show(Target $target): View
    {
        Gate::authorize(GatewayPermission::TargetsView->value, $target);

        $config = $target->connector_type === 'wp_ai_bridge'
            ? WpAiBridgeTargetConfig::query()->where('target_record_id', $target->getKey())->first()
            : null;

        return view('admin.targets.show', [
            'target' => $target,
            'wpConfig' => $config,
        ]);
    }

    private function trimmed(?string $text): ?string
    {
        $trimmed = $text === null ? null : trim($text);

        return $trimmed === '' ? null : $trimmed;
    }
}
