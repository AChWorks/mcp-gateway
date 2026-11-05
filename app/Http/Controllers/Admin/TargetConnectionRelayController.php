<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\ConnectionRelayTargetBinding;
use App\Application\Targets\TargetConnectorFailure;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Infrastructure\Connectors\Relay\ConnectionRelayUnavailable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

final class TargetConnectionRelayController extends Controller
{
    public function update(
        Request $request, Target $target, AdministratorPasswordConfirmation $password,
        ConnectionRelayTargetBinding $bindings,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);
        Gate::authorize(GatewayPermission::SecurityManage->value);
        abort_unless($request->user()?->getRawOriginal('role') === GatewayRole::Owner->value, 403);

        $fields = $request->validate([
            'route_revision' => ['required', 'string', 'size:64', 'regex:/^[a-f0-9]{64}$/D'],
            'connection_relay_id' => ['nullable', 'string', 'max:64',
                'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
        ]);
        $password->confirm($request);
        try {
            $changed = $bindings->change(
                $target, (string) $fields['route_revision'], $fields['connection_relay_id'] ?? null,
            );
        } catch (ConnectionRelayUnavailable) {
            throw ValidationException::withMessages([
                'connection_relay_id' => __('The selected Relay is disabled or missing the independently verified host-isolation attestation.'),
            ]);
        } catch (TargetConnectorFailure $exception) {
            throw ValidationException::withMessages([
                $exception->field ?? 'connection_relay_id' => $exception->getMessage(),
            ]);
        }

        return redirect()->route('admin.targets.edit', ['target' => $target->target_id])
            ->with('status', $changed
                ? __('Target connection route changed. The old route is fenced; reconnect and independently verify the remote Target before running operations.')
                : __('No Target connection route change was necessary.'));
    }
}
