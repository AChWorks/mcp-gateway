<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetTransportBinding;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\Relay\ConnectionRelayUnavailable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

final class TargetConnectionRelayController extends Controller
{
    public function update(
        Request $request, Target $target, AdministratorPasswordConfirmation $password,
        TargetTransportBinding $bindings,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsConfigure->value, $target);

        $fields = $request->validate([
            'route_revision' => ['required', 'string', 'size:64', 'regex:/^[a-f0-9]{64}$/D'],
            ...ConnectionRelayRoutes::selectionRules(),
        ]);
        $password->confirm($request);
        try {
            $changed = $bindings->change(
                $target, (string) $fields['route_revision'], $fields['connection_relay_id'] ?? null,
            );
        } catch (ConnectionRelayUnavailable) {
            throw ValidationException::withMessages([
                'connection_relay_id' => __('The selected Relay is disabled or no longer exists.'),
            ]);
        } catch (TargetConnectorFailure $exception) {
            throw ValidationException::withMessages([
                $exception->field ?? 'connection_relay_id' => $exception->getMessage(),
            ]);
        }

        return redirect()->route('admin.targets.edit', ['target' => $target->target_id])
            ->with('status', $changed
                ? __('Target connection route changed. Stored authorization is preserved; new operations use the selected route.')
                : __('No Target connection route change was necessary.'));
    }
}
