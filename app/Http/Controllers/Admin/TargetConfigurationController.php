<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\TargetConnectorAdapter;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorRegistry;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Support\OperationDiagnostics;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

final class TargetConfigurationController extends Controller
{
    public function update(
        Request $request,
        Target $target,
        TargetConnectorRegistry $connectors,
        AdministratorPasswordConfirmation $confirmation,
    ): RedirectResponse {
        // Updating the remote endpoint, trust binding or login secret is more
        // privileged than changing a display label. Never offer this route to
        // ordinary users with only targets.update permission.
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);
        Gate::authorize(GatewayPermission::SecurityManage->value);

        // Historical, Owner-paused connector types remain viewable but do
        // not acquire an executable configuration endpoint by accident.
        $adapter = $connectors->availableForTarget($target);
        abort_unless($adapter instanceof TargetConnectorAdapter, 404);

        try {
            $validated = $request->validate($adapter->configurationRules($target));
            $confirmation->confirm($request);
            $result = $adapter->updateConfiguration($target, $validated);
        } catch (ValidationException $exception) {
            if ($request->expectsJson()) {
                throw $exception;
            }

            return back()->withErrors($exception->errors())->withInput($this->safeInput($request, $adapter->safeOldInputFields()));
        } catch (TargetConnectorFailure $exception) {
            $code = $exception->reason ?? 'configuration_rejected';
            $reference = OperationDiagnostics::failure('target-configuration-update', $code, $target, $exception->diagnostics);

            return back()
                ->withErrors([$exception->field ?? 'configuration' => $exception->getMessage()])
                ->withInput($this->safeInput($request, $adapter->safeOldInputFields()))
                ->with('diagnostic_code', $code)
                ->with('diagnostic_reference', $reference);
        }

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', $result->statusMessage);
    }

    /**
     * Never flash login passwords, private keys, key passphrases, Owner
     * passwords or other arbitrary POST fields to the session.
     *
     * @param  list<string>  $fields
     * @return array<string,mixed>
     */
    private function safeInput(Request $request, array $fields): array
    {
        return $request->only($fields);
    }
}
