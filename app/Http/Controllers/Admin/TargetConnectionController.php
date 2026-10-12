<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorRegistry;
use App\Application\Targets\TargetConnectorResult;
use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetAdapter;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

final class TargetConnectionController extends Controller
{
    public function connect(Target $target, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsConnect->value, $target);

        try {
            return $this->result($target, $connectors->forTarget($target)->connect($target));
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-connect', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        }
    }

    public function reconnect(Target $target, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsReconnect->value, $target);
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);
        Gate::authorize(GatewayPermission::TargetsConnect->value, $target);

        try {
            return $this->result($target, $connectors->forTarget($target)->reconnect($target));
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-reconnect', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        }
    }

    public function disconnect(Target $target, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);

        try {
            return $this->result($target, $connectors->forTarget($target)->disconnect($target));
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-disconnect', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        }
    }

    public function reconcileRefresh(
        Request $request,
        Target $target,
        WpAiBridgeTargetConnectionService $connections,
        WpAiBridgeTargetAdapter $adapter,
        AdministratorPasswordConfirmation $confirmation,
        ActivityRecorder $activity,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);

        $validated = $request->validate([
            'intent_id' => ['required', 'ulid'],
            'confirm_target_id' => ['required', 'string', 'max:64'],
            'wordpress_client_revoked' => ['required', 'in:yes'],
            'other_clients_affected' => ['required', 'in:yes'],
        ]);
        if (! hash_equals($target->target_id, (string) $validated['confirm_target_id'])) {
            return back()->withErrors(['confirm_target_id' => __('Target ID confirmation does not match.')]);
        }
        $confirmation->confirm($request);

        try {
            $connections->reconcileRevokedRefresh(
                $target,
                (string) $validated['intent_id'],
                static function (Target $locked) use ($activity): void {
                    $activity->recordRequired(
                        CorrelationId::current(),
                        'wordpress-refresh-remote-revocation-attested',
                        'operator-attested',
                        $locked,
                    );
                },
            );

            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->with('status', __('Local WordPress credential cleared on your remote-revocation attestation. This Gateway did not verify remote revocation. Reapprove the Gateway client in WordPress, then authorize this Target again.'));
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $adapter->connectionFailureMessage($exception), 'wordpress-refresh-reconcile', $exception->reason, $exception->diagnostics);
        }
    }

    public function test(Target $target, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsTest->value, $target);

        try {
            return $this->result($target, $connectors->forTarget($target)->test($target));
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-metadata-test', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        }
    }

    private function result(Target $target, TargetConnectorResult $result): RedirectResponse
    {
        if ($result->redirectUrl !== null) {
            return redirect()->away($result->redirectUrl);
        }

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', $result->statusMessage);
    }

    /** @param array<string,mixed> $diagnostics */
    private function failed(Target $target, string $message, string $operation, string $code, array $diagnostics): RedirectResponse
    {
        $reference = OperationDiagnostics::failure($operation, $code, $target, $diagnostics);
        $stage = $diagnostics['failure_stage'] ?? null;
        $safeStage = is_string($stage) && preg_match('/^[a-z_]{2,32}$/D', $stage) === 1
            ? $stage : null;

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->withErrors(['target' => $message])
            ->with('diagnostic_code', $code)
            ->with('diagnostic_stage', $safeStage)
            ->with('diagnostic_reference', $reference);
    }
}
