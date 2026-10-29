<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\ExternalAuthorizationDestination;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorRegistry;
use App\Application\Targets\TargetConnectorResult;
use App\Application\Targets\TargetOperationGate;
use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpClient;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetAdapter;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Gate;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class TargetConnectionController extends Controller
{
    private const HANDOFF_SESSION_KEY = 'admin.external_authorization_handoffs';

    private const HANDOFF_TTL_SECONDS = 120;

    public function connect(Target $target, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsConnect->value, $target);

        try {
            return $this->result($target, $connectors->forTarget($target)->connect($target), 'connect');
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-connect', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        } catch (Throwable) {
            return $this->unexpected($target, 'target-connect');
        }
    }

    public function reconnect(Target $target, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsReconnect->value, $target);
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);
        Gate::authorize(GatewayPermission::TargetsConnect->value, $target);

        try {
            return $this->result($target, $connectors->forTarget($target)->reconnect($target), 'reconnect');
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-reconnect', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        } catch (Throwable) {
            return $this->unexpected($target, 'target-reconnect');
        }
    }

    public function disconnect(Target $target, TargetConnectorRegistry $connectors): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);

        try {
            return $this->result($target, $connectors->forTarget($target)->disconnect($target), 'disconnect');
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-disconnect', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        } catch (Throwable) {
            return $this->unexpected($target, 'target-disconnect');
        }
    }

    public function finishDisconnect(
        Request $request,
        Target $target,
        WpAiBridgeTargetConnectionService $connections,
        WpAiBridgeTargetAdapter $adapter,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);
        $validated = $request->validate(['intent_id' => ['required', 'ulid']]);

        try {
            $connections->disconnect($target, (string) $validated['intent_id']);

            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->with('status', __('Disconnect confirmed. The old authorization is removed locally; you can now authorize WordPress again.'));
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $adapter->connectionFailureMessage($exception), 'wordpress-disconnect-finish', $exception->reason, $exception->diagnostics);
        } catch (Throwable) {
            return $this->unexpected($target, 'wordpress-disconnect-finish');
        }
    }

    public function cancelDisconnect(
        Request $request,
        Target $target,
        WpAiBridgeTargetConnectionService $connections,
        WpAiBridgeMcpClient $bridge,
        WpAiBridgeTargetAdapter $adapter,
        AdministratorPasswordConfirmation $confirmation,
        ActivityRecorder $activity,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);
        Gate::authorize(GatewayPermission::TargetsConnect->value, $target);
        abort_unless((string) $request->user()?->getRawOriginal('role') === GatewayRole::Owner->value, 403);

        $validated = $request->validate([
            'intent_id' => ['required', 'ulid'],
            'confirm_target_id' => ['required', 'string', 'max:64'],
        ]);
        if (! hash_equals($target->target_id, (string) $validated['confirm_target_id'])) {
            return back()->withErrors(['confirm_target_id' => __('Target ID confirmation does not match.')]);
        }
        $confirmation->confirm($request);

        try {
            $connections->cancelNeverSentDisconnect(
                $target,
                (string) $validated['intent_id'],
                static fn (array $routing) => $bridge->verifyExistingAuthorization($routing, CorrelationId::current()),
                static fn (Target $locked) => $activity->recordRequired(
                    CorrelationId::current(), 'wordpress-disconnect-cancel-verified', 'success', $locked,
                ),
            );

            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->with('status', __('Disconnect cancellation confirmed: no revoke was sent and the existing WordPress authorization passed a fresh authenticated catalog check.'));
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $adapter->connectionFailureMessage($exception), 'wordpress-disconnect-cancel', $exception->reason, $exception->diagnostics);
        } catch (Throwable) {
            return $this->unexpected($target, 'wordpress-disconnect-cancel');
        }
    }

    public function reconcileDisconnect(
        Request $request,
        Target $target,
        WpAiBridgeTargetConnectionService $connections,
        WpAiBridgeTargetAdapter $adapter,
        AdministratorPasswordConfirmation $confirmation,
        ActivityRecorder $activity,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);
        abort_unless((string) $request->user()?->getRawOriginal('role') === GatewayRole::Owner->value, 403);

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
            $connections->reconcileRevokedDisconnect(
                $target, (string) $validated['intent_id'],
                static fn (Target $locked) => $activity->recordRequired(
                    CorrelationId::current(), 'wordpress-disconnect-remote-revocation-attested',
                    'operator-attested', $locked,
                ),
            );

            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->with('status', __('Local authorization was cleared based on your WordPress-side revocation attestation, not independent Gateway proof. Authorize a new WordPress session when ready.'));
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $adapter->connectionFailureMessage($exception), 'wordpress-disconnect-reconcile', $exception->reason, $exception->diagnostics);
        } catch (Throwable) {
            return $this->unexpected($target, 'wordpress-disconnect-reconcile');
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
        if (TargetOperationGate::isPaused($target)) {
            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->withErrors(['target' => __('Resume Target operations before starting a new connection test.')]);
        }

        try {
            return $this->result($target, $connectors->forTarget($target)->test($target), 'test');
        } catch (TargetConnectorFailure $exception) {
            return $this->failed($target, $exception->getMessage(), 'target-metadata-test', $exception->reason ?? 'connector_failure', $exception->diagnostics);
        }
    }

    /**
     * Consume a session-bound handoff on a same-origin GET. Authorization is
     * checked again after the POST; a back/refresh never repeats the POST or
     * reissues a provider OAuth state.
     */
    public function externalAuthorization(Request $request, Target $target, string $handoff): Response
    {
        $pending = $request->session()->get(self::HANDOFF_SESSION_KEY, []);
        $pending = is_array($pending) ? $pending : [];
        $entry = $pending[$handoff] ?? null;
        unset($pending[$handoff]);
        $request->session()->put(self::HANDOFF_SESSION_KEY, $pending);

        // The session read/write above is not atomic across PHP workers.
        // An independent expiring cache claim prevents overlapping GETs or a
        // stale concurrent session writer from reusing the same handoff.
        // Supported production cache stores provide atomic add semantics.
        if (! is_array($entry)
            || ! Cache::add('admin:external-authorization:claimed:'.hash('sha256', $handoff), true, self::HANDOFF_TTL_SECONDS)
            || ($entry['target_id'] ?? null) !== $target->target_id
            || ($entry['target_record_id'] ?? null) !== (string) $target->getKey()
            || ($entry['user_id'] ?? null) !== (string) $request->user()?->getAuthIdentifier()
            || ! is_int($entry['expires_at'] ?? null)
            || $entry['expires_at'] <= now()->getTimestamp()
            || ! is_string($entry['operation'] ?? null)
            || ! in_array($entry['operation'], ['connect', 'reconnect', 'disconnect', 'test'], true)
            || ! is_string($entry['destination'] ?? null)
            || ! is_string($entry['authorized_origin'] ?? null)) {
            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->withErrors(['target' => __('Authorization handoff expired or was already used. Check the Target status before restarting authorization.')]);
        }

        foreach (self::requiredPermissions($entry['operation']) as $permission) {
            Gate::authorize($permission->value, $target);
        }

        try {
            $destination = ExternalAuthorizationDestination::validate($entry['destination'], $entry['authorized_origin']);
        } catch (InvalidArgumentException) {
            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->withErrors(['target' => __('The connector authorization destination is invalid. Reload the Target status before retrying.')]);
        }

        return response()->view('admin.targets.external-authorization', [
            'target' => $target,
            'destination' => $destination,
            'providerHost' => (string) parse_url($destination, PHP_URL_HOST),
        ]);
    }

    private function result(Target $target, TargetConnectorResult $result, string $operation): RedirectResponse
    {
        if ($result->redirectUrl !== null) {
            try {
                $destination = ExternalAuthorizationDestination::validate($result->redirectUrl, $result->authorizedOrigin);
            } catch (InvalidArgumentException) {
                throw new TargetConnectorFailure(
                    __('The connector returned an unsafe authorization destination. Check the Target configuration and discovery metadata.'),
                    null,
                    'unsafe_authorization_destination',
                );
            }

            $request = request();
            $pending = $request->session()->get(self::HANDOFF_SESSION_KEY, []);
            $pending = is_array($pending) ? $pending : [];

            // Bound the session data even if the user keeps starting abandoned flows.
            $pending = array_filter($pending, static fn (mixed $entry): bool => is_array($entry)
                && is_int($entry['expires_at'] ?? null) && $entry['expires_at'] > now()->getTimestamp());
            $pending = array_slice($pending, -3, null, true);
            $handoff = bin2hex(random_bytes(16));
            $pending[$handoff] = [
                'target_id' => $target->target_id,
                'target_record_id' => (string) $target->getKey(),
                'user_id' => (string) $request->user()?->getAuthIdentifier(),
                'operation' => $operation,
                'expires_at' => now()->getTimestamp() + self::HANDOFF_TTL_SECONDS,
                'destination' => $destination,
                'authorized_origin' => $result->authorizedOrigin,
            ];
            $request->session()->put(self::HANDOFF_SESSION_KEY, $pending);

            // 303 ends the POST history on our origin before the browser
            // follows a fresh document navigation to the consent provider.
            return redirect()->route('admin.targets.external-authorization', [
                'target' => $target->target_id,
                'handoff' => $handoff,
            ], 303);
        }

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', $result->statusMessage);
    }

    /** @return list<GatewayPermission> */
    private static function requiredPermissions(string $operation): array
    {
        return match ($operation) {
            'connect' => [GatewayPermission::TargetsConnect],
            'reconnect' => [
                GatewayPermission::TargetsReconnect,
                GatewayPermission::TargetsDisconnect,
                GatewayPermission::TargetsConnect,
            ],
            'disconnect' => [GatewayPermission::TargetsDisconnect],
            'test' => [GatewayPermission::TargetsTest],
            default => [],
        };
    }

    private function unexpected(Target $target, string $operation): RedirectResponse
    {
        // Remote I/O or a required audit may have succeeded before local
        // persistence failed. Never expose raw exceptions or imply safe retry.
        return $this->failed(
            $target,
            __('Gateway could not durably confirm this operation. Reload the Target recovery status. Do not repeat an uncertain remote revoke or restore the old credential.'),
            $operation,
            'operation_unconfirmed',
            ['retry_safe' => false],
        );
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
            ->with('diagnostic_context', OperationDiagnostics::safeContext($diagnostics))
            ->with('diagnostic_reference', $reference);
    }
}
