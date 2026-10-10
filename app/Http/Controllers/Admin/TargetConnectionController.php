<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Support\CorrelationId;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

final class TargetConnectionController extends Controller
{
    public function connect(Target $target, WpAiBridgeTargetConnectionService $connections, SshTargetConnectionService $ssh): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsConnect->value, $target);

        try {
            if ($target->connector_type === 'ssh_direct') {
                $ssh->test($target);

                return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                    ->with('status', __('SSH host key, numeric TCP peer and login verified. No command was run.'));
            }

            return redirect()->away($connections->begin($target));
        } catch (SshTargetConnectionException $exception) {
            return $this->failedSsh($target, $exception);
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $exception);
        }
    }

    public function reconnect(Target $target, WpAiBridgeTargetConnectionService $connections, SshTargetConnectionService $ssh): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsReconnect->value, $target);
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);
        Gate::authorize(GatewayPermission::TargetsConnect->value, $target);

        try {
            if ($target->connector_type === 'ssh_direct') {
                $ssh->test($target);

                return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                    ->with('status', __('SSH recheck verified the pinned host key and login.'));
            }

            $connections->disconnect($target);

            return redirect()->away($connections->begin($target));
        } catch (SshTargetConnectionException $exception) {
            return $this->failedSsh($target, $exception);
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $exception);
        }
    }

    public function disconnect(Target $target, WpAiBridgeTargetConnectionService $connections, SshTargetConnectionService $ssh): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);

        try {
            if ($target->connector_type === 'ssh_direct') {
                $ssh->disconnect($target);

                return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                    ->with('status', __('SSH credential deleted from this Gateway. This does NOT revoke the remote Unix account or terminate external sessions.'));
            }

            $connections->disconnect($target);

            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->with('status', __('WordPress Target disconnected after confirmed credential revocation.'));
        } catch (SshTargetConnectionException $exception) {
            return $this->failedSsh($target, $exception);
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $exception);
        }
    }

    public function reconcileRefresh(
        Request $request,
        Target $target,
        WpAiBridgeTargetConnectionService $connections,
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
            return $this->failed($target, $exception);
        }
    }

    public function test(Target $target, WpAiBridgeTargetConnectionService $connections, SshTargetConnectionService $ssh): RedirectResponse
    {
        Gate::authorize(GatewayPermission::TargetsTest->value, $target);

        try {
            if ($target->connector_type === 'ssh_direct') {
                $ssh->test($target);

                return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                    ->with('status', __('SSH TCP peer, pinned host key and login verified.'));
            }

            $connections->testConnection($target);

            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->with('status', __('WordPress metadata is reachable and compatible.'));
        } catch (SshTargetConnectionException $exception) {
            return $this->failedSsh($target, $exception);
        } catch (WpAiBridgeTargetConnectionException $exception) {
            return $this->failed($target, $exception);
        }
    }

    private function failedSsh(Target $target, SshTargetConnectionException $exception): RedirectResponse
    {
        $message = match ($exception->reason) {
            'egress_denied' => __('The registered SSH destination is not permitted by the TCP/DNS policy.'),
            'tcp_peer_mismatch', 'host_key_mismatch', 'ssh_handshake_failed' => __('SSH server identity could not be verified. No credentials were sent after a host-key mismatch.'),
            'authentication_failed' => __('SSH authentication failed after server identity verification.'),
            'tcp_unreachable' => __('The approved numeric SSH endpoint could not be reached.'),
            'credential_invalid', 'credential_unavailable' => __('The stored SSH credential is unavailable or invalid.'),
            'connection_busy' => __('Another SSH verification is already in progress for this Target.'),
            'rate_limited' => __('Too many SSH verification attempts were made for this Target. Try again later.'),
            'admission_unavailable' => __('SSH verification is temporarily unavailable because its safety guard could not be acquired.'),
            'target_changed' => __('The SSH Target changed while verification was in progress. Retry after reviewing it.'),
            default => __('The SSH connection could not be verified safely.'),
        };

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->withErrors(['target' => $message]);
    }

    private function failed(Target $target, WpAiBridgeTargetConnectionException $exception): RedirectResponse
    {
        $message = match ($exception->reason) {
            'unsafe_target' => __('Use a reachable public HTTPS WordPress Target.'),
            'missing_bridge', 'incompatible_metadata' => __('WordPress connector OAuth/MCP metadata is missing or incompatible.'),
            'already_connected' => __('Disconnect or reconnect the existing credential before starting a new authorization.'),
            'callback_pending' => __('An OAuth callback is being completed. Check its result before retrying.'),
            'revocation_pending', 'revocation_failed', 'revocation_conflict' => __('Remote credential revocation is incomplete. Review Target status and retry the disconnect.'),
            'refresh_settling' => __('The refresh recovery window is still active. Wait before reconciling.'),
            'refresh_conflict' => __('The pending refresh changed. Reload Target details before any reconciliation.'),
            'credential_unavailable' => __('Stored credential cannot be verified. Restore the matching encryption key before retrying.'),
            'network_failure', 'tls_failure', 'remote_failure' => __('WordPress cannot be reached securely right now. Retry after checking connectivity.'),
            default => __('The WordPress Target operation could not be completed safely. Check its status and retry.'),
        };

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->withErrors(['target' => $message]);
    }
}
