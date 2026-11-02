<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Support\CorrelationId;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

final class SshManagedReverseRevocationController extends Controller
{
    public function __invoke(
        Request $request, Target $target,
        AdministratorPasswordConfirmation $password,
        SshManagedReverseEnrollmentService $enroll,
        ActivityRecorder $activity,
    ): RedirectResponse {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        Gate::authorize(GatewayPermission::TargetsDisconnect->value, $target);
        abort_unless((string) $request->user()?->getRawOriginal('role') === GatewayRole::Owner->value
            && $request->user()?->access_enabled, 403);
        $fields = $request->validate([
            'confirm_target_id' => ['required', 'string', 'max:64'],
        ]);
        if (! hash_equals($target->target_id, $fields['confirm_target_id'])) {
            throw ValidationException::withMessages([
                'confirm_target_id' => __('Type the exact Target ID to revoke this managed route.'),
            ]);
        }
        $password->confirm($request);

        $managed = SshManagedReverseEnrollment::query()
            ->where('target_record_id', $target->getKey())->first();
        abort_unless($managed instanceof SshManagedReverseEnrollment, 404);
        // Drop route authority FIRST, even if public-key file sync subsequently
        // fails or a previously established control session remains in memory.
        $enroll->revoke($managed);

        DB::transaction(function () use ($target, $activity): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $config = SshTargetConfig::query()->where('target_record_id', $locked->getKey())
                ->lockForUpdate()->firstOrFail();
            // Same audited immutable-binding bypass as SshTargetReconfiguration:
            // route was independently revoked and the credential is destroyed.
            DB::table('ssh_direct_target_configs')->where('id', $config->getKey())->update([
                'binding_revision' => ((int) $config->binding_revision) + 1,
                'verification_attempt_id' => null,
                'observed_peer_ip' => null,
                'observed_at' => null,
                'updated_at' => now(),
            ]);
            // This is terminal local revocation, not an automatic reroute. A
            // fresh Owner enrollment is required before any reauthorization.
            TargetCredential::query()->where('target_record_id', $locked->getKey())
                ->where('connector_type', 'ssh_direct')->delete();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Disconnected,
                'connected_at' => null,
                'last_error_code' => 'reverse_route_not_approved',
            ])->save();
            $activity->recordRequired(
                CorrelationId::current(), 'ssh-managed-reverse-revoke', 'success', $locked,
            );
        });

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', __('Managed Reverse SSH authorization revoked and local SSH credential removed. '
                .'Existing control sessions may remain until the Target service disconnects; stop its systemd unit and remove the installed Target login key separately.'));
    }
}
