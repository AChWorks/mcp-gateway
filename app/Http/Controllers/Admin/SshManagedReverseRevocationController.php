<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use RuntimeException;

final class SshManagedReverseRevocationController extends Controller
{
    public function __invoke(
        Request $request, Target $target,
        AdministratorPasswordConfirmation $password,
        SshManagedReverseEnrollmentService $enroll,
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
        // One durable local revocation transaction destroys the SSH vault
        // credential and fences retained Jobs BEFORE host-file publication.
        try {
            $enroll->revoke($managed);
        } catch (RuntimeException $exception) {
            if ($managed->fresh()?->state === 'revoked') {
                return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                    ->withErrors(['target' => __('Gateway route and credential were revoked, but host key publication is not reconciled. Retry the same Owner revoke action or use Reverse SSH Settings → Reconcile. Do not claim complete host revocation yet.')]);
            }
            throw $exception;
        }

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', __('Managed Reverse SSH access revoked and restricted key reader reconciled. Existing control sessions may persist until the Target-side systemd unit is stopped separately.'));

    }
}
