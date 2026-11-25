<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Domain\Access\GatewayPermission;
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
        Gate::authorize(GatewayPermission::TargetsConfigure->value, $target);
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
        // One durable local route revocation fences retained Jobs before
        // host-file publication, independently of the stored login.
        try {
            $enroll->revoke($managed);
        } catch (RuntimeException $exception) {
            if ($managed->fresh()?->state === 'revoked') {
                return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                    ->withErrors(['target' => __('Gateway route was revoked, but host key publication is not reconciled. Retry the same Target revoke action or ask an Owner to reconcile in Reverse SSH Settings. Do not claim complete host revocation yet.')]);
            }
            throw $exception;
        }

        return redirect()->route('admin.targets.show', ['target' => $target->target_id])
            ->with('status', __('Managed Reverse SSH route revoked and restricted key reader reconciled. Target login credentials are unchanged. Existing control sessions may persist until the Target-side systemd unit is stopped separately.'));

    }
}
