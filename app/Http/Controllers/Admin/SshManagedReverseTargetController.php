<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Application\Targets\SshManagedReverseInstallCommand;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Http\Controllers\Controller;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Models\User;
use App\Support\TargetFormInput;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;
use InvalidArgumentException;
use RuntimeException;

final class SshManagedReverseTargetController extends Controller
{
    public function create(Request $request): RedirectResponse
    {
        $this->requireOwner($request);

        // Bookmarked legacy route has one canonical Target-owned enrollment form.
        return redirect()->route('admin.targets.create', [
            'connector_type' => 'ssh_direct', 'ssh_mode' => 'managed',
        ]);
    }

    public function store(
        Request $request,
        AdministratorPasswordConfirmation $password,
        SshManagedReverseEnrollmentService $enroll,
        SshManagedReverseInstallCommand $installer,
    ): View|RedirectResponse {
        $this->requireOwner($request);

        try {
            return $this->createPending($request, $password, $enroll, $installer);
        } catch (ValidationException $exception) {
            if ($request->expectsJson()) {
                throw $exception;
            }

            // A failed POST must return to the canonical Add Target flow even
            // without Referer, restoring only non-secret identity/trust drafts.
            return redirect()->route('admin.targets.create', [
                'connector_type' => 'ssh_direct', 'ssh_mode' => 'managed',
            ])->withInput(TargetFormInput::replayable($request, [
                'connector_type', 'ssh_mode', 'target_id', 'display_name',
                'ai_guidance', 'ssh_host', 'ssh_port', 'ssh_username',
                'ssh_host_key', 'ssh_trust_confirmed',
            ]))->withErrors($exception->errors());
        }
    }

    private function createPending(
        Request $request, AdministratorPasswordConfirmation $password,
        SshManagedReverseEnrollmentService $enroll, SshManagedReverseInstallCommand $installer,
    ): View {
        // Distinguish browser-profile emails from real OS account names.
        if (str_contains((string) $request->input('ssh_username', ''), '@')) {
            throw ValidationException::withMessages([
                'ssh_username' => __('Enter the existing SSH OS account name (such as deploy), not a browser login email.'),
            ]);
        }
        $fields = $request->validate([
            'target_id' => ['required', 'string', 'max:64',
                'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
            'display_name' => ['required', 'string', 'max:160'],
            'ai_guidance' => ['nullable', 'string', 'max:800',
                'not_regex:/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]/'],
            'ssh_host' => ['required', 'string', 'max:253'],
            'ssh_port' => ['required', 'integer', 'min:1', 'max:65535'],
            'ssh_username' => ['required', 'string', 'max:128', 'regex:/^[a-zA-Z0-9_][a-zA-Z0-9_.+-]{0,127}$/D'],
            'ssh_host_key' => ['required', 'string', 'max:4096'],
            'ssh_trust_confirmed' => ['required', 'in:yes'],
        ]);
        $password->confirm($request);
        // Validate immutable installer availability BEFORE creating the Target.
        try {
            $installer->scriptDigest();
            if (! preg_match('~^https://[a-zA-Z0-9.:-]+(?::[0-9]+)?$~D', (string) config('app.url'))) {
                throw new RuntimeException('Gateway must use HTTPS to issue a privileged enrollment command.');
            }
        } catch (RuntimeException) {
            throw ValidationException::withMessages([
                'site' => __('A verified HTTPS installer artifact is unavailable. Check the immutable release and Gateway URL.'),
            ]);
        }
        try {
            $started = $enroll->begin(
                $fields['target_id'], $fields['display_name'], $fields['ssh_host'],
                (int) $fields['ssh_port'], $fields['ssh_username'],
                $fields['ssh_host_key'], $fields['ai_guidance'] ?? null,
            );
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'target_id' => __('The Target identity, endpoint or verified host key is invalid or already registered.'),
            ]);
        } catch (RuntimeException) {
            throw ValidationException::withMessages([
                'site' => __('Gateway Reverse SSH host capability is not ready. Inspect Settings and the audit logs before retrying.'),
            ]);
        }
        $enrollment = $started['enrollment'];
        $command = $installer->command($enrollment, $started['token']);

        return view('admin.reverse-ssh.install-command', [
            'target' => $enrollment->target,
            'command' => $command,
            'installerSha' => $installer->scriptDigest(),
            'expires' => $enrollment->token_expires_at,
        ])->with('notices', [])
            ->with('suppressCache', true);
    }

    public function reissue(
        Request $request, Target $target, AdministratorPasswordConfirmation $password,
        SshManagedReverseEnrollmentService $enroll, SshManagedReverseInstallCommand $installer,
    ): View {
        $this->requireOwner($request);
        Gate::authorize(GatewayPermission::TargetsUpdate->value, $target);
        $fields = $request->validate([
            'confirm_target_id' => ['required', 'string', 'max:64'],
        ]);
        if (! hash_equals($target->target_id, $fields['confirm_target_id'])) {
            throw ValidationException::withMessages([
                'confirm_target_id' => __('Type the exact Target ID to rotate an unverified enrollment.'),
            ]);
        }
        $password->confirm($request);
        $managed = SshManagedReverseEnrollment::query()
            ->where('target_record_id', $target->getKey())->firstOrFail();
        if ($managed->state === 'revoked' || $target->getRawOriginal('connection_state') !== TargetConnectionState::Pending->value) {
            throw ValidationException::withMessages([
                'target' => __('Only an unverified Pending Setup can be reissued. Revoke or inspect this Target first.'),
            ]);
        }
        $installer->scriptDigest();
        try {
            $started = $enroll->reissue($managed);
        } catch (InvalidArgumentException|RuntimeException) {
            throw ValidationException::withMessages([
                'target' => __('Cannot reissue the enrollment. Inspect Reverse SSH host readiness, publication and audit diagnostics; reconcile then retry.'),
            ]);
        }
        $enrollment = $started['enrollment'];

        return view('admin.reverse-ssh.install-command', [
            'target' => $target,
            'command' => $installer->command($enrollment, $started['token']),
            'installerSha' => $installer->scriptDigest(),
            'expires' => $enrollment->token_expires_at,
        ])->with('notices', [])->with('suppressCache', true);
    }

    private function requireOwner(Request $request): User
    {
        Gate::authorize(GatewayPermission::TargetsCreate->value);
        Gate::authorize(GatewayPermission::SecurityManage->value);
        $user = $request->user();
        abort_unless($user instanceof User && (string) $user->getRawOriginal('role') === GatewayRole::Owner->value
            && $user->access_enabled, 403);

        return $user;
    }
}
