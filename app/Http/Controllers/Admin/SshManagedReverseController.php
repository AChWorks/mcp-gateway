<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\SshManagedReverseAuthorizedKeys;
use App\Application\Targets\SshManagedReverseHostReadiness;
use App\Domain\Access\GatewayRole;
use App\Http\Controllers\Controller;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;
use InvalidArgumentException;

final class SshManagedReverseController extends Controller
{
    public function index(Request $request, SshManagedReverseAuthorizedKeys $keys, SshManagedReverseHostReadiness $readiness): View
    {
        $this->requireOwner($request);
        $gateway = SshManagedReverseGateway::query()->find(1);
        $fileReady = $keys->canPublish();
        $health = $readiness->assess($gateway);
        $fingerprint = null;
        if ($gateway instanceof SshManagedReverseGateway) {
            try {
                $fingerprint = SshHostKeyPin::fromLine($gateway->control_host_key)->fingerprint();
            } catch (InvalidArgumentException) {
                // A stale/corrupt stored pin never becomes an invented verified identity.
            }
        }

        return view('admin.reverse-ssh.index', [
            'gateway' => $gateway,
            'gatewayFingerprint' => $fingerprint,
            'configurationState' => $gateway === null
                ? 'Not configured' : ($gateway->enabled ? 'Configured and enabled' : 'Configured but disabled'),
            'status' => $health['state'],
            'readiness' => $health,
            'policyReconciled' => $keys->isReconciled(),
            'controlPort' => ($gateway instanceof SshManagedReverseGateway ? $gateway->control_port : null)
                ?? $keys->hostManifest()['control_port'] ?? null,
            'fileReady' => $fileReady,
            'pending' => SshManagedReverseEnrollment::query()->whereIn('state', ['pending', 'claimed'])->count(),
            'active' => SshManagedReverseEnrollment::query()->where('state', 'active')->count(),
        ]);
    }

    public function save(
        Request $request, AdministratorPasswordConfirmation $password,
        SshManagedReverseAuthorizedKeys $keys,
    ): RedirectResponse {
        $this->requireOwner($request);
        $fields = $request->validate([
            'revision' => ['required', 'integer', 'min:0'],
            'enabled' => ['required', 'in:0,1'],
            'control_host' => ['required', 'string', 'max:253'],
            'control_port' => ['required', 'integer', 'min:1024', 'max:65535'],
            'control_user' => ['required', 'string', 'regex:/^[a-z_][a-z0-9_-]{0,31}$/D'],
            'control_host_key' => ['required', 'string', 'max:4096'],
        ]);
        $password->confirm($request);
        try {
            $endpoint = SshRegisteredEndpoint::fromInput(
                (string) $fields['control_host'], (int) $fields['control_port'], (string) $fields['control_user'],
            );
            $pin = SshHostKeyPin::fromLine((string) $fields['control_host_key']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'control_host_key' => __('Enter a valid public Gateway endpoint and independently verified OpenSSH host key.'),
            ]);
        }
        $enabled = $fields['enabled'] === '1';
        if ($enabled && (! $keys->canPublish() || ! $keys->hostManifest())) {
            throw ValidationException::withMessages([
                'enabled' => __('The host-side Reverse SSH bootstrap is unavailable. Prepare its restricted key reader before enabling.'),
            ]);
        }
        if ($enabled) {
            $manifest = $keys->hostManifest();
            if (! $manifest || $manifest['control_port'] !== $endpoint->port
                || $manifest['control_user'] !== $endpoint->username
                || $manifest['control_host_key'] !== $pin->canonicalLine()) {
                throw ValidationException::withMessages([
                    'control_host_key' => __('Host bootstrap identity differs from the configured SSHD port, user or public host key.'),
                ]);
            }
        }
        $saveIntent = static function () use ($fields, $endpoint, $pin, $enabled): void {
            DB::transaction(function () use ($fields, $endpoint, $pin, $enabled): void {
                $current = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
                $revision = $current instanceof SshManagedReverseGateway ? (int) $current->revision : 0;
                if ($revision !== (int) $fields['revision']) {
                    throw ValidationException::withMessages([
                        'revision' => __('Reverse SSH settings changed in another session. Reload before applying changes.'),
                    ]);
                }
                if ($current && SshManagedReverseEnrollment::query()
                    ->where('state', '!=', 'revoked')->exists()
                    && ($current->control_host !== $endpoint->host
                        || $current->control_port !== $endpoint->port
                        || $current->control_user !== $endpoint->username
                        || $current->control_host_key !== $pin->canonicalLine())) {
                    throw ValidationException::withMessages([
                        'control_host' => __('Revoke or safely migrate active enrollments before rotating the control endpoint/identity.'),
                    ]);
                }
                SshManagedReverseGateway::query()->updateOrCreate(['id' => 1], [
                    'enabled' => $enabled,
                    'control_host' => $endpoint->host,
                    'control_port' => $endpoint->port,
                    'control_user' => $endpoint->username,
                    'control_host_key' => $pin->canonicalLine(),
                    'revision' => $revision + 1,
                    'publication_pending' => true,
                ]);
            }, 3);
        };

        if ($keys->canPublish()) {
            // Serialize configuration and key-reader policy with claim,
            // reissue and revoke. Committed disable still fails closed
            // immediately if the external publication later fails.
            try {
                $keys->withPolicyLock(static function () use ($saveIntent, $keys): void {
                    $saveIntent();
                    $keys->sync();
                });
            } catch (\RuntimeException) {
                return redirect()->route('admin.reverse-ssh.index')
                    ->with('reverse_ssh_operation', 'save_publication_failed')
                    ->withErrors(['site' => __('The settings save may have committed, but restricted key publication was not confirmed. Inspect the saved revision and pending publication state; if pending, use Owner Repair. Do not repeat Save with a stale revision.')]);
            }
        } else {
            if ($enabled) {
                throw ValidationException::withMessages([
                    'enabled' => __('Cannot enable Reverse SSH with an unavailable host key reader.'),
                ]);
            }
            // Disabling must remain available even with a degraded reader:
            // application route authorization then fails closed immediately.
            $saveIntent();
        }

        return redirect()->route('admin.reverse-ssh.index')
            ->with('status', __('Reverse SSH configuration saved. Verify actual host SSHD restrictions independently before using it.'));
    }

    public function repair(
        Request $request, AdministratorPasswordConfirmation $password,
        SshManagedReverseAuthorizedKeys $keys,
    ): RedirectResponse {
        $this->requireOwner($request);
        $password->confirm($request);
        if (! $keys->canPublish()) {
            throw ValidationException::withMessages([
                'site' => __('Host bootstrap is missing. Run the independently authorized one-time host setup before repair.'),
            ]);
        }
        try {
            $keys->sync();
        } catch (\RuntimeException) {
            return redirect()->route('admin.reverse-ssh.index')
                ->with('reverse_ssh_operation', 'repair_failed')
                ->withErrors(['site' => __('Owner Repair could not publish the restricted key policy. The persisted revision and pending state remain authoritative; inspect host access and retry Repair only after correcting the cause.')]);
        }

        return redirect()->route('admin.reverse-ssh.index')
            ->with('status', __('Restricted public-key policy reconciled. Host SSHD status and reverse listeners still require verification.'));
    }

    private function requireOwner(Request $request): User
    {
        $user = $request->user();
        abort_unless($user instanceof User && (string) $user->getRawOriginal('role') === GatewayRole::Owner->value
            && $user->access_enabled, 403);

        return $user;
    }
}
