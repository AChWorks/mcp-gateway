<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AdministratorPasswordConfirmation;
use App\Application\Targets\ConnectionRelayAdministration;
use App\Application\Targets\TargetConnectorFailure;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Http\Controllers\Controller;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostOperatorPlan;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostReadiness;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRetirementEvidence;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Support\CorrelationId;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;
use InvalidArgumentException;

final class ConnectionRelayController extends Controller
{
    public function index(
        Request $request, ConnectionRelayHostReadiness $host, ConnectionRelayRetirementEvidence $retirement,
        ConnectionRelayHostOperatorPlan $operator,
    ): View {
        $this->authorizeOwner($request);

        $relays = ConnectionRelay::query()->orderBy('display_name')->get();

        /** @var view-string $template */
        $template = 'admin.connection-relays.index';

        return view($template, [
            'relays' => $relays,
            'hostStates' => $relays->mapWithKeys(
                static fn (ConnectionRelay $relay): array => [$relay->id => $host->ready($relay)],
            ),
            'retiredStates' => $relays->mapWithKeys(
                static fn (ConnectionRelay $relay): array => [$relay->id => $retirement->verified($relay)],
            ),
            'hostCommands' => $relays->mapWithKeys(
                static fn (ConnectionRelay $relay): array => [$relay->id => $operator->commands($relay)],
            ),
            'counts' => DB::table('targets')->whereNotNull('relay_record_id')
                ->selectRaw('relay_record_id, count(*) as total')
                ->groupBy('relay_record_id')->pluck('total', 'relay_record_id'),
        ]);
    }

    public function store(Request $request, AdministratorPasswordConfirmation $password, ActivityRecorder $activity): RedirectResponse
    {
        $this->authorizeOwner($request);
        $fields = $request->validate($this->rules());
        $password->confirm($request);
        [$endpoint, $pin] = $this->validatedEndpointAndPin($fields);
        if (ConnectionRelay::query()->where('relay_id', $fields['relay_id'])->exists()) {
            throw ValidationException::withMessages([
                'relay_id' => __('This Relay ID is already in use by another Relay.'),
            ]);
        }
        if (ConnectionRelay::query()->where('local_socks_port', (int) $fields['local_socks_port'])->exists()) {
            throw ValidationException::withMessages([
                'local_socks_port' => __('This SOCKS5 port is already reserved by another Relay.'),
            ]);
        }
        try {
            $relay = DB::transaction(function () use ($fields, $endpoint, $pin, $activity): ConnectionRelay {
                $relay = ConnectionRelay::query()->create([
                    'relay_id' => (string) $fields['relay_id'],
                    'display_name' => (string) $fields['display_name'],
                    'control_host' => $endpoint->host,
                    'control_port' => $endpoint->port,
                    'control_user' => $endpoint->username,
                    'control_host_key' => $pin->canonicalLine(),
                    'local_socks_port' => (int) $fields['local_socks_port'],
                ]);
                $activity->recordRequired(CorrelationId::current(), 'connection-relay-register', 'success');

                return $relay;
            });
        } catch (UniqueConstraintViolationException) {
            // Recheck the database after a concurrent write. A separate
            // query path avoids treating the earlier preflight as immutable.
            if (DB::table('connection_relays')->where('relay_id', $fields['relay_id'])->exists()) {
                throw ValidationException::withMessages([
                    'relay_id' => __('This Relay ID is already in use by another Relay.'),
                ]);
            }
            if (DB::table('connection_relays')->where('local_socks_port', (int) $fields['local_socks_port'])->exists()) {
                throw ValidationException::withMessages([
                    'local_socks_port' => __('This SOCKS5 port is already reserved by another Relay.'),
                ]);
            }
            throw ValidationException::withMessages([
                'relay' => __('A concurrent Relay registration conflicted. Refresh and retry.'),
            ]);
        }

        return redirect()->route('admin.connection-relays.index')
            ->with('status', __('Relay :name was registered as disabled. The separate host isolation, key setup and attestation must be completed before enabling.', ['name' => $relay->display_name]));
    }

    public function toggle(
        Request $request, ConnectionRelay $relay, AdministratorPasswordConfirmation $password,
        ConnectionRelayAdministration $administration, ConnectionRelayHostReadiness $host,
        ActivityRecorder $activity,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate([
            'relay_revision' => ['required', 'integer', 'min:1'],
            'enable' => ['required', 'in:0,1'],
        ]);
        $password->confirm($request);
        $revision = (int) $fields['relay_revision'];
        if ($fields['enable'] === '0') {
            try {
                $disabled = $administration->disable($relay, $revision);
            } catch (TargetConnectorFailure $exception) {
                throw ValidationException::withMessages([$exception->field ?? 'relay' => $exception->getMessage()]);
            }

            return back()->with('status', $disabled
                ? __('Relay disabled. Previous host attestation is invalid; the privileged operator must reverify isolation and renew evidence before re-enabling. Bound Targets require reconnection.')
                : __('Relay was already disabled. Target epochs and host evidence were not changed.'));
        }

        DB::transaction(function () use ($relay, $revision, $host, $activity): void {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $current->lifecycle_revision !== $revision) {
                throw ValidationException::withMessages(['relay_revision' => __('Relay settings changed. Reload this page.')]);
            }
            if ($current->enabled) {
                throw ValidationException::withMessages(['relay' => __('Relay is already enabled. Refresh before submitting another lifecycle action.')]);
            }
            if ((int) $current->lifecycle_revision >= 4294967295) {
                throw ValidationException::withMessages(['relay_revision' => __('The Relay lifecycle generation is exhausted; its history must not be replayed.')]);
            }
            if (DB::table('targets')->where('relay_record_id', $current->getKey())
                ->where('relay_binding_revision', '>=', 4294967295)->exists()) {
                throw ValidationException::withMessages(['relay' => __('At least one Target binding epoch is exhausted. Reconcile its credentials and history before enabling.')]);
            }
            if (! $host->ready($current)) {
                throw ValidationException::withMessages(['relay' => __('Root-owned host attestation for a dedicated Gateway PHP UID and restricted SOCKS5 access is missing or stale. No Relay was enabled.')]);
            }
            DB::table('connection_relays')->where('id', $current->getKey())
                ->update([
                    'enabled' => true,
                    'lifecycle_revision' => (int) $current->lifecycle_revision + 1,
                    'updated_at' => now(),
                ]);
            $activity->recordRequired(CorrelationId::current(), 'connection-relay-enable', 'success');
        });

        return back()->with('status', __('Relay enabled for explicit Target selection. End-to-end Target authentication still requires a separate test.'));
    }

    public function test(Request $request, ConnectionRelay $relay, ConnectionRelayHostReadiness $host): RedirectResponse
    {
        $this->authorizeOwner($request);
        if (! $relay->enabled || ! $host->ready($relay)) {
            return back()->withErrors(['relay' => __('Relay is disabled or lacks a valid host-isolation attestation. No connection attempted.')]);
        }

        $port = (int) $relay->local_socks_port;
        $errorNumber = 0;
        $errorText = '';
        $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errorNumber, $errorText, 2);
        if (! is_resource($socket)) {
            return back()->withErrors(['relay' => __('The approved loopback SOCKS5 control listener was not reachable. Inspect the supervised OpenSSH client.')]);
        }
        try {
            stream_set_timeout($socket, 2);
            fwrite($socket, "\x05\x01\x00");
            $reply = fread($socket, 2);
        } finally {
            fclose($socket);
        }
        if ($reply !== "\x05\x00") {
            return back()->withErrors(['relay' => __('The loopback listener did not complete the SOCKS5 greeting. No Target authentication was attempted.')]);
        }

        return back()->with('status', __('SOCKS5 control listener responded. This does not prove the remote Target endpoint, SSH login, TLS certificate, or Relay egress policy; test each Target separately.'));
    }

    public function update(
        Request $request, ConnectionRelay $relay, AdministratorPasswordConfirmation $password,
        ActivityRecorder $activity, ConnectionRelayRetirementEvidence $retirement,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate([...$this->rules(), 'relay_revision' => ['required', 'integer', 'min:1']]);
        $password->confirm($request);
        [$endpoint, $pin] = $this->validatedEndpointAndPin($fields);
        try {
            $change = DB::transaction(function () use ($relay, $fields, $endpoint, $pin, $activity, $retirement): string {
                $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
                if ($current->enabled || (int) $current->lifecycle_revision !== (int) $fields['relay_revision']
                    || (int) $current->configuration_revision >= 4294967295
                    || (int) $current->lifecycle_revision >= 4294967295
                    || DB::table('targets')->where('relay_record_id', $current->getKey())->exists()) {
                    throw ValidationException::withMessages(['relay' => __('Disable and detach all Targets before rotating Relay identity; reload if its revision changed.')]);
                }
                // The internal ID is an immutable resource namespace. Rotating
                // it would orphan root-owned service and firewall identities.
                // Create a new Relay after retiring this one instead.
                if ($fields['relay_id'] !== $current->relay_id) {
                    throw ValidationException::withMessages([
                        'relay_id' => __('Relay ID is permanent. Create a new Relay and explicitly migrate Targets instead.'),
                    ]);
                }
                if (ConnectionRelay::query()->whereKeyNot($current->getKey())
                    ->where('relay_id', $fields['relay_id'])->exists()) {
                    throw ValidationException::withMessages([
                        'relay_id' => __('This Relay ID is already in use by another Relay.'),
                    ]);
                }
                if (ConnectionRelay::query()->whereKeyNot($current->getKey())
                    ->where('local_socks_port', (int) $fields['local_socks_port'])->exists()) {
                    throw ValidationException::withMessages([
                        'local_socks_port' => __('This SOCKS5 port is already reserved by another Relay.'),
                    ]);
                }
                $connectionChanged = $current->control_host !== $endpoint->host
                    || $current->control_port !== $endpoint->port
                    || $current->control_user !== $endpoint->username
                    || $current->control_host_key !== $pin->canonicalLine()
                    || $current->local_socks_port !== (int) $fields['local_socks_port'];
                if (! $connectionChanged) {
                    if ($current->display_name === $fields['display_name']) {
                        return 'unchanged';
                    }
                    DB::table('connection_relays')->where('id', $current->getKey())->update([
                        'display_name' => (string) $fields['display_name'],
                        'lifecycle_revision' => (int) $current->lifecycle_revision + 1,
                        'updated_at' => now(),
                    ]);
                    $activity->recordRequired(CorrelationId::current(), 'connection-relay-rename', 'success');

                    return 'renamed';
                }
                if (! $retirement->verified($current)) {
                    throw ValidationException::withMessages([
                        'relay' => __('Before changing host, key, username or port, run the Relay-specific Gateway cleanup command and verify retirement. This prevents orphaned services and rules.'),
                    ]);
                }
                DB::table('connection_relays')->where('id', $current->getKey())->update([
                    'relay_id' => (string) $fields['relay_id'],
                    'display_name' => (string) $fields['display_name'],
                    'control_host' => $endpoint->host,
                    'control_port' => $endpoint->port,
                    'control_user' => $endpoint->username,
                    'control_host_key' => $pin->canonicalLine(),
                    'local_socks_port' => (int) $fields['local_socks_port'],
                    'configuration_revision' => (int) $current->configuration_revision + 1,
                    'lifecycle_revision' => (int) $current->lifecycle_revision + 1,
                    'updated_at' => now(),
                ]);
                $activity->recordRequired(CorrelationId::current(), 'connection-relay-rotate', 'success');

                return 'rotated';
            }, 3);
        } catch (UniqueConstraintViolationException) {
            // A concurrent save may win the DB uniqueness race after the
            // friendly initial check; preserve the field-specific feedback.
            if (ConnectionRelay::query()->whereKeyNot($relay->getKey())
                ->where('relay_id', $fields['relay_id'])->exists()) {
                throw ValidationException::withMessages([
                    'relay_id' => __('This Relay ID is already in use by another Relay.'),
                ]);
            }
            if (ConnectionRelay::query()->whereKeyNot($relay->getKey())
                ->where('local_socks_port', (int) $fields['local_socks_port'])->exists()) {
                throw ValidationException::withMessages([
                    'local_socks_port' => __('This SOCKS5 port is already reserved by another Relay.'),
                ]);
            }
            throw ValidationException::withMessages([
                'relay' => __('Another Relay update conflicted with this change. Refresh and try again.'),
            ]);
        }

        return redirect()->route('admin.connection-relays.index')
            ->with('status', match ($change) {
                'rotated' => __('Relay connection settings updated while disabled. New host setup and attestation are required before enabling.'),
                'renamed' => __('Relay display name updated without changing its host transport or attestation.'),
                default => __('No Relay settings changed.'),
            });
    }

    public function rename(
        Request $request, ConnectionRelay $relay, AdministratorPasswordConfirmation $password,
        ActivityRecorder $activity,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate([
            'display_name' => ['required', 'string', 'max:160'],
            'relay_revision' => ['required', 'integer', 'min:1'],
        ]);
        $password->confirm($request);

        $changed = DB::transaction(function () use ($relay, $fields, $activity): bool {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $current->lifecycle_revision !== (int) $fields['relay_revision']) {
                throw ValidationException::withMessages([
                    'relay_revision' => __('This Relay changed since you opened its settings. Reload before saving.'),
                ]);
            }
            $name = (string) $fields['display_name'];
            if ($current->display_name === $name) {
                return false;
            }
            if ((int) $current->lifecycle_revision >= 4294967295) {
                throw ValidationException::withMessages([
                    'relay_revision' => __('Relay revision is exhausted; changing this record is unsafe.'),
                ]);
            }

            // A display-only edit does not change host identity, attestations
            // or bound Target epochs. The lifecycle revision fences stale forms.
            DB::table('connection_relays')->where('id', $current->getKey())->update([
                'display_name' => $name,
                'lifecycle_revision' => (int) $current->lifecycle_revision + 1,
                'updated_at' => now(),
            ]);
            $activity->recordRequired(CorrelationId::current(), 'connection-relay-rename', 'success');

            return true;
        }, 3);

        return redirect()->route('admin.connection-relays.index')
            ->with('status', $changed
                ? __('Relay display name updated without changing its connection or bound Targets.')
                : __('Relay display name was already up to date.'));
    }

    public function destroy(
        Request $request, ConnectionRelay $relay, AdministratorPasswordConfirmation $password,
        ActivityRecorder $activity, ConnectionRelayRetirementEvidence $retirement,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate([
            'relay_revision' => ['required', 'integer', 'min:1'],
            'confirm_relay_id' => ['required', 'string', 'max:64'],
            'confirm_gateway_cleanup' => ['accepted'],
        ]);
        $password->confirm($request);

        DB::transaction(function () use ($relay, $fields, $activity, $retirement): void {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $current->lifecycle_revision !== (int) $fields['relay_revision']) {
                throw ValidationException::withMessages([
                    'relay_revision' => __('This Relay changed since you opened the delete form. Reload and review.'),
                ]);
            }
            if (! hash_equals((string) $current->relay_id, (string) $fields['confirm_relay_id'])) {
                throw ValidationException::withMessages([
                    'confirm_relay_id' => __('Type the exact Relay ID to confirm deletion.'),
                ]);
            }
            if ($current->enabled) {
                throw ValidationException::withMessages([
                    'relay' => __('Disable this Relay before removing its registration.'),
                ]);
            }
            if (DB::table('targets')->where('relay_record_id', $current->getKey())->exists()) {
                throw ValidationException::withMessages([
                    'relay' => __('This Relay still has assigned Targets. Reassign or detach every Target explicitly first; no Target will silently fall back to Direct.'),
                ]);
            }
            // Owner acknowledgement alone cannot prove retirement of the
            // Relay's local resources. An independent privileged helper
            // verifies this Gateway host; Iranian reachability is irrelevant.
            if (! $retirement->verified($current)) {
                throw ValidationException::withMessages([
                    'relay' => __('Verified Gateway-host cleanup is missing or stale. Keep this Relay disabled; local privileged cleanup must be verified before deleting this record. Iran reachability is not required.'),
                ]);
            }
            $current->delete();
            $activity->recordRequired(CorrelationId::current(), 'connection-relay-delete-registration', 'success');
        }, 3);

        return redirect()->route('admin.connection-relays.index')
            ->with('status', __('Relay registration removed after verified Gateway-host cleanup and Owner confirmation. Iran-side cleanup was not checked.'));
    }

    /** @param array<string,mixed> $fields
     * @return array{SshRegisteredEndpoint,SshHostKeyPin}
     */
    private function validatedEndpointAndPin(array $fields): array
    {
        // Laravel validates port bounds and the identical SSH username
        // grammar first. Endpoint failures therefore belong to control_host.
        try {
            $endpoint = SshRegisteredEndpoint::fromInput(
                (string) $fields['control_host'], (int) $fields['control_port'], (string) $fields['control_user'],
            );
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'control_host' => __('Enter a valid, canonical Relay SSH hostname or IP address.'),
            ]);
        }

        try {
            $pin = SshHostKeyPin::fromLine((string) $fields['control_host_key']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'control_host_key' => __('Independently obtain and verify the exact SSH server public host key.'),
            ]);
        }

        return [$endpoint, $pin];
    }

    private function authorizeOwner(Request $request): void
    {
        Gate::authorize(GatewayPermission::SecurityManage->value);
        abort_unless($request->user()?->getRawOriginal('role') === GatewayRole::Owner->value, 403);
    }

    /** @return array<string,array<int,string>> */
    private function rules(): array
    {
        return [
            'relay_id' => ['required', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
            'display_name' => ['required', 'string', 'max:160'],
            'control_host' => ['required', 'string', 'max:253'],
            'control_port' => ['required', 'integer', 'min:1', 'max:65535'],
            'control_user' => ['required', 'string', 'max:128', 'regex:/^[a-zA-Z0-9_][a-zA-Z0-9_.+-]{0,127}$/D'],
            'control_host_key' => ['required', 'string', 'max:4096'],
            // This range does not overlap the existing managed Reverse
            // listener allocation (42000-45000), or Gateway control SSHD.
            'local_socks_port' => ['required', 'integer', 'min:46000', 'max:60999'],
        ];
    }
}
