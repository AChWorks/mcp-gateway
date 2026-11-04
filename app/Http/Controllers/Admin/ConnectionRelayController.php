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
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostReadiness;
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
    public function index(Request $request, ConnectionRelayHostReadiness $host): View
    {
        $this->authorizeOwner($request);

        $relays = ConnectionRelay::query()->orderBy('display_name')->get();

        /** @var view-string $template */
        $template = 'admin.connection-relays.index';

        return view($template, [
            'relays' => $relays,
            'hostStates' => $relays->mapWithKeys(
                static fn (ConnectionRelay $relay): array => [$relay->id => $host->ready($relay)],
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
        try {
            $endpoint = SshRegisteredEndpoint::fromInput(
                (string) $fields['control_host'], (int) $fields['control_port'],
                (string) $fields['control_user'],
            );
            $pin = SshHostKeyPin::fromLine((string) $fields['control_host_key']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'control_host_key' => __('Verify the Relay SSH endpoint and independently obtain its exact public server host key.'),
            ]);
        }
        if (ConnectionRelay::query()->where('relay_id', $fields['relay_id'])
            ->orWhere('local_socks_port', (int) $fields['local_socks_port'])->exists()) {
            throw ValidationException::withMessages(['relay_id' => __('Relay ID or local listener port is already registered.')]);
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
            // The database unique indexes close a concurrent Owner save
            // race even if the friendly initial uniqueness check passed.
            throw ValidationException::withMessages([
                'relay_id' => __('Relay ID or dedicated local SOCKS5 listener port was already registered.'),
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
                $administration->disable($relay, $revision);
            } catch (TargetConnectorFailure $exception) {
                throw ValidationException::withMessages([$exception->field ?? 'relay' => $exception->getMessage()]);
            }

            return back()->with('status', __('Relay disabled. Bound Targets require explicit re-verification; retained SSH Jobs have new route epochs.'));
        }

        DB::transaction(function () use ($relay, $revision, $host, $activity): void {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $current->configuration_revision !== $revision) {
                throw ValidationException::withMessages(['relay_revision' => __('Relay settings changed. Reload this page.')]);
            }
            if (DB::table('targets')->where('relay_record_id', $current->getKey())
                ->where('relay_binding_revision', '>=', 4294967295)->exists()) {
                throw ValidationException::withMessages(['relay' => __('At least one Target binding epoch is exhausted. Reconcile its credentials and history before enabling.')]);
            }
            if (! $host->ready($current)) {
                throw ValidationException::withMessages(['relay' => __('Root-owned host attestation for a dedicated Gateway PHP UID and restricted SOCKS5 access is missing or stale. No Relay was enabled.')]);
            }
            DB::table('connection_relays')->where('id', $current->getKey())
                ->update(['enabled' => true, 'updated_at' => now()]);
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
        ActivityRecorder $activity,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate([...$this->rules(), 'relay_revision' => ['required', 'integer', 'min:1']]);
        $password->confirm($request);
        try {
            $endpoint = SshRegisteredEndpoint::fromInput((string) $fields['control_host'],
                (int) $fields['control_port'], (string) $fields['control_user']);
            $pin = SshHostKeyPin::fromLine((string) $fields['control_host_key']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['control_host_key' => __('Verify the trusted Relay SSH endpoint and its public host key.')]);
        }
        DB::transaction(function () use ($relay, $fields, $endpoint, $pin, $activity): void {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ($current->enabled || (int) $current->configuration_revision !== (int) $fields['relay_revision']
                || DB::table('targets')->where('relay_record_id', $current->getKey())->exists()) {
                throw ValidationException::withMessages(['relay' => __('Disable and detach all Targets before rotating Relay identity; reload if its revision changed.')]);
            }
            if (ConnectionRelay::query()->where('id', '!=', $current->getKey())
                ->where(static fn ($query) => $query->where('relay_id', $fields['relay_id'])
                    ->orWhere('local_socks_port', (int) $fields['local_socks_port']))->exists()) {
                throw ValidationException::withMessages(['relay_id' => __('Relay ID or local listener port conflicts with another Relay.')]);
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
                'updated_at' => now(),
            ]);
            $activity->recordRequired(CorrelationId::current(), 'connection-relay-rotate', 'success');
        });

        return redirect()->route('admin.connection-relays.index')
            ->with('status', __('Relay identity updated while disabled. Reprovision the root-owned host attestation before enabling.'));
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
            'control_user' => ['required', 'string', 'max:128'],
            'control_host_key' => ['required', 'string', 'max:4096'],
            // This range does not overlap the existing managed Reverse
            // listener allocation (42000-45000), or Gateway control SSHD.
            'local_socks_port' => ['required', 'integer', 'min:46000', 'max:60999'],
        ];
    }
}
