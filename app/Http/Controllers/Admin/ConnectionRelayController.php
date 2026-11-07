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
    public function index(Request $request): View
    {
        $this->authorizeOwner($request);

        $relays = ConnectionRelay::query()->orderBy('display_name')->get();

        return view('admin.connection-relays.index', [
            'relays' => $relays,
            'commands' => $relays->mapWithKeys(
                fn (ConnectionRelay $relay): array => [$relay->id => $this->sshCommands($relay)],
            ),
            'counts' => DB::table('targets')->whereNotNull('relay_record_id')
                ->selectRaw('relay_record_id, count(*) as total')
                ->groupBy('relay_record_id')->pluck('total', 'relay_record_id'),
        ]);
    }

    public function store(
        Request $request, AdministratorPasswordConfirmation $password, ActivityRecorder $activity,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate($this->rules());
        $password->confirm($request);
        [$endpoint, $pin] = $this->validatedEndpointAndPin($fields);
        $this->assertUnique($fields);

        try {
            DB::transaction(static function () use ($fields, $endpoint, $pin, $activity): void {
                ConnectionRelay::query()->create([
                    'relay_id' => $fields['relay_id'],
                    'display_name' => $fields['display_name'],
                    'control_host' => $endpoint->host,
                    'control_port' => $endpoint->port,
                    'control_user' => $endpoint->username,
                    'control_host_key' => $pin->canonicalLine(),
                    'local_socks_port' => (int) $fields['local_socks_port'],
                ]);
                $activity->recordRequired(CorrelationId::current(), 'connection-relay-register', 'success');
            }, 3);
        } catch (UniqueConstraintViolationException) {
            $this->assertUnique($fields);
            throw ValidationException::withMessages(['relay' => __('Another Relay was saved concurrently. Refresh and retry.')]);
        }

        return redirect()->route('admin.connection-relays.index')
            ->with('status', __('Relay saved disabled. Prepare the SSH key and start the native OpenSSH tunnel, then enable and test the Relay.'));
    }

    public function toggle(
        Request $request, ConnectionRelay $relay, AdministratorPasswordConfirmation $password,
        ConnectionRelayAdministration $administration, ActivityRecorder $activity,
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
                $changed = $administration->disable($relay, $revision);
            } catch (TargetConnectorFailure $exception) {
                throw ValidationException::withMessages([$exception->field ?? 'relay' => $exception->getMessage()]);
            }

            return back()->with('status', $changed
                ? __('Relay disabled. Assigned Targets remain assigned; reconnect after re-enabling.')
                : __('Relay was already disabled.'));
        }

        DB::transaction(static function () use ($relay, $revision, $activity): void {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $current->lifecycle_revision !== $revision) {
                throw ValidationException::withMessages(['relay_revision' => __('Relay settings changed. Refresh and retry.')]);
            }
            if ($current->enabled) {
                return;
            }
            if ((int) $current->lifecycle_revision >= 4294967295) {
                throw ValidationException::withMessages(['relay_revision' => __('Relay revision is exhausted.')]);
            }
            if (DB::table('targets')->where('relay_record_id', $current->getKey())
                ->where('relay_binding_revision', '>=', 4294967295)->exists()) {
                throw ValidationException::withMessages([
                    'relay' => __('Cannot enable this Relay while an assigned Target binding revision is exhausted.'),
                ]);
            }
            DB::table('connection_relays')->where('id', $current->getKey())->update([
                'enabled' => true,
                'lifecycle_revision' => (int) $current->lifecycle_revision + 1,
                'updated_at' => now(),
            ]);
            $activity->recordRequired(CorrelationId::current(), 'connection-relay-enable', 'success');
        }, 3);

        return back()->with('status', __('Relay enabled. Test the SSH tunnel and the selected Target normally.'));
    }

    public function test(Request $request, ConnectionRelay $relay): RedirectResponse
    {
        $this->authorizeOwner($request);
        // The same simple listener check works before and after enabling.
        // Target-specific SSH/TLS credentials are tested on the Target page.
        $port = (int) $relay->local_socks_port;
        $number = 0;
        $message = '';
        $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $number, $message, 2);
        if (! is_resource($socket)) {
            return back()->withErrors(['relay' => __('Cannot reach the local SSH SOCKS5 tunnel. Start or reconnect the Relay and test again.')]);
        }
        try {
            stream_set_timeout($socket, 2);
            $written = fwrite($socket, "\x05\x01\x00");
            $reply = $written === 3 ? fread($socket, 2) : false;
        } finally {
            fclose($socket);
        }
        if ($reply !== "\x05\x00") {
            return back()->withErrors(['relay' => __('The local tunnel did not respond as SOCKS5. Check the SSH command and try again.')]);
        }

        return back()->with('status', __('Local Relay tunnel responded. Test SSH, SFTP or WordPress on the Target page to verify the full connection.'));
    }

    public function update(
        Request $request, ConnectionRelay $relay, AdministratorPasswordConfirmation $password,
        ActivityRecorder $activity,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate([
            ...$this->rules(), 'relay_revision' => ['required', 'integer', 'min:1'],
        ]);
        $password->confirm($request);
        [$endpoint, $pin] = $this->validatedEndpointAndPin($fields);

        try {
            $changed = DB::transaction(static function () use ($relay, $fields, $endpoint, $pin, $activity): bool {
                $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
                if ($current->enabled || (int) $current->lifecycle_revision !== (int) $fields['relay_revision']) {
                    throw ValidationException::withMessages(['relay' => __('Disable this Relay and refresh before editing connection settings.')]);
                }
                if ($current->relay_id !== $fields['relay_id']) {
                    throw ValidationException::withMessages(['relay_id' => __('Relay ID is fixed. Create another Relay to use a different ID.')]);
                }
                if ((int) $current->lifecycle_revision >= 4294967295) {
                    throw ValidationException::withMessages(['relay_revision' => __('Relay revision is exhausted.')]);
                }
                $values = [
                    'display_name' => (string) $fields['display_name'],
                    'control_host' => $endpoint->host,
                    'control_port' => $endpoint->port,
                    'control_user' => $endpoint->username,
                    'control_host_key' => $pin->canonicalLine(),
                    'local_socks_port' => (int) $fields['local_socks_port'],
                ];
                if (ConnectionRelay::query()->whereKeyNot($current->getKey())
                    ->where('local_socks_port', $values['local_socks_port'])->exists()) {
                    throw ValidationException::withMessages(['local_socks_port' => __('This SOCKS5 port is already assigned.')]);
                }
                $old = $current->only(array_keys($values));
                if ($old == $values) {
                    return false;
                }
                DB::table('connection_relays')->where('id', $current->getKey())->update([
                    ...$values,
                    'lifecycle_revision' => (int) $current->lifecycle_revision + 1,
                    'updated_at' => now(),
                ]);
                $activity->recordRequired(CorrelationId::current(), 'connection-relay-update', 'success');

                return true;
            }, 3);
        } catch (UniqueConstraintViolationException) {
            throw ValidationException::withMessages(['local_socks_port' => __('This SOCKS5 port was assigned concurrently. Refresh and retry.')]);
        }

        return redirect()->route('admin.connection-relays.index')
            ->with('status', $changed
                ? __('Relay updated. Restart its native SSH tunnel with the current settings, then test and enable.')
                : __('No Relay settings changed.'));
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

        DB::transaction(static function () use ($relay, $fields, $activity): void {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $current->lifecycle_revision !== (int) $fields['relay_revision']) {
                throw ValidationException::withMessages(['relay_revision' => __('Relay settings changed. Refresh and retry.')]);
            }
            if ($current->display_name === $fields['display_name']) {
                return;
            }
            DB::table('connection_relays')->where('id', $current->getKey())->update([
                'display_name' => $fields['display_name'],
                'lifecycle_revision' => (int) $current->lifecycle_revision + 1,
                'updated_at' => now(),
            ]);
            $activity->recordRequired(CorrelationId::current(), 'connection-relay-rename', 'success');
        }, 3);

        return redirect()->route('admin.connection-relays.index')
            ->with('status', __('Relay name updated without interrupting its connection.'));
    }

    public function destroy(
        Request $request, ConnectionRelay $relay, AdministratorPasswordConfirmation $password,
        ActivityRecorder $activity,
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $fields = $request->validate([
            'relay_revision' => ['required', 'integer', 'min:1'],
            'confirm_relay_id' => ['required', 'string', 'max:64'],
        ]);
        $password->confirm($request);

        DB::transaction(static function () use ($relay, $fields, $activity): void {
            $current = ConnectionRelay::query()->whereKey($relay->getKey())->lockForUpdate()->firstOrFail();
            if ((int) $current->lifecycle_revision !== (int) $fields['relay_revision']) {
                throw ValidationException::withMessages(['relay_revision' => __('Relay settings changed. Refresh and retry.')]);
            }
            if (! hash_equals($current->relay_id, (string) $fields['confirm_relay_id'])) {
                throw ValidationException::withMessages(['confirm_relay_id' => __('Type the exact Relay ID to confirm.')]);
            }
            if ($current->enabled) {
                throw ValidationException::withMessages(['relay' => __('Disable the Relay first.')]);
            }
            if (DB::table('targets')->where('relay_record_id', $current->getKey())->exists()) {
                throw ValidationException::withMessages(['relay' => __('Reassign or detach assigned Targets first.')]);
            }
            $current->delete();
            $activity->recordRequired(CorrelationId::current(), 'connection-relay-delete-registration', 'success');
        }, 3);

        return redirect()->route('admin.connection-relays.index')
            ->with('status', __('Relay removed from Gateway. Stop the old SSH tunnel separately if it is still running; no intermediary connection is required.'));
    }

    /** @param array<string,mixed> $fields
     * @return array{SshRegisteredEndpoint,SshHostKeyPin}
     */
    private function validatedEndpointAndPin(array $fields): array
    {
        try {
            $endpoint = SshRegisteredEndpoint::fromInput(
                (string) $fields['control_host'], (int) $fields['control_port'], (string) $fields['control_user'],
            );
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['control_host' => __('Enter a valid Relay SSH hostname or IP address.')]);
        }
        try {
            $pin = SshHostKeyPin::fromLine((string) $fields['control_host_key']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['control_host_key' => __('Enter the independently verified public SSH host key.')]);
        }

        return [$endpoint, $pin];
    }

    /** @param array<string,mixed> $fields */
    private function assertUnique(array $fields): void
    {
        if (ConnectionRelay::query()->where('relay_id', $fields['relay_id'])->exists()) {
            throw ValidationException::withMessages(['relay_id' => __('This Relay ID is already in use.')]);
        }
        if (ConnectionRelay::query()->where('local_socks_port', (int) $fields['local_socks_port'])->exists()) {
            throw ValidationException::withMessages(['local_socks_port' => __('This local SOCKS5 port is already in use.')]);
        }
    }

    /** @return array{prepare:string,start:string,stop:string} */
    private function sshCommands(ConnectionRelay $relay): array
    {
        $directory = '"$HOME/.ssh/mcp-gateway-relays"';
        $key = '"$HOME/.ssh/mcp-gateway-relays/'.$relay->relay_id.'"';
        $known = '"$HOME/.ssh/mcp-gateway-relays/'.$relay->relay_id.'.known_hosts"';
        $alias = 'mcp-relay-'.$relay->relay_id;
        $pin = escapeshellarg($alias.' '.$relay->control_host_key);

        $prepare = 'mkdir -p '.$directory.' && chmod 700 '.$directory
            .' && { test -f '.$key.' || ssh-keygen -q -t ed25519 -N '.escapeshellarg('').' -f '.$key.'; }'
            ." && printf '%s\\n' ".$pin.' > '.$known
            .' && cat '.$key.'.pub';

        $start = 'ssh -N -T -D 127.0.0.1:'.$relay->local_socks_port
            .' -p '.$relay->control_port.' -i '.$key
            .' -o IdentitiesOnly=yes -o BatchMode=yes'
            .' -o StrictHostKeyChecking=yes -o UserKnownHostsFile='.$known
            .' -o HostKeyAlias='.escapeshellarg($alias)
            .' -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 '
            .' -l '.escapeshellarg($relay->control_user).' '.escapeshellarg($relay->control_host);

        return [
            'prepare' => $prepare,
            'start' => $start,
            'stop' => __('Stop the native SSH process or its existing supervisor before removing the local key.'),
        ];
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
            'local_socks_port' => ['required', 'integer', 'min:46000', 'max:60999'],
        ];
    }
}
