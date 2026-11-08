@extends('admin.layout')

@section('title', __('Connection Relays'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('System') }}</div>
        <h1>{{ __('Connection Relays') }}</h1>
        <p class="muted reading-width">{{ __('Use a reachable SSH server as a shared connection hop for SSH, SFTP or WordPress Targets. Each Target keeps its selected route until you change it.') }}</p>
    </div>
    <div class="action-row">
        <a href="#relay-add-heading" class="button button-primary">{{ __('Add Relay') }}</a>
        <a href="{{ route('admin.targets.create') }}">{{ __('Add Target') }}</a>
    </div>
</div>

<section class="panel panel-wide" aria-labelledby="relay-list-heading">
    <h2 id="relay-list-heading">{{ __('Registered Relays') }} ({{ $relays->count() }})</h2>
    @forelse ($relays as $relay)
        <article class="target-subsection" aria-labelledby="relay-title-{{ $relay->id }}">
            <div class="section-heading">
                <div>
                    <h3 id="relay-title-{{ $relay->id }}">{{ $relay->display_name }}</h3>
                    <p class="relay-state" role="status"><span class="badge {{ $relay->enabled ? 'badge-success' : 'badge-neutral' }}">{{ $relay->enabled ? __('Enabled for Targets') : __('Disabled for Targets') }}</span> <span class="field-help">{{ __('This status is a routing setting, not proof that the local tunnel is running.') }}</span></p>
                </div>
            </div>
            <dl class="summary-list summary-grid">
                <div><dt>{{ __('Relay ID') }}</dt><dd><code>{{ $relay->relay_id }}</code></dd></div>
                <div><dt>{{ __('Relay SSH') }}</dt><dd><code>{{ $relay->control_user.'@'.$relay->control_host.':'.$relay->control_port }}</code></dd></div>
                <div><dt>{{ __('Local SOCKS5') }}</dt><dd><code>127.0.0.1:{{ $relay->local_socks_port }}</code></dd></div>
                <div><dt>{{ __('Assigned Targets') }}</dt><dd>{{ $counts[$relay->id] ?? 0 }}</dd></div>
            </dl>

            <details class="target-help-details relay-setup-details" @if ($commands[$relay->id] === null) open @endif>
                <summary>{{ __('Two-command Relay setup (no open terminal required)') }}</summary>
                @if ($commands[$relay->id] !== null)
                    <p class="field-help">{{ __('Run exactly one complete command on each indicated host. Start with the Relay host, then the Gateway host. The Gateway command installs a persistent OpenSSH service that survives terminal close and host reboot; private keys never appear in this page.') }}</p>
                    <ol class="relay-setup-steps">
                        <li>
                            <div class="field">
                                <label for="relay-peer-{{ $relay->id }}">{{ __('On the intermediary Relay server (SSH account setup)') }}</label>
                                <textarea id="relay-peer-{{ $relay->id }}" readonly spellcheck="false" rows="7">{{ $commands[$relay->id]['relay'] }}</textarea>
                                <div class="action-row"><button type="button" class="button button-secondary" data-copy-command="relay-peer-{{ $relay->id }}">{{ __('Copy Relay command') }}</button><output role="status" aria-live="polite" data-copy-status-for="relay-peer-{{ $relay->id }}"></output></div>
                                <p class="field-help">{{ __('Sets up this Relay account’s authorized public login key. Use a trusted shell on the Relay server; the account and SSHD forwarding must already be available.') }}</p>
                            </div>
                        </li>
                        <li>
                            <div class="field">
                                <label for="relay-connect-{{ $relay->id }}">{{ __('On the Gateway server (install and start persistent tunnel)') }}</label>
                                <textarea id="relay-connect-{{ $relay->id }}" readonly spellcheck="false" rows="3">{{ $commands[$relay->id]['gateway'] }}</textarea>
                                <div class="action-row"><button type="button" class="button button-secondary" data-copy-command="relay-connect-{{ $relay->id }}">{{ __('Copy Gateway command') }}</button><output role="status" aria-live="polite" data-copy-status-for="relay-connect-{{ $relay->id }}"></output></div>
                                <p class="field-help">{{ __('Installs the exact registered Relay identity, pinned server key and automatic service startup. No manual SSH key copy, systemd editing or foreground tunnel is needed. If an old manual tunnel already occupies this port, stop that exact process before running this command.') }}</p>
                            </div>
                        </li>
                    </ol>
                    <p class="field-help">{{ __('After both commands succeed, Test local Relay connection and verify SSH/SFTP or WordPress on the actual Target. Enabled is a routing choice, not a live host health probe.') }}</p>
                @else
                    <p class="field-help">{{ __('This Relay was registered before the two-command setup. Prepare a new encrypted Gateway client key and matching public-key command. Your existing manual tunnel is not stopped by this action.') }}</p>
                    <form method="post" class="form-stack" action="{{ route('admin.connection-relays.prepare', ['relay' => $relay->id]) }}">
                        @csrf
                        <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                        <div class="field">
                            <label for="relay-prepare-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                            <input id="relay-prepare-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                        </div>
                        <button class="button button-secondary" type="submit">{{ __('Prepare the two complete setup commands') }}</button>
                    </form>
                @endif
            </details>

            <form method="post" class="form-stack" action="{{ route('admin.connection-relays.test', ['relay' => $relay->id]) }}">
                @csrf
                <button class="button button-secondary" type="submit">{{ __('Test local Relay connection') }}</button>
                <p class="field-help">{{ __('Checks the local SOCKS5 tunnel, even while this Relay is disabled. Test the actual SSH/SFTP/WordPress connection on each Target separately.') }}</p>
            </form>

            <form method="post" class="form-stack" action="{{ route('admin.connection-relays.toggle', ['relay' => $relay->id]) }}">
                @csrf
                <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                <input type="hidden" name="enable" value="{{ $relay->enabled ? '0' : '1' }}">
                <div class="field">
                    <label for="relay-toggle-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                    <input id="relay-toggle-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                </div>
                <button class="button {{ $relay->enabled ? 'button-secondary' : 'button-primary' }}" type="submit">{{ $relay->enabled ? __('Disable Relay') : __('Enable Relay for Targets') }}</button>
            </form>

            <details class="target-help-details">
                <summary>{{ __('Rename Relay') }}</summary>
                <form method="post" class="form-stack" action="{{ route('admin.connection-relays.rename', ['relay' => $relay->id]) }}" autocomplete="off">
                    @csrf
                    @method('PUT')
                    <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                    <div class="field">
                        <label for="relay-name-{{ $relay->id }}">{{ __('Display name') }}</label>
                        <input id="relay-name-{{ $relay->id }}" type="text" name="display_name" value="{{ $relay->display_name }}" maxlength="160" autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ $relay->display_name }}" required>
                    </div>
                    <div class="field">
                        <label for="relay-rename-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                        <input id="relay-rename-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                    </div>
                    <button class="button button-secondary" type="submit">{{ __('Save display name') }}</button>
                </form>
            </details>

            @if (! $relay->enabled)
                <details class="target-help-details">
                    <summary>{{ __('Edit Relay connection') }}</summary>
                    <p class="field-help">{{ __('Change the host, SSH account, pinned host key or local port. After saving, rerun the two displayed host commands to reconcile the persistent SSH service. Assigned Targets stay selected and can be retested normally.') }}</p>
                    <form class="form-stack" method="post" action="{{ route('admin.connection-relays.update', ['relay' => $relay->id]) }}" autocomplete="off">
                        @csrf
                        @method('PUT')
                        <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                        <input type="hidden" name="edit_relay_id" value="{{ $relay->getKey() }}">
                        @include('admin.connection-relays.partials.fields', ['prefix' => 'edit-'.$relay->id, 'editing' => true])
                        <div class="field">
                            <label for="relay-edit-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                            <input id="relay-edit-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                        </div>
                        <button class="button button-primary" type="submit">{{ __('Save Relay settings') }}</button>
                    </form>
                </details>

                @if ((int) ($counts[$relay->id] ?? 0) === 0)
                    <details class="target-help-details">
                        <summary>{{ __('Delete Relay') }}</summary>
                        <p class="field-help">{{ __('This removes the Gateway record. Stop its old SSH tunnel separately if it is still running. No connection to the intermediary is required to delete the record.') }}</p>
                        <form method="post" class="form-stack" action="{{ route('admin.connection-relays.destroy', ['relay' => $relay->id]) }}" autocomplete="off">
                            @csrf
                            @method('DELETE')
                            <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                            <div class="field">
                                <label for="relay-confirm-delete-{{ $relay->id }}">{{ __('Type Relay ID to confirm: :id', ['id' => $relay->relay_id]) }}</label>
                                <input id="relay-confirm-delete-{{ $relay->id }}" type="text" name="confirm_relay_id" maxlength="64" required autocomplete="off" spellcheck="false">
                            </div>
                            <div class="field">
                                <label for="relay-delete-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                                <input id="relay-delete-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                            </div>
                            <button class="button button-danger" type="submit">{{ __('Delete Relay') }}</button>
                        </form>
                    </details>
                @else
                    <p class="field-help">{{ __('Reassign or detach :count Target(s) before deleting this Relay.', ['count' => $counts[$relay->id]]) }}</p>
                    <a href="{{ route('admin.targets.index') }}">{{ __('Manage Targets') }}</a>
                @endif
            @else
                <p class="field-help">{{ __('Disable this Relay before editing or deleting it. Existing Target settings are retained.') }}</p>
            @endif
        </article>
    @empty
        <p class="muted">{{ __('No Relays yet. Add a reusable SSH hop below.') }}</p>
    @endforelse
</section>

<section class="panel panel-wide" aria-labelledby="relay-add-heading">
    <h2 id="relay-add-heading">{{ __('Add Connection Relay') }}</h2>
    <p class="field-help">{{ __('Before saving, obtain the PUBLIC SSH host key from the trusted console of the intermediary server and check its fingerprint. The form creates the Gateway client login identity separately. After saving, you will receive two complete host-specific setup commands; no private login key will be displayed.') }}</p>
    <form class="form-stack" method="post" action="{{ route('admin.connection-relays.store') }}" autocomplete="off">
        @csrf
        @include('admin.connection-relays.partials.fields', ['prefix' => 'add', 'editing' => false, 'relay' => null])
        <div class="field">
            <label for="relay-add-password">{{ __('Current Owner password') }}</label>
            <input id="relay-add-password" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
        </div>
        <button class="button button-primary" type="submit">{{ __('Add Relay') }}</button>
    </form>
</section>
@endsection
