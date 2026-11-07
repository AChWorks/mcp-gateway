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
                    <p class="field-help">{{ $relay->enabled ? __('Enabled') : __('Disabled') }}</p>
                </div>
            </div>
            <dl class="summary-list summary-grid">
                <div><dt>{{ __('Relay ID') }}</dt><dd><code>{{ $relay->relay_id }}</code></dd></div>
                <div><dt>{{ __('Relay SSH') }}</dt><dd><code>{{ $relay->control_user.'@'.$relay->control_host.':'.$relay->control_port }}</code></dd></div>
                <div><dt>{{ __('Local SOCKS5') }}</dt><dd><code>127.0.0.1:{{ $relay->local_socks_port }}</code></dd></div>
                <div><dt>{{ __('Assigned Targets') }}</dt><dd>{{ $counts[$relay->id] ?? 0 }}</dd></div>
            </dl>

            <details class="target-help-details">
                <summary>{{ __('Set up or reconnect with OpenSSH') }}</summary>
                <p class="field-help">{{ __('Run these commands on the Gateway host using the Unix account that will maintain this SSH tunnel. This uses ordinary OpenSSH, not a Gateway-managed firewall or installer.') }}</p>
                <div class="field">
                    <label for="relay-prepare-{{ $relay->id }}">{{ __('1. Prepare a local SSH key and pinned host key') }}</label>
                    <textarea id="relay-prepare-{{ $relay->id }}" readonly spellcheck="false" rows="4">{{ $commands[$relay->id]['prepare'] }}</textarea>
                    <p class="field-help">{{ __('Add only the printed PUBLIC key to the Relay server SSH account authorized_keys. Keep the private key on the Gateway host. Verify the Relay server host key independently before saving it here.') }}</p>
                </div>
                <div class="field">
                    <label for="relay-connect-{{ $relay->id }}">{{ __('2. Connect Gateway to Relay') }}</label>
                    <textarea id="relay-connect-{{ $relay->id }}" readonly spellcheck="false" rows="5">{{ $commands[$relay->id]['start'] }}</textarea>
                    <p class="field-help">{{ __('The command stays in the foreground until disconnected. For continuous service, run it under your existing process supervisor; restart it there after a failure or configuration edit. Gateway does not start, stop or install system services.') }}</p>
                </div>
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
                    <p class="field-help">{{ __('Change the host, SSH account, pinned host key or local port. Restart the OpenSSH command after saving. Assigned Targets keep this Relay and can be retested normally.') }}</p>
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
