@extends('admin.layout')

@section('title', __('Edit Target'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target administration') }}</div>
        <h1>{{ __('Edit Target') }}</h1>
        <p class="muted">{{ __('Keep the stable Target ID, connector, group assignments and existing access rules. Updating connection settings may require new authentication.') }}</p>
    </div>
    <a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Back to Target') }}</a>
</div>

<section class="panel panel-wide target-enrollment" aria-label="{{ __('Target identity') }}">
    <h2>{{ __('Display and identity') }}</h2>
    <form method="post" action="{{ route('admin.targets.update', ['target' => $target->target_id]) }}" class="form-stack">
        @csrf
        @method('PUT')
        <div class="field">
            <label for="target_id">{{ __('Stable Target ID') }}</label>
            <input id="target_id" type="text" value="{{ $target->target_id }}" readonly aria-readonly="true">
            <p class="field-help">{{ __('Target ID and connector type do not change. Existing users, groups and client references keep pointing at this Target.') }}</p>
        </div>
        <div class="field">
            <label for="display_name">{{ __('Display name') }}</label>
            <input id="display_name" name="display_name" type="text" required maxlength="160"
                value="{{ old('display_name', $target->display_name) }}">
            @error('display_name')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Save display name') }}</button>
        </div>
    </form>
</section>

@can('security.manage')
@if (! empty($configurationRevision))
    <section class="panel panel-wide target-enrollment" aria-label="{{ __('Connector settings') }}">
        <h2>{{ __('Connection settings') }}</h2>
        <p class="field-help">{{ __('Only Owners can rotate connector endpoints and encrypted credentials. Changes are audited and require the current Owner password. Existing Target access permissions remain unchanged.') }}</p>

        @if ($target->connector_type === 'ssh_direct' && isset($sshConfig))
            <form id="ssh-reconfiguration" class="form-stack" method="post"
                action="{{ route('admin.targets.configuration.update', ['target' => $target->target_id]) }}">
                @csrf
                @method('PUT')
                <input type="hidden" name="configuration_revision" value="{{ $configurationRevision }}">
                @error('configuration_revision')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                @error('configuration')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                <p class="field-help">{{ __('Changing the SSH port, host, username, host key or login secret clears the old connection verification. Verify the new host and login afterward. Leave secret fields empty to retain the current encrypted login credential when the method is unchanged.') }}</p>
                <div class="target-field-grid">
                    <div class="field">
                        <label for="ssh_edit_host">{{ __('SSH host or IP address') }}</label>
                        <input id="ssh_edit_host" name="ssh_host" type="text" maxlength="253" required spellcheck="false"
                            autocomplete="off" value="{{ old('ssh_host', $sshConfig->host) }}">
                        @error('ssh_host')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <div class="field">
                        <label for="ssh_edit_port">{{ __('TCP port') }}</label>
                        <input id="ssh_edit_port" name="ssh_port" type="number" min="1" max="65535" required
                            value="{{ old('ssh_port', $sshConfig->port) }}">
                        @error('ssh_port')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <div class="field target-span-all">
                        <label for="ssh_edit_username">{{ __('SSH OS username') }}</label>
                        <input id="ssh_edit_username" name="ssh_username" type="text" maxlength="128" required
                            autocomplete="off" spellcheck="false" value="{{ old('ssh_username', $sshConfig->username) }}">
                        @error('ssh_username')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                </div>
                <div class="target-subsection">
                    <h3>{{ __('Trusted server identity') }}</h3>
                    <p class="field-help">{{ __('This is the server PUBLIC host key, not your PRIVATE login key. Verify any change through an independent server console before confirming.') }}</p>
                    <p class="field-help">{{ __('Currently pinned SHA256 fingerprint:') }} <code>{{ $sshFingerprint }}</code></p>
                    <div class="field">
                        <label for="ssh_edit_host_key">{{ __('Verified OpenSSH server public host key') }}</label>
                        <textarea id="ssh_edit_host_key" name="ssh_host_key" rows="3" maxlength="4096"
                            required spellcheck="false" autocomplete="off">{{ old('ssh_host_key', $sshConfig->pinned_host_key) }}</textarea>
                        @error('ssh_host_key')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <label class="target-trust-confirmation">
                        <input type="checkbox" name="ssh_trust_confirmed" value="yes" required
                            @checked(old('ssh_trust_confirmed') === 'yes')>
                        <span>{{ __('I independently verified the intended SSH endpoint and this exact server public host key.') }}</span>
                    </label>
                    @error('ssh_trust_confirmed')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="target-subsection">
                    <h3>{{ __('Login credential') }}</h3>
                    <div class="field">
                        <label for="ssh_edit_auth_method">{{ __('SSH authentication method') }}</label>
                        <select id="ssh_edit_auth_method" name="ssh_auth_method" required>
                            <option value="password" @selected(old('ssh_auth_method', $sshConfig->auth_method) === 'password')>{{ __('Password only') }}</option>
                            <option value="private_key" @selected(old('ssh_auth_method', $sshConfig->auth_method) === 'private_key')>{{ __('Private key only') }}</option>
                        </select>
                        <p class="field-help">{{ __('Switching login method requires a new password or private key. This form never displays or restores stored secrets.') }}</p>
                        @error('ssh_auth_method')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <div class="field" data-edit-ssh-credential="password">
                        <label for="ssh_edit_password">{{ __('New SSH login password (optional if unchanged)') }}</label>
                        <input id="ssh_edit_password" type="password" name="ssh_password" maxlength="4096"
                            autocomplete="new-password">
                        @error('ssh_password')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <div class="field" data-edit-ssh-credential="private_key">
                        <label for="ssh_edit_private_key">{{ __('New SSH private login key (optional if unchanged)') }}</label>
                        <textarea id="ssh_edit_private_key" name="ssh_private_key" rows="5" maxlength="16384"
                            spellcheck="false" autocomplete="off"></textarea>
                        @error('ssh_private_key')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                        <label for="ssh_edit_passphrase">{{ __('Passphrase for a newly submitted encrypted key') }}</label>
                        <input id="ssh_edit_passphrase" type="password" name="ssh_passphrase" maxlength="4096"
                            autocomplete="new-password">
                        @error('ssh_passphrase')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                </div>
                <div class="field">
                    <label for="ssh_config_owner_password">{{ __('Current Owner password') }}</label>
                    <input id="ssh_config_owner_password" type="password" name="current_password" required maxlength="255"
                        autocomplete="current-password">
                    @error('current_password')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="target-create-actions">
                    <button class="button button-primary" type="submit">{{ __('Save SSH settings and require re-verification') }}</button>
                </div>
            </form>
            <script>
            document.addEventListener('DOMContentLoaded', () => {
                const form = document.getElementById('ssh-reconfiguration');
                if (!form) return;
                const method = form.querySelector('#ssh_edit_auth_method');
                const trust = form.querySelector('input[name="ssh_trust_confirmed"]');
                const sync = () => {
                    form.querySelectorAll('[data-edit-ssh-credential]').forEach(group => {
                        const active = group.dataset.editSshCredential === method.value;
                        group.hidden = !active;
                        group.querySelectorAll('input,textarea').forEach(field => field.disabled = !active);
                    });
                };
                method.addEventListener('change', sync);
                ['ssh_host','ssh_port','ssh_username','ssh_host_key'].forEach(name => {
                    form.querySelector('[name="' + name + '"]').addEventListener('input', () => {
                        trust.checked = false;
                    });
                });
                sync();
            });
            </script>
        @elseif ($target->connector_type === 'wp_ai_bridge' && isset($wpConfig))
            @php
                $canChangeWordpressOrigin = in_array($target->connection_state->value, ['disconnected', 'error'], true)
                    && ! ($hasCredential ?? false) && ! ($revocationPending ?? false) && ! ($refreshPending ?? false)
                    && ! ($oauthFlowPending ?? false) && ! ($refreshIntent ?? null);
            @endphp
            @if (! $canChangeWordpressOrigin)
                <div class="alert alert-caution" role="status">
                    {{ __('WordPress OAuth is still connected or pending. First use Disconnect WordPress from Target details and wait for confirmed remote token revocation/recovery. Only then can the HTTPS origin change safely. Your users and group assignments stay intact.') }}
                </div>
            @else
                <form class="form-stack" method="post"
                    action="{{ route('admin.targets.configuration.update', ['target' => $target->target_id]) }}">
                    @csrf
                    @method('PUT')
                    <input type="hidden" name="configuration_revision" value="{{ $configurationRevision }}">
                    @error('configuration_revision')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    @error('configuration')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    <div class="field">
                        <label for="wp_edit_origin">{{ __('WordPress public HTTPS URL') }}</label>
                        <input id="wp_edit_origin" name="base_url" type="url" maxlength="2048" required inputmode="url"
                            value="{{ old('base_url', $wpConfig->base_url) }}">
                        <p class="field-help">{{ __('The new HTTPS origin is independently discovered and validated. Existing OAuth credentials are never reused; authorize WordPress again afterward.') }}</p>
                        @error('base_url')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <div class="field">
                        <label for="wp_config_owner_password">{{ __('Current Owner password') }}</label>
                        <input id="wp_config_owner_password" type="password" name="current_password" required maxlength="255"
                            autocomplete="current-password">
                        @error('current_password')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <button class="button button-primary" type="submit">{{ __('Verify and save WordPress origin') }}</button>
                </form>
            @endif
        @endif
    </section>
@else
    <p class="muted">{{ __('This historical connector does not offer a configuration editor while its adapter is paused.') }}</p>
@endif
@endcan
@endsection
