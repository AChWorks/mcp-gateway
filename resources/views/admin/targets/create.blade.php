@extends('admin.layout')

@section('title', __('Add Target'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Targets') }}</div>
        <h1>{{ __('Add Target') }}</h1>
        <p class="muted">{{ __('Register a WordPress or Direct SSH Target. Every Target has an immutable ID and connector-specific trust boundary.') }}</p>
    </div>
    <a href="{{ route('admin.targets.index') }}">{{ __('Back to Targets') }}</a>
</div>

<section class="panel" aria-labelledby="wp-target-title">
    <h2 id="wp-target-title">{{ __('WordPress (WP AI Bridge)') }}</h2>
    <form class="form-stack" method="post" action="{{ route('admin.targets.store') }}">
        @csrf
        <input type="hidden" name="connector_type" value="wp_ai_bridge">
        <div class="field">
            <label for="wp_target_id">{{ __('Stable Target ID') }}</label>
            <input id="wp_target_id" name="target_id" maxlength="64" pattern="[a-z0-9]+(-[a-z0-9]+)*" required autocomplete="off" spellcheck="false" value="{{ old('connector_type', 'wp_ai_bridge') === 'wp_ai_bridge' ? old('target_id') : '' }}">
            @if(old('connector_type', 'wp_ai_bridge') === 'wp_ai_bridge') @error('target_id')<p class="field-error">{{ $message }}</p>@enderror @endif
        </div>
        <div class="field">
            <label for="wp_display_name">{{ __('Display name') }}</label>
            <input id="wp_display_name" name="display_name" maxlength="160" required value="{{ old('connector_type', 'wp_ai_bridge') === 'wp_ai_bridge' ? old('display_name') : '' }}">
        </div>
        <div class="field">
            <label for="base_url">{{ __('WordPress public HTTPS URL') }}</label>
            <input id="base_url" name="base_url" type="url" maxlength="2048" inputmode="url" placeholder="https://wordpress.example.com" required value="{{ old('base_url') }}">
            @error('base_url')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <button class="button button-primary" type="submit">{{ __('Verify and add WordPress Target') }}</button>
    </form>
</section>

<section class="panel" aria-labelledby="ssh-target-title">
    <h2 id="ssh-target-title">{{ __('Direct SSH') }}</h2>
    <p class="muted">{{ __('The SSH server public host key must be confirmed using a trusted out-of-band source BEFORE enrolling this Target. Registration stores encrypted credentials but does not connect or run commands.') }}</p>
    <form class="form-stack" method="post" action="{{ route('admin.targets.store') }}">
        @csrf
        <input type="hidden" name="connector_type" value="ssh_direct">
        @error('connector_type')<p class="field-error">{{ $message }}</p>@enderror
        <div class="field">
            <label for="ssh_target_id">{{ __('Stable Target ID') }}</label>
            <input id="ssh_target_id" name="target_id" maxlength="64" pattern="[a-z0-9]+(-[a-z0-9]+)*" required autocomplete="off" spellcheck="false" value="{{ old('connector_type') === 'ssh_direct' ? old('target_id') : '' }}">
            @if(old('connector_type') === 'ssh_direct') @error('target_id')<p class="field-error">{{ $message }}</p>@enderror @endif
        </div>
        <div class="field">
            <label for="ssh_display_name">{{ __('Display name') }}</label>
            <input id="ssh_display_name" name="display_name" maxlength="160" required value="{{ old('connector_type') === 'ssh_direct' ? old('display_name') : '' }}">
        </div>
        <div class="field">
            <label for="ssh_host">{{ __('Registered hostname or IP address') }}</label>
            <input id="ssh_host" name="ssh_host" maxlength="253" required autocomplete="off" spellcheck="false" placeholder="server.example.com" value="{{ old('ssh_host') }}">
            @error('ssh_host')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="ssh_port">{{ __('TCP port') }}</label>
            <input id="ssh_port" type="number" name="ssh_port" min="1" max="65535" required value="{{ old('ssh_port', '22') }}">
            @error('ssh_port')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="ssh_username">{{ __('SSH OS username') }}</label>
            <input id="ssh_username" name="ssh_username" maxlength="128" required spellcheck="false" autocomplete="off" value="{{ old('ssh_username') }}">
            @error('ssh_username')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="ssh_host_key">{{ __('Trusted OpenSSH server public host key') }}</label>
            <textarea id="ssh_host_key" name="ssh_host_key" rows="3" maxlength="4096" required spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA...">{{ old('ssh_host_key') }}</textarea>
            <p class="field-help">{{ __('Use the server host PUBLIC key (not your private login key) verified through a separate trusted channel. No automatic trust-on-first-use.') }}</p>
            @error('ssh_host_key')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="ssh_auth_method">{{ __('Authentication method') }}</label>
            <select id="ssh_auth_method" name="ssh_auth_method" required>
                <option value="password" @selected(old('ssh_auth_method') !== 'private_key')>{{ __('Password') }}</option>
                <option value="private_key" @selected(old('ssh_auth_method') === 'private_key')>{{ __('Private key') }}</option>
            </select>
        </div>
        <div class="field" data-ssh-secret="password">
            <label for="ssh_password">{{ __('SSH login password') }}</label>
            <input id="ssh_password" name="ssh_password" type="password" maxlength="4096" autocomplete="new-password">
            @error('ssh_password')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <div class="field" data-ssh-secret="private_key">
            <label for="ssh_private_key">{{ __('SSH private login key (PEM/OpenSSH)') }}</label>
            <textarea id="ssh_private_key" name="ssh_private_key" rows="5" maxlength="16384" spellcheck="false" autocomplete="off"></textarea>
            @error('ssh_private_key')<p class="field-error">{{ $message }}</p>@enderror
            <label for="ssh_passphrase">{{ __('Key passphrase (when encrypted)') }}</label>
            <input id="ssh_passphrase" name="ssh_passphrase" type="password" maxlength="4096" autocomplete="new-password">
        </div>
        <label>
            <input type="checkbox" name="ssh_trust_confirmed" value="yes" required>
            {{ __('I independently verified that this exact server host public key belongs to the intended SSH endpoint.') }}
        </label>
        @error('ssh_trust_confirmed')<p class="field-error">{{ $message }}</p>@enderror
        <button class="button button-primary" type="submit">{{ __('Register encrypted SSH Target') }}</button>
    </form>
    <p class="muted">{{ __('Only approved public TCP destinations can connect. Remote commands and SFTP are not enabled by this registration step.') }}</p>
</section>
<script>
document.addEventListener('DOMContentLoaded', () => {
    const method = document.getElementById('ssh_auth_method');
    if (!method) return;
    const sync = () => {
        document.querySelectorAll('[data-ssh-secret]').forEach(group => {
            const active = group.dataset.sshSecret === method.value;
            group.hidden = !active;
            group.querySelectorAll('input, textarea').forEach(input => {
                input.disabled = !active;
                input.required = active && input.name !== 'ssh_passphrase';
            });
        });
    };
    method.addEventListener('change', sync);
    sync();
});
</script>
@endsection
