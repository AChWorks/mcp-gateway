@extends('admin.layout')

@section('title', __('Add Target'))

@section('content')
@php
    $requestedConnector = old('connector_type', $selectedConnector);
    $selected = is_string($requestedConnector) && array_key_exists($requestedConnector, $connectorOptions)
        ? $requestedConnector : '';
@endphp
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Targets') }}</div>
        <h1>{{ __('Add Target') }}</h1>
        <p class="muted">{{ __('Choose a connector, then provide only the details it needs. Registration never executes remote commands.') }}</p>
    </div>
    <a href="{{ route('admin.targets.index') }}">{{ __('Back to Targets') }}</a>
</div>

<section class="panel panel-wide target-enrollment" aria-labelledby="target-enrollment-title">
    <h2 id="target-enrollment-title">{{ __('New connection') }}</h2>
    <form id="target-create-form" method="post" action="{{ route('admin.targets.store') }}" class="form-stack">
        @csrf
        <div class="field">
            <label for="connector_type">{{ __('1. Connector type') }}</label>
            <select id="connector_type" name="connector_type" required aria-describedby="connector_type_help">
                <option value="">{{ __('Choose a connector') }}</option>
                @foreach ($connectorOptions as $type => $label)
                    <option value="{{ $type }}" @selected($selected === $type)>{{ $label }}</option>
                @endforeach
            </select>
            <p id="connector_type_help" class="field-help">{{ __('The next fields change with your selection. Only implemented connectors can be enrolled.') }}</p>
            @error('connector_type')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            <noscript>
                <p class="field-help">{{ __('JavaScript is disabled. Choose a connector below to open its server-rendered form:') }}</p>
                @foreach ($connectorOptions as $type => $label)
                    <a class="button button-secondary" href="{{ route('admin.targets.create', ['connector_type' => $type]) }}">{{ $label }}</a>
                @endforeach
            </noscript>
        </div>

        <fieldset class="target-form-section" data-target-shared @if($selected === '') hidden disabled @endif>
            <legend>{{ __('2. Target details') }}</legend>
            <p class="field-help">{{ __('A stable ID identifies this Target across clients and permissions; the display name can change later.') }}</p>
            <div class="target-field-grid">
                <div class="field">
                    <label for="target_id">{{ __('Stable Target ID') }}</label>
                    <input type="text" id="target_id" name="target_id" maxlength="64" pattern="[a-z0-9]+(-[a-z0-9]+)*" required
                        autocomplete="off" spellcheck="false" placeholder="my-target" value="{{ old('target_id') }}">
                    <p class="field-help">{{ __('Lowercase letters, numbers and hyphens.') }}</p>
                    @error('target_id')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field">
                    <label for="display_name">{{ __('Display name') }}</label>
                    <input type="text" id="display_name" name="display_name" maxlength="160" required
                        placeholder="{{ __('Production blog or staging server') }}" value="{{ old('display_name') }}">
                    @error('display_name')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field target-span-all">
                    <label for="ai_guidance">{{ __('AI guidance (optional)') }}</label>
                    <textarea id="ai_guidance" name="ai_guidance" rows="3"
                        maxlength="{{ \App\Domain\Targets\Target::AI_GUIDANCE_MAX_LENGTH }}"
                        aria-describedby="ai_guidance_help" autocomplete="off"
                        placeholder="{{ __('Example: This is a production server. Explain risks and ask before making changes.') }}">{{ old('ai_guidance') }}</textarea>
                    <p id="ai_guidance_help" class="field-help">{{ __('Shown to authorized AI clients as Target-specific context. This is advice, not enforced approval. Never include credentials or secrets.') }}</p>
                    @error('ai_guidance')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
            </div>
        </fieldset>

        <fieldset class="target-form-section" data-connector-panel="wp_ai_bridge" @if($selected !== 'wp_ai_bridge') hidden disabled @endif>
            <legend>{{ __('3. WordPress (WP AI Bridge)') }}</legend>
            <p class="field-help">{{ __('Use the public HTTPS URL of a WordPress site with WP AI Bridge installed. Authorization is completed after registration.') }}</p>
            <div class="field">
                <label for="base_url">{{ __('WordPress public HTTPS URL') }}</label>
                <input type="url" id="base_url" name="base_url" maxlength="2048" inputmode="url"
                    autocomplete="url" placeholder="https://wordpress.example.com" required value="{{ old('base_url') }}">
                @error('base_url')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <button class="button button-secondary" type="submit"
                formaction="{{ route('admin.targets.preflight') }}" formnovalidate>
                {{ __('Check DNS from Gateway (no registration)') }}
            </button>
            @if (session('target_dns_preflight'))
                @php($preflight = (array) session('target_dns_preflight'))
                <div class="alert {{ ($preflight['ok'] ?? false) ? 'alert-success' : 'alert-error' }}"
                    role="{{ ($preflight['ok'] ?? false) ? 'status' : 'alert' }}">
                    <strong>{{ __('Gateway DNS preflight') }}:</strong> {{ $preflight['message'] ?? '' }}
                    @if (! empty($preflight['next_step']))
                        <p><strong>{{ __('What to check') }}:</strong> {{ $preflight['next_step'] }}</p>
                    @endif
                    @if (! empty($preflight['reference']))
                        <p><strong>{{ __('Log reference') }}:</strong> <code>{{ $preflight['reference'] }}</code></p>
                    @endif
                </div>
            @endif
            <p class="field-help">{{ __('This checks the effective Gateway DNS and public-IP policy only. It does not contact WordPress, verify TLS, install Bridge, grant access or reserve an IP. Registration rechecks everything independently.') }}</p>
        </fieldset>

        <fieldset class="target-form-section" data-connector-panel="ssh_direct" @if($selected !== 'ssh_direct') hidden disabled @endif>
            <legend>{{ __('3. Direct SSH connection') }}</legend>
            <p class="field-help">{{ __('Register a public SSH endpoint. Authentication will be verified separately; no shell command is executed during enrollment.') }}</p>
            <div class="target-field-grid">
                <div class="field">
                    <label for="ssh_host">{{ __('Registered hostname or IP address') }}</label>
                    <input type="text" id="ssh_host" name="ssh_host" maxlength="253" required
                        autocomplete="off" spellcheck="false" placeholder="server.example.com" value="{{ old('ssh_host') }}">
                    @error('ssh_host')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field">
                    <label for="ssh_port">{{ __('TCP port') }}</label>
                    <input id="ssh_port" type="number" name="ssh_port" min="1" max="65535" required value="{{ old('ssh_port', '22') }}">
                    @error('ssh_port')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field target-span-all">
                    <label for="ssh_username">{{ __('SSH OS username') }}</label>
                    <input type="text" id="ssh_username" name="ssh_username" maxlength="128" required
                        spellcheck="false" autocomplete="off" placeholder="deploy" value="{{ old('ssh_username') }}">
                    @error('ssh_username')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
            </div>

            <div class="target-subsection">
                <h3>{{ __('Server identity') }}</h3>
                <p class="field-help">{{ __('The public HOST key identifies the server. This is different from your private LOGIN key. A verified host-key pin is required even when logging in with only a password.') }}</p>
                <div class="field">
                    <label for="ssh_host_key">{{ __('Trusted OpenSSH server public host key') }}</label>
                    <textarea id="ssh_host_key" name="ssh_host_key" rows="2" maxlength="4096" required
                        spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA...">{{ old('ssh_host_key') }}</textarea>
                    @error('ssh_host_key')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <details class="target-help-details">
                    <summary>{{ __('How to obtain and verify the server host key') }}</summary>
                    <p class="field-help">{{ __('From an independently trusted server console, inspect which PUBLIC host-key files actually exist:') }}</p>
                    <code>ls -l /etc/ssh/ssh_host_*_key.pub</code>
                    <p class="field-help">{{ __('If an Ed25519 public host key exists, use its first two fields:') }}</p>
                    <code>sudo awk '{print $1, $2}' /etc/ssh/ssh_host_ed25519_key.pub</code>
                    <p class="field-help">{{ __('Otherwise, an existing RSA public host key is also supported (do not use DSA):') }}</p>
                    <code>sudo awk '{print $1, $2}' /etc/ssh/ssh_host_rsa_key.pub</code>
                    <p class="field-help">{{ __('Compare the matching SHA256 fingerprint using the same trusted channel (substitute the actual existing file):') }}</p>
                    <code>sudo ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub -E sha256</code>
                    <div class="target-fingerprint-tools">
                        <button class="button button-secondary" type="button" id="show_host_fingerprint">{{ __('Preview pasted key fingerprint') }}</button>
                        <output id="host_fingerprint" role="status" aria-live="polite"></output>
                    </div>
                    <p class="field-help">{{ __('A fingerprint copied from this form alone does not prove server identity. Verify it against the independent server console before confirming.') }}</p>
                </details>
                <label class="target-trust-confirmation">
                    <input type="checkbox" name="ssh_trust_confirmed" value="yes" required @checked(old('ssh_trust_confirmed') === 'yes')>
                    <span>{{ __('I verified that this exact server public host key belongs to the intended endpoint using a separate trusted channel.') }}</span>
                </label>
                @error('ssh_trust_confirmed')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>

            <div class="target-subsection">
                <h3>{{ __('Login credentials') }}</h3>
                <div class="field">
                    <label for="ssh_auth_method">{{ __('Authentication method') }}</label>
                    <select id="ssh_auth_method" name="ssh_auth_method" required>
                        <option value="password" @selected(old('ssh_auth_method', 'password') === 'password')>{{ __('Password only') }}</option>
                        <option value="private_key" @selected(old('ssh_auth_method') === 'private_key')>{{ __('Private key only') }}</option>
                    </select>
                    <p class="field-help" id="ssh_auth_help">{{ __('Choose how the SSH user authenticates after the server host key is verified.') }}</p>
                    @error('ssh_auth_method')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="target-credential-grid">
                    <div class="field" data-ssh-secret="password">
                        <label for="ssh_password">{{ __('SSH login password') }}</label>
                        <input id="ssh_password" name="ssh_password" type="password" maxlength="4096" autocomplete="new-password">
                        @error('ssh_password')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                    </div>
                    <div class="field" data-ssh-secret="private_key">
                        <label for="ssh_private_key">{{ __('SSH private login key (PEM/OpenSSH)') }}</label>
                        <textarea id="ssh_private_key" name="ssh_private_key" rows="5" maxlength="16384" spellcheck="false" autocomplete="off"></textarea>
                        @error('ssh_private_key')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                        <label for="ssh_passphrase">{{ __('Key passphrase (when encrypted)') }}</label>
                        <input id="ssh_passphrase" name="ssh_passphrase" type="password" maxlength="4096" autocomplete="new-password">
                    </div>
                </div>
            </div>
            <p class="field-help">{{ __('Only approved public TCP destinations can connect. After registering, separately verify the pinned SSH server key and login. Then grant access through Edit User / Target access or Target Groups. Registering a Target alone never grants remote command or file capabilities.') }}</p>
        </fieldset>

        <div class="target-create-actions" data-target-actions @if($selected === '') hidden @endif>
            <button class="button button-primary" type="submit">{{ __('Register Target') }}</button>
            <p class="field-help">{{ __('Credentials are encrypted and never restored into this form after validation errors.') }}</p>
        </div>
    </form>
</section>

<script>
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('target-create-form');
    if (!form) return;
    const connector = form.querySelector('#connector_type');
    const shared = form.querySelector('[data-target-shared]');
    const panels = form.querySelectorAll('[data-connector-panel]');
    const actions = form.querySelector('[data-target-actions]');
    const method = form.querySelector('#ssh_auth_method');
    const trustedCheckbox = form.querySelector('input[name="ssh_trust_confirmed"]');
    const hostKey = form.querySelector('#ssh_host_key');
    const fingerprint = form.querySelector('#host_fingerprint');

    const syncAuthentication = () => {
        const current = method.value;
        form.querySelectorAll('[data-ssh-secret]').forEach(group => {
            const active = group.dataset.sshSecret === current;
            group.hidden = !active;
            group.querySelectorAll('input, textarea').forEach(field => {
                field.disabled = !active || connector.value !== 'ssh_direct';
                field.required = active && field.name !== 'ssh_passphrase';
            });
        });
    };
    const syncConnector = () => {
        const current = connector.value;
        shared.hidden = !current;
        shared.disabled = !current;
        actions.hidden = !current;
        panels.forEach(panel => {
            const active = panel.dataset.connectorPanel === current;
            panel.hidden = !active;
            panel.disabled = !active;
        });
        syncAuthentication();
    };
    connector.addEventListener('change', syncConnector);
    method.addEventListener('change', syncAuthentication);
    // If the server endpoint or pasted host key changes, prior user confirmation
    // is no longer meaningful. This is not a substitute for server-side checks.
    ['ssh_host', 'ssh_port', 'ssh_host_key'].forEach(name => {
        form.querySelector('[name="' + name + '"]').addEventListener('input', () => {
            trustedCheckbox.checked = false;
            if (name === 'ssh_host_key') fingerprint.textContent = '';
        });
    });
    form.querySelector('#show_host_fingerprint').addEventListener('click', async () => {
        const parts = hostKey.value.trim().split(/\s+/);
        fingerprint.textContent = '';
        if (parts.length !== 2 || !['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'].includes(parts[0])) {
            fingerprint.textContent = @json(__('Paste one supported public host key with no trailing comment.'));
            return;
        }
        try {
            const decoded = atob(parts[1]);
            const bytes = Uint8Array.from(decoded, c => c.charCodeAt(0));
            const data = new DataView(bytes.buffer);
            const length = data.getUint32(0);
            if (bytes.length < 16 || length !== parts[0].length ||
                new TextDecoder().decode(bytes.subarray(4, 4 + length)) !== parts[0]) {
                throw new Error('invalid public key');
            }
            const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
            fingerprint.textContent = 'SHA256:' + btoa(String.fromCharCode(...digest)).replace(/=+$/, '');
        } catch (_) {
            fingerprint.textContent = @json(__('Cannot preview this key. Check its format or use the trusted server console.'));
        }
    });
    syncConnector();
});
</script>
@endsection
