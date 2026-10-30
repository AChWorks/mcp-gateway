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
