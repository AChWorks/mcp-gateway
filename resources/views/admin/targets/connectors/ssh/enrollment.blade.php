<fieldset class="target-form-section" data-connector-panel="ssh_direct" @if($selected !== 'ssh_direct') hidden disabled @endif>
    <legend>{{ __('3. SSH connection') }}</legend>
    <p class="field-help" id="ssh-enrollment-help">{{ __('Register the real SSH endpoint and independently verified host identity. Direct authentication and Managed Reverse setup are verified only after enrollment.') }}</p>
    <div class="target-field-grid">
        <div class="field">
            <label for="ssh_host">{{ __('Registered hostname or IP address') }}</label>
            <input type="text" id="ssh_host" name="ssh_host" maxlength="253" required
                autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ old('ssh_host') }}" spellcheck="false" placeholder="server.example.com" value="{{ old('ssh_host') }}" @error('ssh_host') aria-invalid="true" @enderror aria-describedby="ssh-enrollment-help{{ $errors->has('ssh_host') ? ' ssh_host-error' : '' }}">
            @error('ssh_host')<p class="field-error" role="alert" id="ssh_host-error">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="ssh_port">{{ __('TCP port') }}</label>
            <input id="ssh_port" type="number" name="ssh_port" min="1" max="65535" required value="{{ old('ssh_port', '22') }}" @error('ssh_port') aria-invalid="true" aria-describedby="ssh_port-error" @enderror>
            @error('ssh_port')<p class="field-error" role="alert" id="ssh_port-error">{{ $message }}</p>@enderror
        </div>
        <div class="field target-span-all">
            <label for="ssh_username">{{ __('SSH OS username') }}</label>
            <input type="text" id="ssh_username" name="ssh_username" maxlength="128" required
                spellcheck="false" autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ old('ssh_username') }}" placeholder="deploy" value="{{ old('ssh_username') }}" @error('ssh_username') aria-invalid="true" aria-describedby="ssh_username-error" @enderror>
            @error('ssh_username')<p class="field-error" role="alert" id="ssh_username-error">{{ $message }}</p>@enderror
        </div>
    </div>

    <div class="target-subsection">
        <h3>{{ __('SSH connection method') }}</h3>
        <p class="field-help">{{ __('Direct connects from Gateway to the Target. Managed Reverse sets up a persistent Target-initiated tunnel with one installer command. Manual Reverse requires an existing Owner-approved loopback listener.') }}</p>
        <div class="field">
            <label for="ssh_mode">{{ __('Connection method') }}</label>
            <select id="ssh_mode" name="ssh_mode" aria-describedby="ssh-mode-help">
                <option value="direct" @selected($selectedSshMode === 'direct')>{{ __('Direct SSH (default)') }}</option>
                @if (auth()->user()?->getRawOriginal('role') === 'owner')
                    <option value="managed" @selected($selectedSshMode === 'managed')>{{ __('Managed Reverse SSH — one-command setup') }}</option>
                    <option value="manual" @selected($selectedSshMode === 'manual')>{{ __('Manual Reverse SSH (advanced)') }}</option>
                @endif
            </select>
            <p class="field-help" id="ssh-mode-help">{{ __('Choose how Gateway will reach the real SSH server. The Target ID, identity and host-key verification remain the same.') }}</p>
            <noscript>
                <p class="field-help">{{ __('Choose a connection mode using the links below before completing the form:') }}</p>
                <a href="{{ route('admin.targets.create', ['connector_type' => 'ssh_direct', 'ssh_mode' => 'direct']) }}">{{ __('Direct SSH') }}</a>
                @if (auth()->user()?->getRawOriginal('role') === 'owner')
                    <a href="{{ route('admin.targets.create', ['connector_type' => 'ssh_direct', 'ssh_mode' => 'managed']) }}">{{ __('Managed Reverse SSH') }}</a>
                    <a href="{{ route('admin.targets.create', ['connector_type' => 'ssh_direct', 'ssh_mode' => 'manual']) }}">{{ __('Manual Reverse SSH') }}</a>
                @endif
            </noscript>
        </div>
        <input name="ssh_route_mode" type="hidden" value="{{ $selectedSshMode === 'manual' ? 'reverse' : 'direct' }}" data-ssh-route-value @if($selectedSshMode === 'managed') disabled @endif>
        @if (auth()->user()?->getRawOriginal('role') === 'owner')
            <div class="target-field-grid" data-ssh-reverse-route @if($selectedSshMode !== 'manual') hidden @endif>
                <div class="field">
                    <label for="ssh_reverse_port">{{ __('Gateway-approved loopback listener port (1024–65535)') }}</label>
                    <input id="ssh_reverse_port" name="ssh_reverse_port" type="number" min="1024" max="65535" value="{{ old('ssh_reverse_port') }}" @if($selectedSshMode !== 'manual') disabled @endif @error('ssh_reverse_port') aria-invalid="true" @enderror>
                    @error('ssh_reverse_port')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field">
                    <label for="ssh_tunnel_identity">{{ __('Gateway-approved tunnel identity') }}</label>
                    <input id="ssh_tunnel_identity" name="ssh_tunnel_identity" type="text" maxlength="80" autocomplete="off" spellcheck="false" value="{{ old('ssh_tunnel_identity') }}" @if($selectedSshMode !== 'manual') disabled @endif>
                    @error('ssh_tunnel_identity')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field target-span-all">
                    <label for="ssh_reverse_owner_password">{{ __('Current Owner password (manual Reverse SSH only)') }}</label>
                    <input id="ssh_reverse_owner_password" name="current_password" type="password" data-admin-requires-intent maxlength="255" autocomplete="off" @if($selectedSshMode !== 'manual') disabled @endif>
                    @error('current_password')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                    <p class="field-help">{{ __('Manual Reverse requires an independently provisioned, Owner-approved loopback forward. Do not enter the Gateway control SSHD port here.') }}</p>
                </div>
            </div>
            <div class="target-route-mode-details" data-ssh-managed @if($selectedSshMode !== 'managed') hidden @endif>
                <h4>{{ __('One-command Managed Reverse SSH') }}</h4>
                @if (! $managedConfigured)
                    <div class="alert alert-info" role="status">
                        {{ __('Managed Reverse SSH is not enabled. Configure and verify the Gateway host before issuing an installer command.') }}
                        <a href="{{ route('admin.reverse-ssh.index') }}">{{ __('Open System Reverse SSH settings') }}</a>
                    </div>
                @else
                    <p class="field-help">{{ __('After creating Pending Setup, copy the one-time verified installer command in the next step. The Target remains unconnected until explicit verification.') }}</p>
                @endif
                <div class="field">
                    <label for="managed_owner_password">{{ __('Current Owner password (managed enrollment)') }}</label>
                    <input id="managed_owner_password" name="current_password" type="password" data-admin-requires-intent required maxlength="255" autocomplete="off" @if($selectedSshMode !== 'managed') disabled @endif>
                    @error('current_password')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
            </div>
        @endif
    </div>
    <div class="target-subsection">
        <h3>{{ __('Server identity') }}</h3>
        <p class="field-help" id="ssh-host-key-help">{{ __('The public HOST key identifies the server. This is different from your private LOGIN key. A verified host-key pin is required even when logging in with only a password.') }}</p>
        <div class="field">
            <label for="ssh_host_key">{{ __('Trusted OpenSSH server public host key') }}</label>
            <textarea id="ssh_host_key" name="ssh_host_key" rows="2" maxlength="4096" required
                spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA..." @error('ssh_host_key') aria-invalid="true" @enderror aria-describedby="ssh-host-key-help{{ $errors->has('ssh_host_key') ? ' ssh_host_key-error' : '' }}">{{ old('ssh_host_key') }}</textarea>
            @error('ssh_host_key')<p class="field-error" role="alert" id="ssh_host_key-error">{{ $message }}</p>@enderror
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
                <output data-invalid-message="{{ __('Paste one supported public host key with no trailing comment.') }}"
                    data-unavailable-message="{{ __('Cannot preview this key. Check its format or use the trusted server console.') }}" id="host_fingerprint" role="status" aria-live="polite"></output>
            </div>
            <p class="field-help" id="ssh-host-confirmation-help">{{ __('A fingerprint copied from this form alone does not prove server identity. Verify it against the independent server console before confirming.') }}</p>
        </details>
        <label class="target-trust-confirmation">
            <input type="checkbox" name="ssh_trust_confirmed" value="yes" required @checked(old('ssh_trust_confirmed') === 'yes') id="ssh_trust_confirmed" @error('ssh_trust_confirmed') aria-invalid="true" @enderror aria-describedby="ssh-host-confirmation-help{{ $errors->has('ssh_trust_confirmed') ? ' ssh_trust_confirmed-error' : '' }}">
            <span>{{ __('I verified that this exact server public host key belongs to the intended endpoint using a separate trusted channel.') }}</span>
        </label>
        @error('ssh_trust_confirmed')<p class="field-error" role="alert" id="ssh_trust_confirmed-error">{{ $message }}</p>@enderror
    </div>

    <div class="target-subsection" data-ssh-standard @if($selectedSshMode === 'managed') hidden @endif>
        <h3>{{ __('Login credentials') }}</h3>
        <div class="field">
            <label for="ssh_auth_method">{{ __('Authentication method') }}</label>
            <select id="ssh_auth_method" name="ssh_auth_method" required @if($selectedSshMode === 'managed') disabled @endif @error('ssh_auth_method') aria-invalid="true" @enderror aria-describedby="ssh_auth_help{{ $errors->has('ssh_auth_method') ? ' ssh_auth_method-error' : '' }}">
                <option value="password" @selected(old('ssh_auth_method', 'password') === 'password')>{{ __('Password only') }}</option>
                <option value="private_key" @selected(old('ssh_auth_method') === 'private_key')>{{ __('Private key only') }}</option>
            </select>
            <p class="field-help" id="ssh_auth_help">{{ __('Choose how the SSH user authenticates after the server host key is verified.') }}</p>
            @error('ssh_auth_method')<p class="field-error" role="alert" id="ssh_auth_method-error">{{ $message }}</p>@enderror
        </div>
        <div class="target-credential-grid">
            <div class="field" data-ssh-secret="password">
                <label for="ssh_password">{{ __('SSH login password') }}</label>
                <input id="ssh_password" name="ssh_password" type="password" maxlength="4096" autocomplete="new-password" @error('ssh_password') aria-invalid="true" @enderror aria-describedby="target-credential-help{{ $errors->has('ssh_password') ? ' ssh_password-error' : '' }}">
                @error('ssh_password')<p class="field-error" role="alert" id="ssh_password-error">{{ $message }}</p>@enderror
            </div>
            <div class="field" data-ssh-secret="private_key">
                <label for="ssh_private_key">{{ __('SSH private login key (PEM/OpenSSH)') }}</label>
                <textarea id="ssh_private_key" name="ssh_private_key" rows="5" maxlength="16384" spellcheck="false" autocomplete="off" @error('ssh_private_key') aria-invalid="true" @enderror aria-describedby="target-credential-help{{ $errors->has('ssh_private_key') ? ' ssh_private_key-error' : '' }}"></textarea>
                @error('ssh_private_key')<p class="field-error" role="alert" id="ssh_private_key-error">{{ $message }}</p>@enderror
                <label for="ssh_passphrase">{{ __('Key passphrase (when encrypted)') }}</label>
                <input id="ssh_passphrase" name="ssh_passphrase" type="password" maxlength="4096" autocomplete="new-password" @error('ssh_passphrase') aria-invalid="true" @enderror aria-describedby="target-credential-help{{ $errors->has('ssh_passphrase') ? ' ssh_passphrase-error' : '' }}">
                @error('ssh_passphrase')<p class="field-error" id="ssh_passphrase-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>
    </div>
    <p class="field-help">{{ __('Only approved public TCP destinations can connect. After registering, separately verify the pinned SSH server key and login. Then grant access through Edit User / Target access or Target Groups. Registering a Target alone never grants remote command or file capabilities.') }}</p>
</fieldset>
