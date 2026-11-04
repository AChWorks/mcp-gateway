<div class="target-field-grid">
    <div class="field">
        <label for="relay-{{ $prefix }}-id">{{ __('Relay ID') }}</label>
        <input id="relay-{{ $prefix }}-id" type="text" name="relay_id" maxlength="64" required
            pattern="[a-z0-9]+(-[a-z0-9]+)*" spellcheck="false" autocomplete="off"
            value="{{ $editing ? $relay->relay_id : old('relay_id') }}" placeholder="iran-bridge-1">
        @error('relay_id')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-name">{{ __('Display name') }}</label>
        <input id="relay-{{ $prefix }}-name" type="text" name="display_name" maxlength="160" required autocomplete="off"
            value="{{ $editing ? $relay->display_name : old('display_name') }}" placeholder="{{ __('Iran intermediary') }}">
        @error('display_name')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-host">{{ __('Iran SSH host or public IP') }}</label>
        <input id="relay-{{ $prefix }}-host" type="text" name="control_host" maxlength="253" required autocomplete="off" spellcheck="false"
            value="{{ $editing ? $relay->control_host : old('control_host') }}" placeholder="relay.example.com">
        @error('control_host')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-port">{{ __('SSH control port') }}</label>
        <input id="relay-{{ $prefix }}-port" type="number" name="control_port" min="1" max="65535" required
            value="{{ $editing ? $relay->control_port : old('control_port', 22) }}">
        @error('control_port')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-user">{{ __('Dedicated SSH control username') }}</label>
        <input id="relay-{{ $prefix }}-user" type="text" name="control_user" maxlength="128" required data-admin-manual-entry
            data-admin-server-value="{{ $editing ? $relay->control_user : old('control_user') }}" autocomplete="off"
            value="{{ $editing ? $relay->control_user : old('control_user') }}" spellcheck="false">
        @error('control_user')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-socks">{{ __('Dedicated local SOCKS5 TCP port') }}</label>
        <input id="relay-{{ $prefix }}-socks" type="number" name="local_socks_port" min="46000" max="60999" required
            value="{{ $editing ? $relay->local_socks_port : old('local_socks_port', 46081) }}">
        @error('local_socks_port')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <div class="field target-span-all">
        <label for="relay-{{ $prefix }}-key">{{ __('Independently verified SSH server public host key') }}</label>
        <textarea id="relay-{{ $prefix }}-key" name="control_host_key" rows="3" maxlength="4096" required
            autocomplete="off" spellcheck="false">{{ $editing ? $relay->control_host_key : old('control_host_key') }}</textarea>
        <p class="field-help">{{ __('This is the public SSH HOST key, not the Relay login private key. The login key belongs on the operator-managed host, never in this form.') }}</p>
        @error('control_host_key')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
</div>
