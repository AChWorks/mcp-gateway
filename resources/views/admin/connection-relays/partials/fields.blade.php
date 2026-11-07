@php
    $restore = $editing
        ? old('edit_relay_id') === (string) $relay->getKey()
        : old('edit_relay_id') === null;
    $draft = static fn (string $name, mixed $saved = ''): mixed => $restore ? old($name, $saved) : $saved;
@endphp
<div class="target-field-grid">
    <div class="field">
        <label for="relay-{{ $prefix }}-id">{{ __('Relay ID') }}</label>
        <input id="relay-{{ $prefix }}-id" type="text" name="relay_id" maxlength="64" required
            pattern="[a-z0-9]+(-[a-z0-9]+)*" spellcheck="false" autocomplete="off"
            data-admin-manual-entry data-admin-server-value="{{ $draft('relay_id', $editing ? $relay->relay_id : '') }}"
            value="{{ $draft('relay_id', $editing ? $relay->relay_id : '') }}" placeholder="edge-relay-1" @readonly($editing)
            @if($restore && $errors->has('relay_id')) aria-invalid="true" aria-describedby="relay-{{ $prefix }}-id-error" @endif>
        @if($restore) @error('relay_id')<p class="field-error" role="alert" id="relay-{{ $prefix }}-id-error">{{ $message }}</p>@enderror @endif
        @if($editing)<p class="field-help">{{ __('Stable host-resource identifier. To change it, create a new Relay and explicitly migrate Targets; do not rename existing systemd/firewall resources.') }}</p>@endif
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-name">{{ __('Display name') }}</label>
        <input id="relay-{{ $prefix }}-name" type="text" name="display_name" maxlength="160" required autocomplete="off"
            data-admin-manual-entry data-admin-server-value="{{ $draft('display_name', $editing ? $relay->display_name : '') }}"
            value="{{ $draft('display_name', $editing ? $relay->display_name : '') }}" placeholder="{{ __('Edge intermediary') }}"
            @if($restore && $errors->has('display_name')) aria-invalid="true" aria-describedby="relay-{{ $prefix }}-name-error" @endif>
        @if($restore) @error('display_name')<p class="field-error" role="alert" id="relay-{{ $prefix }}-name-error">{{ $message }}</p>@enderror @endif
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-host">{{ __('Intermediary SSH host or public IP') }}</label>
        <input id="relay-{{ $prefix }}-host" type="text" name="control_host" maxlength="253" required autocomplete="off" spellcheck="false"
            value="{{ $draft('control_host', $editing ? $relay->control_host : '') }}" placeholder="relay.example.com"
            @if($restore && $errors->has('control_host')) aria-invalid="true" aria-describedby="relay-{{ $prefix }}-host-error" @endif>
        @if($restore) @error('control_host')<p class="field-error" role="alert" id="relay-{{ $prefix }}-host-error">{{ $message }}</p>@enderror @endif
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-port">{{ __('SSH control port') }}</label>
        <input id="relay-{{ $prefix }}-port" type="number" name="control_port" min="1" max="65535" required
            value="{{ $draft('control_port', $editing ? $relay->control_port : 22) }}"
            @if($restore && $errors->has('control_port')) aria-invalid="true" aria-describedby="relay-{{ $prefix }}-port-error" @endif>
        @if($restore) @error('control_port')<p class="field-error" role="alert" id="relay-{{ $prefix }}-port-error">{{ $message }}</p>@enderror @endif
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-user">{{ __('Dedicated SSH control username') }}</label>
        <input id="relay-{{ $prefix }}-user" type="text" name="control_user" maxlength="128" required
            data-admin-manual-entry data-admin-server-value="{{ $draft('control_user', $editing ? $relay->control_user : '') }}"
            autocomplete="off" value="{{ $draft('control_user', $editing ? $relay->control_user : '') }}" spellcheck="false"
            @if($restore && $errors->has('control_user')) aria-invalid="true" aria-describedby="relay-{{ $prefix }}-user-error" @endif>
        @if($restore) @error('control_user')<p class="field-error" role="alert" id="relay-{{ $prefix }}-user-error">{{ $message }}</p>@enderror @endif
    </div>
    <div class="field">
        <label for="relay-{{ $prefix }}-socks">{{ __('Dedicated local SOCKS5 TCP port') }}</label>
        <input id="relay-{{ $prefix }}-socks" type="number" name="local_socks_port" min="46000" max="60999" required
            value="{{ $draft('local_socks_port', $editing ? $relay->local_socks_port : 46081) }}"
            @if($restore && $errors->has('local_socks_port')) aria-invalid="true" aria-describedby="relay-{{ $prefix }}-socks-error" @endif>
        @if($restore) @error('local_socks_port')<p class="field-error" role="alert" id="relay-{{ $prefix }}-socks-error">{{ $message }}</p>@enderror @endif
    </div>
    <div class="field target-span-all">
        <label for="relay-{{ $prefix }}-key">{{ __('Independently verified SSH server public host key') }}</label>
        <textarea id="relay-{{ $prefix }}-key" name="control_host_key" rows="3" maxlength="4096" required
            autocomplete="off" spellcheck="false"
            aria-describedby="relay-{{ $prefix }}-key-help{{ $restore && $errors->has('control_host_key') ? ' relay-'.$prefix.'-key-error' : '' }}"
            @if($restore && $errors->has('control_host_key')) aria-invalid="true" @endif>{{ $draft('control_host_key', $editing ? $relay->control_host_key : '') }}</textarea>
        <p class="field-help" id="relay-{{ $prefix }}-key-help">{{ __('Paste the independently checked PUBLIC SSH host key, not a login key or password. Private keys never belong in this form.') }}</p>
        @if($restore) @error('control_host_key')<p class="field-error" role="alert" id="relay-{{ $prefix }}-key-error">{{ $message }}</p>@enderror @endif
    </div>
</div>
