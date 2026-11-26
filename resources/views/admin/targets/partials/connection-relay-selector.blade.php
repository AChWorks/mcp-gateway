@php
    $initialRelayId = $initialRelayId ?? null;
    $disabled = $disabled ?? false;
    $blockedRelay = $blockedRelay ?? null;
    $showBlocked = $blockedRelay !== null && $initialRelayId === $blockedRelay->relay_id;
@endphp
<div class="field">
    <label for="{{ $selectId }}">{{ __('Connection route') }}</label>
    <select id="{{ $selectId }}" name="connection_relay_id" @if($disabled) disabled @endif
        aria-describedby="{{ $selectId }}-help{{ $errors->has('connection_relay_id') ? ' '.$selectId.'-error' : '' }}"
        @error('connection_relay_id') aria-invalid="true" @enderror>
        @if ($showBlocked)
            <option value="{{ $blockedRelay->relay_id }}" selected>{{ __('Unavailable: :name (choose a new route)', ['name' => $blockedRelay->display_name]) }}</option>
        @endif
        <option value="" @selected(! $showBlocked && ($initialRelayId === null || $initialRelayId === ''))>{{ ($reverseSelected ?? false) ? __('No Relay (keep selected Reverse listener)') : __('Direct (default)') }}</option>
        @foreach($connectionRelays as $relay)
            <option value="{{ $relay->relay_id }}" @selected($initialRelayId === $relay->relay_id)>{{ $relay->display_name }}</option>
        @endforeach
    </select>
    <p id="{{ $selectId }}-help" class="field-help">{{ __('Use Direct unless this Target needs an enabled, host-verified intermediary. A fixed Reverse listener can be selected or cleared in its route controls.') }}</p>
    @if ($showBlocked)
        <p class="field-help" role="status">{{ __('Saved Relay :name cannot be used until enabled. Choose Direct or another enabled Relay without changing Target authorization.', ['name' => $blockedRelay->display_name]) }}</p>
    @endif
    @error('connection_relay_id')<p class="field-error" role="alert" id="{{ $selectId }}-error">{{ $message }}</p>@enderror
</div>
