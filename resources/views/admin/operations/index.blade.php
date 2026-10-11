@extends('admin.layout')

@section('title', __('Operational settings'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Gateway operations') }}</div>
        <h1>{{ __('Operational settings') }}</h1>
        <p class="muted">{{ __('Tune finite response budgets without editing environment files or publishing a new version. Only the Owner may change these values.') }}</p>
    </div>
</div>

<section class="panel panel-wide" aria-label="{{ __('WordPress response budgets') }}">
    <h2>{{ __('WordPress downstream response budgets') }}</h2>
    <p class="muted">{{ __('These settings bound a single decoded downstream HTTP response, including its JSON-RPC wrapper. They are not file size limits. Ordinary and mutating operations retain the smaller budget; only verified read-only calls use the read-only budget.') }}</p>
    <p class="muted">{{ __('Defaults are existing source/environment values. Adjustable maximums are conservative provisional safety envelopes pending the workload measurements in Issue #153 and external compatibility checks in Issue #154. Higher budgets do not allocate memory when responses are small, but can increase peak memory under concurrent large requests. The independent 8 MiB decoded-body safety guard remains enforced.') }}</p>

    <form method="post" action="{{ route('admin.operations.update') }}" class="form-stack">
        @csrf
        @method('PUT')
        <input type="hidden" name="version" value="{{ $state['version'] }}">

        @foreach ($definitions as $key => $range)
            @php
                $isReadOnly = $key === 'wp_readonly_response_kib';
                $fieldId = 'setting_'.$key;
                $description = $isReadOnly
                    ? __('Read-only confirmed WordPress Ability result (larger bounded response).')
                    : __('OAuth, metadata, unknown or potentially mutating WordPress operations (smaller response).');
            @endphp
            <div class="field">
                <label for="{{ $fieldId }}">{{ $description }}</label>
                <input
                    id="{{ $fieldId }}"
                    type="number"
                    inputmode="numeric"
                    name="values[{{ $key }}]"
                    min="{{ $range['minimum'] }}"
                    max="{{ $range['maximum'] }}"
                    step="1"
                    value="{{ old('values.'.$key, $state['overrides'][$key] ?? '') }}"
                    aria-describedby="{{ $fieldId }}_info"
                >
                <p class="muted" id="{{ $fieldId }}_info">
                    {{ __('Units: KiB. Current effective: :value KiB. Source/environment default: :default KiB. Valid override: :min–:max KiB. Leave empty to restore the default.', [
                        'value' => number_format(($state['overrides'][$key] ?? $defaults[$key]), 2),
                        'default' => number_format($defaults[$key], 2),
                        'min' => $range['minimum'],
                        'max' => $range['maximum'],
                    ]) }}
                </p>
                @error('values.'.$key)
                    <p class="form-error" role="alert">{{ $message }}</p>
                @enderror
            </div>
        @endforeach

        @error('values')
            <p class="form-error" role="alert">{{ $message }}</p>
        @enderror
        @error('version')
            <p class="form-error" role="alert">{{ $message }}</p>
        @enderror

        <div class="field">
            <label for="current_password">{{ __('Current Owner password') }}</label>
            <input id="current_password" type="password" name="current_password" required autocomplete="current-password" maxlength="255">
            <p class="muted">{{ __('Required to authorize and audit any operational settings change. Never logged or stored in a settings override.') }}</p>
            @error('current_password')
                <p class="form-error" role="alert">{{ $message }}</p>
            @enderror
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Save operational settings') }}</button>
        </div>
    </form>
</section>
@endsection
