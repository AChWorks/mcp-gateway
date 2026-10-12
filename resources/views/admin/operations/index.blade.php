@extends('admin.layout')

@section('title', __('Operational settings'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Gateway operations') }}</div>
        <h1>{{ __('Operational settings') }}</h1>
        <p class="muted">{{ __('Tune finite WordPress response and connection limits without editing environment files or publishing a new version. Only the Owner may change these values.') }}</p>
    </div>
</div>

<section class="panel panel-wide" aria-label="{{ __('WordPress operational limits') }}">
    <h2>{{ __('WordPress downstream resource limits') }}</h2>
    <p class="muted">{{ __('Only the Owner can modify this finite, audited allowlist. The default for each field comes from the existing source/environment configuration. Blank values restore that default without a code release.') }}</p>
    <p class="muted">{{ __('Response limits apply per decoded HTTP reply, including the JSON-RPC wrapper; they are not full-file limits. Confirmed read-only operations may use the larger response budget. The independent 8 MiB decoded-body safety guard still applies.') }}</p>
    <p class="muted">{{ __('Connection and total request timeouts apply to WordPress Bridge HTTPS requests including metadata and OAuth. The complete DNS lookup and HTTPS dispatch share the overall deadline. The connect limit must not exceed the overall request limit. OAuth one-shot recovery is still governed by the provider window and the original attempt timeout; changing settings cannot reopen or shorten that window.') }}</p>
    <p class="muted">{{ __('These are conservative provisional ranges pending evidence in Issues #153 and #154. They do not extend PHP-FPM/CDN worker limits, change Target permissions, permit indefinite streaming or add file attachment support.') }}</p>

    <form method="post" action="{{ route('admin.operations.update') }}" class="form-stack">
        @csrf
        @method('PUT')
        <input type="hidden" name="version" value="{{ $state['version'] }}">

        @foreach ($definitions as $key => $range)
            @if($key === 'wp_response_kib')
                <h3>{{ __('Response budgets') }}</h3>
            @elseif($key === 'wp_connect_timeout_seconds')
                <h3>{{ __('Connection and request deadlines') }}</h3>
            @endif
            @php
                $isTime = str_ends_with($key, '_seconds');
                $fieldId = 'setting_'.$key;
                $description = match ($key) {
                    'wp_response_kib' => __('Ordinary, OAuth, metadata and potentially mutating response limit'),
                    'wp_readonly_response_kib' => __('Confirmed read-only WordPress Ability response limit'),
                    'wp_connect_timeout_seconds' => __('Maximum HTTPS connection establishment time'),
                    'wp_request_timeout_seconds' => __('Overall HTTPS request time including DNS and response'),
                };
                $effective = $state['overrides'][$key] ?? $defaults[$key];
                if ($key === 'wp_request_timeout_seconds') {
                    $effective = max($effective, $state['overrides']['wp_connect_timeout_seconds'] ?? $defaults['wp_connect_timeout_seconds']);
                }
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
                    {{ __('Units: :unit. Current effective: :value :unit. Source/environment default: :default :unit. Valid override: :min–:max :unit. Leave empty to restore the default.', [
                        'unit' => $isTime ? __('seconds') : __('KiB'),
                        'value' => $isTime ? $effective : number_format($effective, 2),
                        'default' => $isTime ? $defaults[$key] : number_format($defaults[$key], 2),
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
