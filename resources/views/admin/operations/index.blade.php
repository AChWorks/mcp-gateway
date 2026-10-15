@extends('admin.layout')

@section('title', __('Operational settings'))

@section('content')
@php
    // Presentation groups only. The single authoritative allowlist, bounds,
    // version fence, password check and audit remain in OperationalSettings.
    $groups = [
        [
            'title' => __('WordPress responses'),
            'description' => __('Set decoded response budgets for WordPress Bridge calls. These are per-message limits, not whole-file transfer quotas.'),
            'keys' => ['wp_response_kib', 'wp_readonly_response_kib'],
        ],
        [
            'title' => __('WordPress connection deadlines'),
            'description' => __('Bound connection establishment and total request time. The total deadline includes DNS lookup and response processing.'),
            'keys' => ['wp_connect_timeout_seconds', 'wp_request_timeout_seconds'],
        ],
        [
            'title' => __('SSH whole-file transfer'),
            'description' => __('Limits for the optional authenticated binary transfer plane only. Separate from WordPress responses and small SFTP calls.'),
            'keys' => ['ssh_transfer_max_kib', 'ssh_transfer_max_seconds'],
        ],
        [
            'title' => __('SSH commands'),
            'description' => __('Bound each synchronous SSH command separately from whole-file transfer. Use retained SSH Jobs for longer operations. Timeout includes the remote exec phase, not setup; transport, PHP and proxy limits may be lower.'),
            'keys' => ['ssh_command_timeout_seconds', 'ssh_command_max_kib'],
        ],
    ];
    $descriptions = [
        'wp_response_kib' => __('Ordinary, OAuth and mutating responses'),
        'wp_readonly_response_kib' => __('Confirmed read-only Ability responses'),
        'wp_connect_timeout_seconds' => __('Connection establishment'),
        'wp_request_timeout_seconds' => __('Total request deadline'),
        'ssh_transfer_max_kib' => __('Maximum whole-file size'),
        'ssh_transfer_max_seconds' => __('Maximum synchronous transfer time'),
        'ssh_command_timeout_seconds' => __('Maximum SSH command execution time'),
        'ssh_command_max_kib' => __('Maximum SSH command input size'),
    ];
@endphp
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Gateway operations') }}</div>
        <h1>{{ __('Operational settings') }}</h1>
        <p class="muted">{{ __('Adjust bounded Gateway behavior without editing environment files. Changes apply to new requests and require Owner password confirmation.') }}</p>
    </div>
</div>

<section class="panel panel-wide" aria-labelledby="outbound-dns-preflight-title">
    <div class="section-heading">
        <h2 id="outbound-dns-preflight-title">{{ __('Outbound DNS compatibility preflight') }}</h2>
        @if ($dnsCompatibility['applicable'])
            <span class="badge badge-{{ $dnsCompatibility['ready'] ? 'success' : 'neutral' }}">{{ $dnsCompatibility['ready'] ? __('PHP files accessible') : __('Check PHP file access') }}</span>
        @endif
    </div>
    @if (! $dnsCompatibility['applicable'])
        <p>{{ __('This Linux-focused file preflight does not apply to the current host. Follow the platform DNS resolver configuration documentation.') }}</p>
    @else
        <p>{{ __('The Gateway HTTPS safety policy uses bounded React DNS and the PHP worker must be able to read its system resolver configuration. This check runs inside PHP with its effective filesystem restrictions; it does not send a DNS query or authenticate WordPress.') }}</p>
        <dl class="detail-list">
            <dt><code>/etc/resolv.conf</code></dt><dd>{{ $dnsCompatibility['resolv_conf_readable'] ? __('Readable by PHP') : __('Not readable by PHP') }}</dd>
            <dt><code>/etc/hosts</code></dt><dd>{{ $dnsCompatibility['hosts_readable'] ? __('Readable by PHP') : __('Not readable by PHP') }}</dd>
            <dt><code>open_basedir</code></dt><dd>{{ $dnsCompatibility['open_basedir_active'] ? __('Enabled for this PHP worker') : __('Not configured for this PHP worker') }}</dd>
        </dl>
        @if (! $dnsCompatibility['ready'])
            <p class="target-recovery-warning">{{ __('If an OpenLiteSpeed LSAPI VHost uses php_admin_value open_basedir, update the effective VHost allowlist through aaPanel to include only the necessary resolver files (and real symlink targets), not the entire filesystem. Retest after PHP worker reload. Do not turn off open_basedir or bypass TLS/SSRF checks.') }}</p>
        @else
            <p class="field-help">{{ __('Readable system files are a prerequisite, not a guarantee of DNS, TLS, outbound network access or WordPress OAuth validity.') }}</p>
        @endif
    @endif
</section>

<section class="panel panel-wide operations-panel" aria-labelledby="operational-limits-title">
    <div class="section-heading operations-heading">
        <div>
            <h2 id="operational-limits-title">{{ __('Resource budgets and timeouts') }}</h2>
            <p class="field-help">{{ __('Review current effective values and source defaults before making changes.') }}</p>
        </div>
        <span class="operations-version">{{ __('Settings revision :version', ['version' => $state['version']]) }}</span>
    </div>

    <details class="operations-guidance">
        <summary>{{ __('How these limits interact') }}</summary>
        <ul>
            <li>{{ __('WordPress responses count the decoded JSON-RPC envelope, including metadata. Confirmed read-only calls can use their separate higher limit; the independent 8 MiB hard response guard remains in force.') }}</li>
            <li>{{ __('The overall WordPress timeout must be at least the connection timeout. The existing OAuth refresh/recovery window cannot be extended by these settings.') }}</li>
            <li>{{ __('SSH whole-file limits do not change its 16 KiB inline reads, 64 KiB temporary buffer, or WordPress transfer limits. The binary sidecar must be independently enabled and authorized.') }}</li>
            <li>{{ __('Values cannot override PHP worker, proxy/CDN, filesystem or actual client limits. These bounded ranges remain provisional pending operational measurements.') }}</li>
        </ul>
    </details>

    <form class="operations-form" method="post" action="{{ route('admin.operations.update') }}">
        @csrf
        @method('PUT')
        <input type="hidden" name="version" value="{{ $state['version'] }}">

        @foreach ($groups as $group)
            <fieldset class="operations-group">
                <legend>{{ $group['title'] }}</legend>
                <p class="field-help operations-group-intro">{{ $group['description'] }}</p>
                <div class="operations-field-grid">
                    @foreach ($group['keys'] as $key)
                        @php
                            $range = $definitions[$key];
                            $isTime = str_ends_with($key, '_seconds');
                            $unit = $isTime ? __('seconds') : __('KiB');
                            $fieldId = 'setting_'.$key;
                            $effective = $state['overrides'][$key] ?? $defaults[$key];
                            if ($key === 'wp_request_timeout_seconds') {
                                $effective = max($effective, $state['overrides']['wp_connect_timeout_seconds'] ?? $defaults['wp_connect_timeout_seconds']);
                            }
                            $formattedEffective = $isTime ? $effective : number_format($effective, 2);
                            $formattedDefault = $isTime ? $defaults[$key] : number_format($defaults[$key], 2);
                            $overridden = array_key_exists($key, $state['overrides']);
                        @endphp
                        <div class="operations-setting field">
                            <label for="{{ $fieldId }}">{{ $descriptions[$key] }}</label>
                            <div class="operations-setting-control">
                                <input
                                    id="{{ $fieldId }}"
                                    type="number"
                                    inputmode="numeric"
                                    name="values[{{ $key }}]"
                                    min="{{ $range['minimum'] }}"
                                    max="{{ $range['maximum'] }}"
                                    step="1"
                                    placeholder="{{ $defaults[$key] }}"
                                    value="{{ old('values.'.$key, $state['overrides'][$key] ?? '') }}"
                                    aria-describedby="{{ $fieldId }}_info"
                                >
                                <span class="operations-unit">{{ $unit }}</span>
                                <button type="button" class="operations-reset button button-secondary"
                                    data-clear-setting="{{ $fieldId }}" hidden>{{ __('Use default') }}</button>
                            </div>
                            <div class="operations-setting-meta" id="{{ $fieldId }}_info">
                                <p>{{ __('Current effective') }}: <strong>{{ $formattedEffective }} {{ $unit }}</strong>
                                    <span class="operations-setting-source">{{ $overridden ? __('Custom override') : __('Source default') }}</span>
                                </p>
                                <p class="field-help">{{ __('Source default: :value :unit. Allowed: :min–:max. Leave empty to restore the default.', [
                                    'value' => $formattedDefault,
                                    'unit' => $unit,
                                    'min' => $range['minimum'],
                                    'max' => $range['maximum'],
                                ]) }}</p>
                            </div>
                            @error('values.'.$key)
                                <p class="form-error" role="alert">{{ $message }}</p>
                            @enderror
                        </div>
                    @endforeach
                </div>
            </fieldset>
        @endforeach

        @error('values')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        @error('version')<p class="form-error" role="alert">{{ $message }}</p>@enderror

        <fieldset class="operations-group operations-confirmation">
            <legend>{{ __('Confirm changes') }}</legend>
            <p class="field-help">{{ __('Editing these limits does not grant any new Target permission, unlock binary transfer, or replace an external server setting. Changes are version-checked and audited.') }}</p>
            <div class="field">
                <label for="current_password">{{ __('Current Owner password') }}</label>
                <input id="current_password" type="password" name="current_password" required
                    autocomplete="current-password" maxlength="255">
                <p class="field-help">{{ __('Required to authorize any settings change. The password is never stored as an override or logged.') }}</p>
                @error('current_password')<p class="form-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="operations-save-row">
                <button class="button button-primary" type="submit">{{ __('Save operational settings') }}</button>
                <p class="field-help">{{ __('Blank numeric fields restore the configured defaults when saved.') }}</p>
            </div>
        </fieldset>
    </form>
</section>

<script>
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-clear-setting]').forEach(button => {
        const input = document.getElementById(button.dataset.clearSetting);
        if (!input) return;
        button.hidden = false;
        button.addEventListener('click', () => {
            input.value = '';
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.focus();
        });
    });
});
</script>
@endsection
