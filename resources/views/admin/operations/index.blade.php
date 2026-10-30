@extends('admin.layout')

@section('title', __('Operational settings'))

@section('content')
@php
    // Presentation groups only. The single authoritative allowlist, bounds,
    // version fence, password check and audit remain in OperationalSettings.
    $groups = [
        [
            'id' => 'wordpress-responses',
            'title' => __('WordPress responses'),
            'description' => __('Set decoded response budgets for WordPress Bridge calls. These are per-message limits, not whole-file transfer quotas.'),
            'keys' => ['wp_response_kib', 'wp_readonly_response_kib'],
        ],
        [
            'id' => 'wordpress-deadlines',
            'title' => __('WordPress connection deadlines'),
            'description' => __('Bound connection establishment and total request time. The total deadline includes DNS lookup and response processing.'),
            'keys' => ['wp_connect_timeout_seconds', 'wp_request_timeout_seconds'],
        ],
        [
            'id' => 'ssh-transfers',
            'title' => __('SSH whole-file transfer'),
            'description' => __('Limits for the optional authenticated binary transfer plane only. An extended timeout requires suitable PHP, proxy and client deadlines; it does not extend the signed-file download deadline.'),
            'keys' => ['ssh_transfer_max_kib', 'ssh_transfer_max_seconds'],
        ],
        [
            'id' => 'ssh-commands',
            'title' => __('SSH commands'),
            'description' => __('Bound each synchronous SSH command separately from whole-file transfer. Use retained SSH Jobs for longer operations. Timeout includes the remote exec phase, not setup; transport, PHP and proxy limits may be lower.'),
            'keys' => ['ssh_command_timeout_seconds', 'ssh_command_max_kib', 'ssh_command_stdout_kib', 'ssh_command_stderr_kib'],
        ],
        [
            'id' => 'ssh-jobs',
            'title' => __('Detached SSH Jobs'),
            'description' => __('Owner-configurable script input (16-512 KiB), bounded output-read windows, concurrent admission, runtime, retention and recovery. Existing retained stdout/stderr spools stay at 1 MiB per stream.'),
            'keys' => [
                'ssh_job_max_active_per_user', 'ssh_job_max_runtime_seconds',
                'ssh_job_retention_hours', 'ssh_job_preparing_grace_seconds',
                'ssh_job_reconcile_grace_seconds', 'ssh_job_max_script_kib', 'ssh_job_output_window_kib',
            ],
        ],
        [
            'id' => 'ssh-inline',
            'title' => __('SSH SFTP inline windows'),
            'description' => __('Per-call file read/write decoded-byte limits and directory-name aggregate. These do not change SSH whole-file transfer budgets or internal streaming block sizes.'),
            'keys' => ['ssh_file_read_window_kib', 'ssh_file_write_window_kib', 'ssh_file_list_name_kib'],
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
        'ssh_command_stdout_kib' => __('Maximum captured SSH command stdout (KiB)'),
        'ssh_command_stderr_kib' => __('Maximum captured SSH command stderr (KiB)'),
        'ssh_job_max_active_per_user' => __('Concurrent SSH Jobs admitted per user'),
        'ssh_job_max_runtime_seconds' => __('Maximum remote Job runtime'),
        'ssh_job_retention_hours' => __('Retain terminal Job results'),
        'ssh_job_preparing_grace_seconds' => __('Pre-dispatch crash recovery window'),
        'ssh_job_reconcile_grace_seconds' => __('Post-runtime uncertain admission grace'),
        'ssh_job_max_script_kib' => __('Maximum SSH Job script input (KiB)'),
        'ssh_job_output_window_kib' => __('Maximum SSH Job output read per call (KiB)'),
        'ssh_file_read_window_kib' => __('Maximum inline SFTP read per call (KiB)'),
        'ssh_file_write_window_kib' => __('Maximum inline SFTP write per call (KiB)'),
        'ssh_file_list_name_kib' => __('Maximum directory listing aggregate names (KiB)'),
    ];
@endphp
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Gateway operations') }}</div>
        <h1>{{ __('Operational settings') }}</h1>
        <p class="muted reading-width">{{ __('Adjust bounded Gateway behavior without editing environment files. Changes apply to new requests and require Owner password confirmation.') }}</p>
    </div>
</div>

<nav class="section-nav" aria-label="{{ __('Operational settings sections') }}">
    <a href="#outbound-dns-preflight-title">{{ __('Host readiness') }}</a>
    @foreach ($groups as $group)
        <a href="#settings-{{ $group['id'] }}">{{ $group['title'] }}</a>
    @endforeach
    <a href="#settings-confirmation">{{ __('Confirm changes') }}</a>
</nav>

<section class="panel panel-wide" aria-labelledby="outbound-dns-preflight-title">
    <div class="section-heading">
        <h2 id="outbound-dns-preflight-title" tabindex="-1">{{ __('Outbound DNS compatibility preflight') }}</h2>
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
            <li>{{ __('SSH whole-file limits are independent of Owner-selected inline SFTP read/write windows, 64 KiB temporary streaming blocks, and WordPress transfer limits. The binary sidecar must be independently enabled and authorized.') }}</li>
            <li>{{ __('SSH Job concurrency counts only live admission leases, not retained historical records. Remote systemd runtime and metadata retention are independent. A stale or ambiguous Job is never automatically replayed; remote uncertainty remains visible after its admission lease ends.') }}</li>
            <li>{{ __('Unverifiable orphaned Job spools require deliberate operator reconciliation after independently verified cleanup on the original SSH host, never a newly rebound Target.') }}</li>
            <li>{{ __('Selecting up to 600 seconds for a synchronous SSH command requires the hosting PHP worker, HTTP proxy and MCP client to support that duration. An unsupported hop can terminate the HTTP request even when the remote effect is uncertain. Use detached SSH Jobs for longer or uncertain work.') }}</li>
            <li>{{ __('Values cannot override PHP worker, proxy/CDN, filesystem or actual client limits. These bounded ranges remain provisional pending operational measurements.') }}</li>
        </ul>
    </details>

    <form class="operations-form" method="post" action="{{ route('admin.operations.update') }}">
        @csrf
        @method('PUT')
        <input type="hidden" name="version" value="{{ $state['version'] }}">

        @foreach ($groups as $group)
            <fieldset class="operations-group" tabindex="-1" id="settings-{{ $group['id'] }}">
                <legend>{{ $group['title'] }}</legend>
                <p class="field-help operations-group-intro reading-width">{{ $group['description'] }}</p>
                <div class="operations-field-grid">
                    @foreach ($group['keys'] as $key)
                        @php
                            $range = $definitions[$key];
                            $isTime = str_ends_with($key, '_seconds');
                            $unit = str_ends_with($key, '_hours') ? __('hours')
                                : (str_ends_with($key, '_per_user') ? __('jobs')
                                    : ($isTime ? __('seconds') : __('KiB')));
                            $fieldId = 'setting_'.$key;
                            $effective = $state['overrides'][$key] ?? $defaults[$key];
                            if ($key === 'wp_request_timeout_seconds') {
                                $effective = max($effective, $state['overrides']['wp_connect_timeout_seconds'] ?? $defaults['wp_connect_timeout_seconds']);
                            }
                            $isIntegerUnit = $isTime || str_ends_with($key, '_hours') || str_ends_with($key, '_per_user');
                            $formattedEffective = $isIntegerUnit ? $effective : number_format($effective, 2);
                            $formattedDefault = $isIntegerUnit ? $defaults[$key] : number_format($defaults[$key], 2);
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
                                    aria-describedby="{{ $fieldId }}_info{{ $errors->has('values.'.$key) ? ' '.$fieldId.'_error' : '' }}"
                                    @error('values.'.$key) aria-invalid="true" @enderror
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
                                <p class="form-error" id="{{ $fieldId }}_error" role="alert">{{ $message }}</p>
                            @enderror
                        </div>
                    @endforeach
                </div>
            </fieldset>
        @endforeach
        @error('values')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        @error('version')<p class="form-error" role="alert">{{ $message }}</p>@enderror

        <fieldset class="operations-group operations-confirmation" tabindex="-1" id="settings-confirmation">
            <legend>{{ __('Confirm changes') }}</legend>
            <p class="field-help">{{ __('Editing these limits does not grant any new Target permission, unlock binary transfer, or replace an external server setting. Changes are version-checked and audited.') }}</p>
            <div class="field">
                <label for="current_password">{{ __('Current Owner password') }}</label>
                <input id="current_password" type="password" name="current_password" required
                    autocomplete="current-password" maxlength="255"
                    aria-describedby="current-password-help{{ $errors->has('current_password') ? ' current-password-error' : '' }}"
                    @error('current_password') aria-invalid="true" @enderror>
                <p class="field-help" id="current-password-help">{{ __('Required to authorize any settings change. The password is never stored as an override or logged.') }}</p>
                @error('current_password')<p class="form-error" id="current-password-error" role="alert">{{ $message }}</p>@enderror
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
