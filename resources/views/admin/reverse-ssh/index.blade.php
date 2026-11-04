@extends('admin.layout')

@section('title', __('Reverse SSH settings'))
@section('form-page', '1')
@section('admin-errors-inline', '1')

@section('content')
@php($editing = ! $gateway || request()->boolean('edit'))
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('System') }}</div>
        <h1>{{ __('Managed Reverse SSH') }}</h1>
        <p class="muted">{{ __('Optional outbound-only onboarding for SSH Targets that cannot accept inbound connections from Gateway.') }}</p>
    </div>
    <a href="{{ route('admin.targets.create', ['connector_type' => 'ssh_direct']) }}">{{ __('Back to Add Target') }}</a>
</div>

<section class="panel panel-wide" aria-labelledby="reverse-status">
    <h2 id="reverse-status">{{ __('Gateway host readiness') }}</h2>
    <dl class="detail-list">
        <dt>{{ __('Configuration') }}</dt><dd><strong>{{ __($configurationState) }}</strong></dd>
        <dt>{{ __('Local host state') }}</dt><dd><strong>{{ __($status) }}</strong></dd>
        <dt>{{ __('Restricted key reader') }}</dt><dd>{{ $fileReady ? __('Available locally') : __('Missing or not writable by PHP') }}</dd>
        <dt>{{ __('Key policy publication') }}</dt><dd>{{ $policyReconciled ? __('Reconciled') : __('Pending or mismatched — Owner repair required') }}</dd>
        <dt>{{ __('Local SSH host verification') }}</dt><dd>{{ __($readiness['reason']) }}</dd>
        <dt>{{ __('Control TCP port') }}</dt><dd>{{ $controlPort ?? __('Not configured') }}</dd>
        <dt>{{ __('Remote Target reachability') }}</dt><dd>{{ __($readiness['external']) }}</dd>
        <dt>{{ __('Pending enrollments') }}</dt><dd>{{ $pending }}</dd>
        <dt>{{ __('Activated enrollments') }}</dt><dd>{{ $active }}</dd>
    </dl>
    @if ($errors->any() && ! $editing)
        <div class="alert alert-error" role="alert">
            <strong>{{ __('The host repair did not complete.') }}</strong>
            <ul>@foreach ($errors->all() as $message)<li>{{ $message }}</li>@endforeach</ul>
        </div>
    @endif
    <p class="field-help">{{ __('The local status probes a bounded SSH handshake with the pinned control key when enabled and reachable. It does not prove systemd supervision, firewall policy, container-host namespace equivalence or remote Target egress. PHP cannot change root-owned SSHD/systemd configuration without a separately approved bootstrap.') }}</p>
    <p class="field-help">{{ __('Trusted Gateway host checks (run with separately authorized host access):') }} <code>sudo systemctl status mcp-gateway-reverse-sshd.service --no-pager</code> {{ __('and') }} <code>sudo ss -lntp</code>. {{ __('To validate setup compatibility first, run the verified release installer with --preflight, the actual --app path, --php-user and selected --port.') }}</p>
    @if ($status === 'Degraded')
        <div class="alert alert-error" role="status">{{ __('Gateway Reverse SSH needs host inspection or key-policy reconciliation before onboarding. A key reader alone is not proof of SSHD availability.') }}</div>
    @elseif ($status === 'Needs host setup')
        <div class="alert alert-info" role="status">{{ __('The optional managed feature has not been bootstrapped on this host. Normal Direct SSH Targets remain available.') }}</div>
    @endif
    @unless ($fileReady)
        <div class="alert alert-info" role="status">
            {{ __('One-time Gateway host setup is required. Use a trusted, independently verified release installer with explicit host approval. No host privileges are granted to this Admin page.') }}
        </div>
    @endunless
</section>

<section class="panel panel-wide" aria-labelledby="reverse-config">
    <div class="page-heading">
        <div>
            <h2 id="reverse-config">{{ $gateway ? __('Reverse SSH configuration') : __('Configure Reverse SSH') }}</h2>
            <p class="field-help">{{ __('These settings apply once to this Gateway, not to individual Targets.') }}</p>
        </div>
        @if ($gateway && ! $editing)
            <a class="button button-secondary" href="{{ route('admin.reverse-ssh.index', ['edit' => '1']) }}#reverse-config">{{ __('Edit settings') }}</a>
        @elseif ($gateway)
            <a class="button button-secondary" href="{{ route('admin.reverse-ssh.index') }}#reverse-config">{{ __('Cancel editing') }}</a>
        @endif
    </div>
    @if ($gateway && ! $editing)
        <dl class="detail-list" aria-label="{{ __('Saved Gateway Reverse SSH settings') }}">
            <dt>{{ __('Configuration') }}</dt><dd><strong>{{ __('Saved') }}</strong></dd>
            <dt>{{ __('Feature state') }}</dt><dd>{{ $gateway->enabled ? __('Enabled') : __('Disabled') }}</dd>
            <dt>{{ __('Control host') }}</dt><dd><code>{{ $gateway->control_host }}</code></dd>
            <dt>{{ __('Control SSH port') }}</dt><dd><code>{{ $gateway->control_port }}</code></dd>
            <dt>{{ __('Restricted control username') }}</dt><dd><code>{{ $gateway->control_user }}</code></dd>
            <dt>{{ __('Pinned control SSHD fingerprint') }}</dt><dd><code>{{ $gatewayFingerprint ?? __('Unavailable — inspect saved key') }}</code></dd>
            <dt>{{ __('Host readiness') }}</dt><dd>{{ __($status) }}</dd>
        </dl>
        <p class="field-help">{{ __('This saved configuration does not prove host readiness or any remote Target is connected. Review the local checks above, then enroll Targets under Targets → Add Target.') }}</p>
    @else

    <form action="{{ route('admin.reverse-ssh.save') }}" method="post" class="form-stack" autocomplete="off">
        @csrf
        @method('PUT')
        <input type="hidden" name="revision" value="{{ $gateway?->revision ?? 0 }}">
        @if ($errors->any())
            <div class="alert alert-error" role="alert">
                <p>{{ __('No configuration was applied. Check the fields and retry.') }}</p>
                <ul>@foreach ($errors->all() as $message)<li>{{ $message }}</li>@endforeach</ul>
            </div>
        @endif
        <div class="field">
            <label for="reverse_enabled">{{ __('Feature state') }}</label>
            <select id="reverse_enabled" name="enabled" required>
                <option value="0" @selected(old('enabled', $gateway?->enabled ? '1' : '0') === '0')>{{ __('Disabled (default)') }}</option>
                <option value="1" @selected(old('enabled', $gateway?->enabled ? '1' : '0') === '1')>{{ __('Enabled (host bootstrap required)') }}</option>
            </select>
            @error('enabled')<p class="field-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="target-field-grid">
            <div class="field">
                <label for="reverse_control_host">{{ __('Public control SSH host') }}</label>
                <input id="reverse_control_host" type="text" name="control_host" maxlength="253" required autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ old('control_host', $gateway?->control_host ?? '') }}" value="{{ old('control_host', $gateway?->control_host ?? '') }}">
                @error('control_host')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="reverse_control_port">{{ __('Control SSH port') }}</label>
                <input id="reverse_control_port" type="number" name="control_port" min="1024" max="65535" required value="{{ old('control_port', $gateway?->control_port ?? 7770) }}">
                @error('control_port')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="reverse_control_user">{{ __('Restricted control username') }}</label>
                <input id="reverse_control_user" name="control_user" maxlength="32" required autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ old('control_user', $gateway?->control_user ?? 'mcp-reverse') }}" value="{{ old('control_user', $gateway?->control_user ?? 'mcp-reverse') }}" spellcheck="false">
                @error('control_user')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="reverse_host_key">{{ __('Independently verified control SSHD public host key') }}</label>
                <textarea id="reverse_host_key" name="control_host_key" maxlength="4096" required rows="2" spellcheck="false" autocomplete="off">{{ old('control_host_key', $gateway?->control_host_key ?? '') }}</textarea>
                @error('control_host_key')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>
        <div class="field">
            <label for="reverse_owner_password">{{ __('Current Owner password') }}</label>
            <input id="reverse_owner_password" type="password" name="current_password" data-admin-requires-intent required maxlength="255" autocomplete="off">
            @error('current_password')<p class="field-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="target-create-actions">
            <button class="button button-primary" type="submit">{{ __('Save settings') }}</button>
        </div>
    </form>
    @endif
    @if ($gateway && $fileReady && ($status === 'Degraded' || ! $policyReconciled))
    <form action="{{ route('admin.reverse-ssh.repair') }}" method="post" data-admin-dirty-guard="off">
        @csrf
        <div class="field">
            <label for="reverse_repair_password">{{ __('Current Owner password (repair)') }}</label>
            <input id="reverse_repair_password" type="password" name="current_password" data-admin-requires-intent required autocomplete="current-password">
        </div>
        <button class="button button-secondary" type="submit">{{ __('Reconcile restricted public keys') }}</button>
    </form>
    @endif
</section>
@endsection
