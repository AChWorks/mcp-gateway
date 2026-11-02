@extends('admin.layout')

@section('title', __('Reverse SSH settings'))
@section('form-page', '1')

@section('content')
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
        <dt>{{ __('State') }}</dt><dd><strong>{{ __($status) }}</strong></dd>
        <dt>{{ __('Restricted key reader') }}</dt><dd>{{ $fileReady ? __('Available locally') : __('Missing or not writable by PHP') }}</dd>
        <dt>{{ __('Pending enrollments') }}</dt><dd>{{ $pending }}</dd>
        <dt>{{ __('Activated enrollments') }}</dt><dd>{{ $active }}</dd>
    </dl>
    <p class="field-help">{{ __('This status only checks local configuration and key-reader availability. It does not prove that sshd, firewall, control port or a remote tunnel is reachable. PHP cannot change root-owned SSHD/systemd configuration without a separately approved bootstrap.') }}</p>
    @unless ($fileReady)
        <div class="alert alert-error" role="status">
            {{ __('One-time Gateway host setup is required. Use a trusted, independently verified release installer with explicit host approval. No host privileges are granted to this Admin page.') }}
        </div>
    @endunless
</section>

<section class="panel panel-wide" aria-labelledby="reverse-config">
    <h2 id="reverse-config">{{ __('Configure Reverse SSH') }}</h2>
    <form action="{{ route('admin.reverse-ssh.save') }}" method="post" class="form-stack">
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
                <input id="reverse_control_host" type="text" name="control_host" maxlength="253" required value="{{ old('control_host', $gateway?->control_host ?? '') }}" autocomplete="off">
                @error('control_host')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="reverse_control_port">{{ __('Control SSH port') }}</label>
                <input id="reverse_control_port" type="number" name="control_port" min="1024" max="65535" required value="{{ old('control_port', $gateway?->control_port ?? 7770) }}">
                @error('control_port')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="reverse_control_user">{{ __('Restricted control username') }}</label>
                <input id="reverse_control_user" name="control_user" maxlength="32" required value="{{ old('control_user', $gateway?->control_user ?? 'mcp-reverse') }}" spellcheck="false" autocomplete="off">
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
            <input id="reverse_owner_password" type="password" name="current_password" required maxlength="255" autocomplete="current-password">
            @error('current_password')<p class="field-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="target-create-actions">
            <button class="button button-primary" type="submit">{{ __('Save settings') }}</button>
        </div>
    </form>
    <form action="{{ route('admin.reverse-ssh.repair') }}" method="post">
        @csrf
        <div class="field">
            <label for="reverse_repair_password">{{ __('Current Owner password (repair)') }}</label>
            <input id="reverse_repair_password" type="password" name="current_password" required autocomplete="current-password">
        </div>
        <button class="button button-secondary" type="submit">{{ __('Reconcile restricted public keys') }}</button>
    </form>
</section>
@endsection
