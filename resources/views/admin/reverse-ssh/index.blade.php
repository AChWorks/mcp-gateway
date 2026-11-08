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
    <p class="field-help">{{ __('Configuration') }}: <strong>{{ __($configurationState) }}</strong>. {{ __('Local host state') }}: <strong>{{ __($status) }}</strong>. {{ __('Only Target verification proves the remote SSH connection.') }}</p>
    <details class="target-help-details" @if($status === 'Degraded') open @endif>
        <summary>{{ __('View technical readiness and host diagnostics') }}</summary>
        <dl class="detail-list">
        <dt>{{ __('Restricted key reader') }}</dt><dd>{{ $fileReady ? __('Available locally') : __('Missing or not writable by PHP') }}</dd>
        <dt>{{ __('Key policy publication') }}</dt><dd>{{ $policyReconciled ? __('Reconciled') : __('Pending or mismatched — Owner repair required') }}</dd>
        <dt>{{ __('Local SSH host verification') }}</dt><dd>{{ __($readiness['reason']) }}</dd>
        <dt>{{ __('Control TCP port') }}</dt><dd>{{ $controlPort ?? __('Not configured') }}</dd>
        <dt>{{ __('Remote Target reachability') }}</dt><dd>{{ __($readiness['external']) }}</dd>
        <dt>{{ __('Pending enrollments') }}</dt><dd>{{ $pending }}</dd>
        <dt>{{ __('Activated enrollments') }}</dt><dd>{{ $active }}</dd>
        </dl>
        <p class="field-help">{{ __('Local readiness checks a bounded SSH handshake with the pinned control host key, but does not prove systemd supervision, firewall policy, PHP/host namespace equivalence or remote Target egress.') }}</p>
        <p class="field-help">{{ __('With separately approved host access, inspect these host checks:') }}</p>
        <ul class="diagnostic-command-list" role="list" aria-label="{{ __('Host inspection commands') }}">
            <li><code class="command-snippet" dir="ltr">sudo systemctl status mcp-gateway-reverse-sshd.service --no-pager</code></li>
            <li><code class="command-snippet" dir="ltr">sudo ss -lntp</code></li>
        </ul>
        <p class="field-help">{{ __('Run the verified release installer with --preflight and actual --app, --php-user and dedicated --port before privileged setup.') }}</p>
    </details>
    @if ($errors->any() && (! $editing || session('reverse_ssh_operation')))
        <div class="alert alert-error" role="alert" data-admin-feedback tabindex="-1" autofocus>
            <strong>
                @if (session('reverse_ssh_operation') === 'save_publication_failed')
                    {{ __('Configuration Save could not complete key publication.') }}
                @elseif (session('reverse_ssh_operation') === 'repair_failed')
                    {{ __('Owner Repair could not complete key publication.') }}
                @else
                    {{ __('The host repair did not complete.') }}
                @endif
            </strong>
            <ul>@foreach ($errors->all() as $message)<li>{{ $message }}</li>@endforeach</ul>
            @if ($gateway && session('reverse_ssh_operation'))
                <p>{{ __('Current saved revision: :revision. Restricted key publication: :status.', [
                    'revision' => $gateway->revision,
                    'status' => $gateway->publication_pending ? __('Pending reconciliation') : __('No pending publication'),
                ]) }}</p>
                <p>{{ __('The database and host key reader may differ. Inspect host readiness below and use the explicit Owner Repair action only when available; saved configuration is not remote connectivity.') }}</p>
            @endif
        </div>
    @endif

    @if ($status === 'Degraded')
        <div class="alert alert-error" role="status">{{ __('Gateway Reverse SSH needs host inspection or key-policy reconciliation before onboarding. A key reader alone is not proof of SSHD availability.') }}</div>
    @elseif ($status === 'Needs host setup')
        <div class="alert alert-info" role="status">{{ __('The optional managed feature has not been bootstrapped on this host. Normal Direct SSH Targets remain available.') }}</div>
    @endif
</section>

@if (! $gateway || $status !== 'Ready')
<section class="panel panel-wide" aria-labelledby="reverse-setup">
    <h2 id="reverse-setup">{{ __('One-time Gateway host setup') }}</h2>
    @if (! $gateway)
        <p class="field-help"><strong>{{ __('Next: prepare the dedicated SSH control host, then save the independently verified Gateway identity below.') }}</strong></p>
    @elseif (! $gateway->enabled)
        <p class="field-help"><strong>{{ __('This feature is disabled. Direct SSH remains available. Enable only after approved host setup.') }}</strong></p>
    @elseif ($status === 'Degraded')
        <p class="field-help"><strong>{{ __('Next: diagnose the existing restricted service and key publication before adding a Target. Inspect the technical diagnostics above.') }}</strong></p>
    @else
        <p class="field-help"><strong>{{ __('Next: complete the separately approved host setup and confirm local readiness before Managed enrollment.') }}</strong></p>
    @endif
    <ol class="reverse-setup-list" aria-label="{{ __('Gateway bootstrap checklist') }}">
        <li><strong>{{ __('Verify the installed release') }}</strong>
            <p class="field-help">{{ __('Use independently verified immutable Gateway installer artifacts. Select a dedicated SSH control port that does not conflict with normal SSH or a Target loopback listener.') }}</p>
        </li>
        <li><strong>{{ __('Check compatibility without changes') }}</strong>
            <p class="field-help">{{ __('Run the verified installer in --preflight mode with the actual application path, PHP service account and selected control port using authorized host access.') }}</p>
        </li>
        <li><strong>{{ __('Apply the restricted host service only after approval') }}</strong>
            <p class="field-help">{{ __('The privileged --apply step creates an isolated OpenSSH control service and key reader; this Admin page never runs it. Firewall ingress and narrowly scoped PHP open_basedir access require separate approval. Do not disable PHP isolation or modify the normal SSHD.') }}</p>
        </li>
        <li><strong>{{ __('Pin control SSHD identity and save settings') }}</strong>
            <p class="field-help">{{ __('Verify the dedicated public host key independently. Enter the real control host, port, restricted username and public host key below, confirm with the Owner password, then check local readiness.') }}</p>
        </li>
        <li><strong>{{ __('Enroll and verify each Target') }}</strong>
            <p class="field-help">{{ __('Use Targets > Add Target > SSH > Managed Reverse. The installer creates Pending Setup; only Target Details verification proves the actual remote SSH host key and login. Local Ready is not remote Connected.') }}</p>
        </li>
    </ol>
</section>
@endif

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
            <dt>{{ __('Revision') }}</dt><dd>{{ $gateway->revision }}</dd>
            <dt>{{ __('Key publication') }}</dt><dd>{{ $gateway->publication_pending ? __('Pending reconciliation') : __('Reconciled') }}</dd>
            <dt>{{ __('Feature state') }}</dt><dd>{{ $gateway->enabled ? __('Enabled') : __('Disabled') }}</dd>
            <dt>{{ __('Control host') }}</dt><dd><code>{{ $gateway->control_host }}</code></dd>
            <dt>{{ __('Control SSH port') }}</dt><dd><code>{{ $gateway->control_port }}</code></dd>
            <dt>{{ __('Restricted control username') }}</dt><dd><code>{{ $gateway->control_user }}</code></dd>
            <dt>{{ __('Pinned control SSHD fingerprint') }}</dt><dd><code>{{ $gatewayFingerprint ?? __('Unavailable — inspect saved key') }}</code></dd>
        </dl>
        <p class="field-help">{{ __('This saved configuration does not prove host readiness or any remote Target is connected. Review the local checks above, then enroll Targets under Targets → Add Target.') }}</p>
    @else

    <form action="{{ route('admin.reverse-ssh.save') }}" method="post" class="form-stack" autocomplete="off">
        @csrf
        @method('PUT')
        <input type="hidden" name="revision" value="{{ $gateway?->revision ?? 0 }}">
        @if ($errors->any() && session('reverse_ssh_operation') !== 'save_publication_failed' && session('reverse_ssh_operation') !== 'repair_failed')
            <div class="alert alert-error" role="alert">
                <p>{{ __('The proposed configuration was not accepted. Check the fields and retry.') }}</p>
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
