@extends('admin.layout')

@section('title', __('Connection Relays'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('System') }}</div>
        <h1>{{ __('Connection Relays') }}</h1>
        <p class="muted reading-width">{{ __('Register one intermediary for several SSH/SFTP or WordPress Targets. Direct stays the default; existing Reverse SSH routes remain separate.') }}</p>
    </div>
    <a href="{{ route('admin.targets.create') }}">{{ __('Add Target') }}</a>
</div>

<section class="panel panel-wide" aria-labelledby="relay-setup-heading">
    <h2 id="relay-setup-heading">{{ __('Before enabling a Relay') }}</h2>
    <p class="muted reading-width">{{ __('Registration only saves an inactive route. A privileged host operator must complete these separate steps; the Gateway cannot install or attest its own transport.') }}</p>
    <ol class="reverse-setup-list">
        <li><strong>{{ __('Isolate the Gateway') }}</strong>
            <p class="field-help">{{ __('Use a dedicated PHP-FPM and worker UID, with exclusive access to the selected local SOCKS5 listener.') }}</p>
        </li>
        <li><strong>{{ __('Restrict the Iran intermediary') }}</strong>
            <p class="field-help">{{ __('Pin its SSH host key and limit a dedicated forwarding-only account to approved public destinations.') }}</p>
        </li>
        <li><strong>{{ __('Verify and attest the host') }}</strong>
            <p class="field-help">{{ __('Test the effective access rules, then issue fresh, boot- and policy-bound root-owned evidence. Recheck after every disable or host-policy change.') }}</p>
        </li>
    </ol>
    <details class="target-help-details">
        <summary>{{ __('Security details and operator runbook') }}</summary>
        <p class="field-help">{{ __('Loopback alone is not isolation when other websites share a PHP Unix user. The privileged verifier must refresh short-lived evidence and rotate its policy generation before changing relevant host rules. Never expose SOCKS5 publicly or use an ambient proxy.') }}</p>
        <p class="field-help">{{ __('Operator procedure:') }} <code>docs/CONNECTION-RELAYS.md</code></p>
        <p class="field-help">{{ __('A verified local SOCKS greeting is not proof of destination reachability or identity. Test the selected Target’s SSH key/login or HTTPS certificate separately.') }}</p>
    </details>
</section>

<section class="panel panel-wide" aria-labelledby="relay-list-heading">
    <h2 id="relay-list-heading">{{ __('Registered Relays') }}</h2>
    @forelse ($relays as $relay)
        <article class="target-subsection" aria-labelledby="relay-title-{{ $relay->id }}">
            <div class="section-heading">
                <div>
                    <h3 id="relay-title-{{ $relay->id }}">{{ $relay->display_name }}</h3>
                    <p class="field-help">{{ $relay->enabled ? __('Enabled for selected Targets') : __('Disabled — no Target can use this Relay') }}</p>
                </div>
            </div>
            <dl class="summary-list summary-grid">
                <div><dt>{{ __('Relay ID') }}</dt><dd><code>{{ $relay->relay_id }}</code></dd></div>
                <div><dt>{{ __('Control SSH') }}</dt><dd><code>{{ $relay->control_user.'@'.$relay->control_host.':'.$relay->control_port }}</code></dd></div>
                <div><dt>{{ __('Local SOCKS5') }}</dt><dd><code>127.0.0.1:{{ $relay->local_socks_port }}</code></dd></div>
                <div><dt>{{ __('Targets using Relay') }}</dt><dd>{{ $counts[$relay->id] ?? 0 }}</dd></div>
                <div><dt>{{ __('Host evidence') }}</dt><dd>{{ $hostStates[$relay->id] ? __('Current for this PHP UID') : __('Not ready — missing, expired or mismatched') }}</dd></div>
            </dl>
            @if ($relay->enabled)
                <form method="post" class="form-stack" action="{{ route('admin.connection-relays.test', ['relay' => $relay->id]) }}">
                    @csrf
                    <button class="button button-secondary" type="submit">{{ __('Check local SOCKS5 greeting') }}</button>
                    <p class="field-help">{{ __('Control-only check; no Target authentication or remote operation.') }}</p>
                </form>
            @endif
            <form method="post" class="form-stack" action="{{ route('admin.connection-relays.toggle', ['relay' => $relay->id]) }}">
                @csrf
                <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                <input type="hidden" name="enable" value="{{ $relay->enabled ? '0' : '1' }}">
                <div class="field">
                    <label for="relay-toggle-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                    <input id="relay-toggle-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                </div>
                <button class="button {{ $relay->enabled ? 'button-secondary' : 'button-primary' }}" type="submit">{{ $relay->enabled ? __('Disable Relay and fence bound Targets') : __('Enable with current host evidence') }}</button>
                @if (! $relay->enabled)
                    <p class="field-help">{{ __('Enabling requires renewed host evidence after any prior disable. Existing Targets must reconnect and verify their identity.') }}</p>
                @endif
            </form>
            @if (! $relay->enabled && (int) ($counts[$relay->id] ?? 0) === 0)
                <details class="target-help-details">
                    <summary>{{ __('Edit inactive Relay identity') }}</summary>
                    <p class="field-help">{{ __('Changing the control endpoint, key or port requires fresh privileged host verification before enabling.') }}</p>
                    <form class="form-stack" method="post" action="{{ route('admin.connection-relays.update', ['relay' => $relay->id]) }}" autocomplete="off">
                        @csrf
                        @method('PUT')
                        <input type="hidden" name="relay_revision" value="{{ $relay->lifecycle_revision }}">
                        <input type="hidden" name="edit_relay_id" value="{{ $relay->getKey() }}">
                        @include('admin.connection-relays.partials.fields', ['prefix' => 'edit-'.$relay->id, 'editing' => true])
                        <div class="field">
                            <label for="relay-edit-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                            <input id="relay-edit-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                        </div>
                        <button class="button button-primary" type="submit">{{ __('Save Relay identity') }}</button>
                    </form>
                </details>
            @elseif (! $relay->enabled)
                <p class="field-help">{{ __('Detach all bound Targets before editing this Relay’s identity.') }}</p>
            @endif
        </article>
    @empty
        <p class="muted">{{ __('No Relays registered yet. Add one below; it starts disabled and cannot route traffic until the host is verified.') }}</p>
    @endforelse
</section>

<section class="panel panel-wide" aria-labelledby="relay-add-heading">
    <h2 id="relay-add-heading">{{ __('Add Connection Relay') }}</h2>
    <p class="field-help">{{ __('Give this reusable route a stable name, control endpoint and independently verified public SSH host key.') }}</p>
    <form class="form-stack" method="post" action="{{ route('admin.connection-relays.store') }}" autocomplete="off">
        @csrf
        @include('admin.connection-relays.partials.fields', ['prefix' => 'add', 'editing' => false, 'relay' => null])
        <div class="field">
            <label for="relay-add-password">{{ __('Current Owner password') }}</label>
            <input id="relay-add-password" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
        </div>
        <button class="button button-primary" type="submit">{{ __('Register disabled Relay') }}</button>
        <p class="field-help">{{ __('No tunnel, firewall rule or Target authorization is created by this action.') }}</p>
    </form>
</section>
@endsection
