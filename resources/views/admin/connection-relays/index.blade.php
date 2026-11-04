@extends('admin.layout')

@section('title', __('Connection Relays'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('System') }}</div>
        <h1>{{ __('Connection Relays') }}</h1>
        <p class="muted reading-width">{{ __('Configure an Iran intermediary once, then select it for multiple SSH/SFTP and WordPress Targets. Direct and existing Reverse SSH remain separate connection methods.') }}</p>
    </div>
    <a href="{{ route('admin.targets.create') }}">{{ __('Add Target') }}</a>
</div>

<section class="panel panel-wide" aria-labelledby="relay-setup-heading">
    <h2 id="relay-setup-heading">{{ __('One-time host setup and trust boundary') }}</h2>
    <p>{{ __('Register Relay metadata below while disabled. A separately authorized host operator provisions a dedicated restricted OpenSSH -D tunnel and verifies the Gateway PHP-FPM UID is dedicated, then installs a root-owned isolation attestation. The Admin application cannot install SSH users, keys, firewalls or services on its own.') }}</p>
    <p class="field-help">{{ __('Loopback-only SOCKS5 is not isolation when multiple PHP websites share the same Unix user. Only the dedicated Gateway PHP UID may reach the selected listener; the Iran SSH account must have bounded outbound forwarding. Never expose SOCKS5 publicly or use an ambient system proxy.') }}</p>
    <p class="field-help">{{ __('Host policy and verification steps:') }} <code>docs/CONNECTION-RELAYS.md</code>. {{ __('An attested host is not proof that a Target is reachable or authenticated. Use Test control listener and then the Target-specific authentication test.') }}</p>
</section>

<section class="panel panel-wide" aria-labelledby="relay-list-heading">
    <h2 id="relay-list-heading">{{ __('Registered Relays') }}</h2>
    @forelse ($relays as $relay)
        <article class="target-subsection" aria-labelledby="relay-title-{{ $relay->id }}">
            <h3 id="relay-title-{{ $relay->id }}">{{ $relay->display_name }}</h3>
            <dl class="detail-list">
                <dt>{{ __('Relay ID') }}</dt><dd><code>{{ $relay->relay_id }}</code></dd>
                <dt>{{ __('SSH control endpoint') }}</dt><dd><code>{{ $relay->control_user }}@{{ $relay->control_host }}:{{ $relay->control_port }}</code></dd>
                <dt>{{ __('Gateway loopback SOCKS5') }}</dt><dd><code>127.0.0.1:{{ $relay->local_socks_port }}</code></dd>
                <dt>{{ __('Bound Targets') }}</dt><dd>{{ $counts[$relay->id] ?? 0 }}</dd>
                <dt>{{ __('Configured status') }}</dt><dd>{{ $relay->enabled ? __('Enabled') : __('Disabled') }}</dd>
                <dt>{{ __('Host isolation attestation') }}</dt><dd>{{ $hostStates[$relay->id] ? __('Verified file is present for this PHP UID') : __('Missing or invalid — not ready') }}</dd>
            </dl>
            @if ($relay->enabled)
                <form method="post" class="form-stack" action="{{ route('admin.connection-relays.test', ['relay' => $relay->id]) }}">
                    @csrf
                    <button class="button button-secondary" type="submit">{{ __('Test SOCKS5 control listener') }}</button>
                    <p class="field-help">{{ __('No Target packets, commands or credentials are sent by this control-only check.') }}</p>
                </form>
            @endif
            <form method="post" class="form-stack" action="{{ route('admin.connection-relays.toggle', ['relay' => $relay->id]) }}">
                @csrf
                <input type="hidden" name="relay_revision" value="{{ $relay->configuration_revision }}">
                <input type="hidden" name="enable" value="{{ $relay->enabled ? '0' : '1' }}">
                <div class="field">
                    <label for="relay-toggle-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                    <input id="relay-toggle-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                </div>
                <button class="button {{ $relay->enabled ? 'button-secondary' : 'button-primary' }}" type="submit">{{ $relay->enabled ? __('Disable Relay and fence all Target routes') : __('Enable only after verified host setup') }}</button>
            </form>
            @if (! $relay->enabled && (int) ($counts[$relay->id] ?? 0) === 0)
                <details>
                    <summary>{{ __('Edit disabled Relay identity') }}</summary>
                    <form class="form-stack" method="post" action="{{ route('admin.connection-relays.update', ['relay' => $relay->id]) }}" autocomplete="off">
                        @csrf
                        @method('PUT')
                        <input type="hidden" name="relay_revision" value="{{ $relay->configuration_revision }}">
                        @include('admin.connection-relays.partials.fields', ['prefix' => 'edit-'.$relay->id, 'editing' => true])
                        <div class="field">
                            <label for="relay-edit-password-{{ $relay->id }}">{{ __('Current Owner password') }}</label>
                            <input id="relay-edit-password-{{ $relay->id }}" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
                        </div>
                        <button class="button button-primary" type="submit">{{ __('Save Relay identity (requires new host setup)') }}</button>
                    </form>
                </details>
            @endif
        </article>
    @empty
        <p class="muted">{{ __('No Connection Relays have been configured. Register one below; it will remain disabled until independently verified host setup.') }}</p>
    @endforelse
</section>

<section class="panel panel-wide" aria-labelledby="relay-add-heading">
    <h2 id="relay-add-heading">{{ __('Add Connection Relay') }}</h2>
    <form class="form-stack" method="post" action="{{ route('admin.connection-relays.store') }}" autocomplete="off">
        @csrf
        @include('admin.connection-relays.partials.fields', ['prefix' => 'add', 'editing' => false, 'relay' => null])
        <div class="field">
            <label for="relay-add-password">{{ __('Current Owner password') }}</label>
            <input id="relay-add-password" type="password" name="current_password" data-admin-requires-intent autocomplete="current-password" maxlength="255" required>
        </div>
        <button class="button button-primary" type="submit">{{ __('Register disabled Relay') }}</button>
        <p class="field-help">{{ __('Registration never installs software, opens a tunnel or grants Target access.') }}</p>
    </form>
</section>
@endsection
