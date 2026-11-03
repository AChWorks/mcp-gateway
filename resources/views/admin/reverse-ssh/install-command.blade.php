@extends('admin.layout')

@section('title', __('Reverse SSH setup command'))
@section('form-page', '1')

@section('head')
<meta name="referrer" content="no-referrer">
@endsection

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Targets / Reverse SSH') }}</div>
        <h1>{{ __('Pending Setup created') }}</h1>
        <p class="muted">{{ __('The following one-use command is displayed only in this response. Treat it as a short-lived credential. Do not paste it into tickets, logs or shared chat.') }}</p>
    </div>
    <a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Open Target details') }}</a>
</div>
<section class="panel panel-wide" aria-labelledby="reverse-install-command">
    <h2 id="reverse-install-command">{{ __('Run once on the Target server') }}</h2>
    <p><strong>{{ __('Target') }}:</strong> <code>{{ $target->target_id }}</code></p>
    <p><strong>{{ __('Enrollment expires') }}:</strong> <time datetime="{{ $expires->toIso8601String() }}">{{ $expires->toIso8601String() }}</time></p>
    <div class="field">
        <label for="reverse_setup_command">{{ __('Verified installer command') }}</label>
        <textarea id="reverse_setup_command" rows="7" readonly spellcheck="false" autocomplete="off">{{ $command }}</textarea>
    </div>
    <p>{{ __('The command downloads the fixed installer over HTTPS, checks its exact SHA256 BEFORE sudo and runs an OpenSSH/systemd setup. It contains a one-use enrollment token but no SSH private keys. The installer script does NOT run unless its expected digest matches.') }}</p>
    <p><strong>{{ __('Installer SHA256') }}:</strong> <code>{{ $installerSha }}</code></p>
    <p class="field-help">{{ __('Confirm this digest against the independently trusted MCP Gateway release manifest. A digest displayed by the same server is not an independent signature. Without independently trusted release evidence, do not execute privileged installer material.') }}</p>
    <p>{{ __('Installation does not mark the Target connected. Once installed, open its Details and run Verify to check the real pinned host key and login through the tunnel.') }}</p>
</section>
@endsection
