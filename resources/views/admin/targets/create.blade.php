@extends('admin.layout')

@section('title', __('Add Target'))
@section('form-page', '1')
@section('admin-errors-inline', '1')

@section('content')
@php
    $requestedConnector = old('connector_type', $selectedConnector);
    $selectedSshMode = old('ssh_mode', $sshMode);
    $selected = is_string($requestedConnector) && array_key_exists($requestedConnector, $connectorOptions)
        ? $requestedConnector : '';
@endphp
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Targets') }}</div>
        <h1>{{ __('Add Target') }}</h1>
        <p class="muted">{{ __('Choose a connector, then provide only the details it needs. Registration never executes remote commands.') }}</p>
    </div>
    <a href="{{ route('admin.targets.index') }}">{{ __('Back to Targets') }}</a>
</div>

<section class="panel panel-wide target-enrollment" aria-labelledby="target-enrollment-title">
    <h2 id="target-enrollment-title">{{ __('New connection') }}</h2>
    <form id="target-create-form" method="post" action="{{ route($selectedSshMode === 'managed' ? 'admin.reverse-ssh.targets.store' : 'admin.targets.store') }}"
        data-standard-action="{{ route('admin.targets.store') }}"
        data-managed-action="{{ route('admin.reverse-ssh.targets.store') }}"
        data-managed-configured="{{ $managedConfigured ? 'true' : 'false' }}" class="form-stack" autocomplete="off">
        @csrf
        @if ($errors->any())
            <div id="target-registration-errors" class="alert alert-error" data-admin-feedback role="alert" tabindex="-1" autofocus aria-labelledby="target-registration-errors-title">
                <h3 id="target-registration-errors-title">{{ session('target_preflight_validation_failed') ? __('Endpoint check could not be completed.') : __('Target was not registered.') }}</h3>
                <p>{{ session('target_preflight_validation_failed')
                    ? __('Correct the endpoint fields and check again. No Target was registered.')
                    : __('Correct the fields below and submit again. Previously entered passwords, private keys and passphrases must be entered again.') }}</p>
                <ul>
                    @foreach ($errors->all() as $message)
                        <li>{{ $message }}</li>
                    @endforeach
                </ul>
                @include('admin.partials.operation-diagnostic', ['embedded' => true])
            </div>
        @endif
        <div class="field">
            <label for="connector_type">{{ __('1. Connector type') }}</label>
            <select id="connector_type" name="connector_type" required @error('connector_type') aria-invalid="true" @enderror aria-describedby="connector_type_help{{ $errors->has('connector_type') ? ' connector_type-error' : '' }}">
                <option value="">{{ __('Choose a connector') }}</option>
                @foreach ($connectorOptions as $type => $label)
                    <option value="{{ $type }}" @selected($selected === $type)>{{ $label }}</option>
                @endforeach
            </select>
            <p id="connector_type_help" class="field-help">{{ __('The next fields change with your selection. Only implemented connectors can be enrolled.') }}</p>
            @error('connector_type')<p class="field-error" role="alert" id="connector_type-error">{{ $message }}</p>@enderror
            <noscript>
                <p class="field-help">{{ __('JavaScript is disabled. Choose a connector below to open its server-rendered form:') }}</p>
                @foreach ($connectorOptions as $type => $label)
                    <a class="button button-secondary" href="{{ route('admin.targets.create', ['connector_type' => $type]) }}">{{ $label }}</a>
                @endforeach
            </noscript>
        </div>

        @include('admin.targets.partials.identity-fields')

        @foreach ($connectorDefinitions as $connectorDefinition)
            @include($connectorDefinition->enrollmentView)
        @endforeach

        <div class="target-create-actions" data-target-actions @if($selected === '') hidden @endif>
            <button class="button button-primary" type="submit" data-target-submit @disabled($selected === 'ssh_direct' && $selectedSshMode === 'managed' && ! $managedConfigured)>{{ $selectedSshMode === 'managed' ? __('Create Pending Setup and installer command') : __('Register Target') }}</button>
            <button class="button button-secondary" type="submit" data-target-preflight @if($selectedSshMode === 'managed') hidden disabled @endif
                formaction="{{ route('admin.targets.preflight') }}" formnovalidate>
                {{ __('Check endpoint from Gateway (no registration)') }}
            </button>
            <p class="field-help" id="target-credential-help">{{ __('Credentials are encrypted and never restored into this form after validation errors.') }}</p>
        </div>
        @if (session('target_endpoint_preflight'))
            @php($preflight = (array) session('target_endpoint_preflight'))
            <div id="target-endpoint-preflight" class="alert {{ ($preflight['ok'] ?? false) ? 'alert-success' : 'alert-error' }}"
                role="{{ ($preflight['ok'] ?? false) ? 'status' : 'alert' }}" data-admin-feedback tabindex="-1" autofocus
                @if (($preflight['ok'] ?? false) && isset($preflight['checked_connector'], $preflight['checked_fields']))
                    data-checked-connector="{{ $preflight['checked_connector'] }}"
                    data-checked-fields="{{ json_encode($preflight['checked_fields'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) }}"
                @endif>
                @if (! empty($preflight['checked_subject']))
                    <p><strong>{{ __('Checked endpoint') }}:</strong> <code>{{ $preflight['checked_subject'] }}</code></p>
                @endif
                <strong>{{ __('Gateway endpoint preflight') }}:</strong> {{ $preflight['message'] ?? '' }}
                @if (! empty($preflight['limitation']))
                    <p>{{ $preflight['limitation'] }}</p>
                @endif
                @if (! empty($preflight['next_step']))
                    <p><strong>{{ __('What to check') }}:</strong> {{ $preflight['next_step'] }}</p>
                @endif
                @if (! empty($preflight['reference']))
                    <p><strong>{{ __('Log reference') }}:</strong> <code>{{ $preflight['reference'] }}</code></p>
                @endif
            </div>
            @if (($preflight['ok'] ?? false) && ! empty($preflight['checked_fields']))
                <p id="target-preflight-stale" class="field-help" role="status" hidden>{{ __('The endpoint changed after preflight. The previous result no longer applies; check the new endpoint again.') }}</p>
            @endif
        @endif
        <p class="field-help" data-target-preflight-help @if($selectedSshMode === 'managed') hidden @endif>{{ __('Preflight is optional and read-only. It uses the selected connector network policy and does not register, contact, authenticate or trust a Target. Actual connections independently recheck DNS and verify their required identity protections.') }}</p>
    </form>
</section>


@endsection
