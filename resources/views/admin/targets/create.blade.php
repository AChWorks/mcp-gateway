@extends('admin.layout')

@section('title', __('Add Target'))

@section('content')
@php
    $requestedConnector = old('connector_type', $selectedConnector);
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
    <form id="target-create-form" method="post" action="{{ route('admin.targets.store') }}" class="form-stack">
        @csrf
        <div class="field">
            <label for="connector_type">{{ __('1. Connector type') }}</label>
            <select id="connector_type" name="connector_type" required aria-describedby="connector_type_help">
                <option value="">{{ __('Choose a connector') }}</option>
                @foreach ($connectorOptions as $type => $label)
                    <option value="{{ $type }}" @selected($selected === $type)>{{ $label }}</option>
                @endforeach
            </select>
            <p id="connector_type_help" class="field-help">{{ __('The next fields change with your selection. Only implemented connectors can be enrolled.') }}</p>
            @error('connector_type')<p class="field-error" role="alert">{{ $message }}</p>@enderror
            <noscript>
                <p class="field-help">{{ __('JavaScript is disabled. Choose a connector below to open its server-rendered form:') }}</p>
                @foreach ($connectorOptions as $type => $label)
                    <a class="button button-secondary" href="{{ route('admin.targets.create', ['connector_type' => $type]) }}">{{ $label }}</a>
                @endforeach
            </noscript>
        </div>

        <fieldset class="target-form-section" data-target-shared @if($selected === '') hidden disabled @endif>
            <legend>{{ __('2. Target details') }}</legend>
            <p class="field-help">{{ __('A stable ID identifies this Target across clients and permissions; the display name can change later.') }}</p>
            <div class="target-field-grid">
                <div class="field">
                    <label for="target_id">{{ __('Stable Target ID') }}</label>
                    <input type="text" id="target_id" name="target_id" maxlength="64" pattern="[a-z0-9]+(-[a-z0-9]+)*" required
                        autocomplete="off" spellcheck="false" placeholder="my-target" value="{{ old('target_id') }}">
                    <p class="field-help">{{ __('Lowercase letters, numbers and hyphens.') }}</p>
                    @error('target_id')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field">
                    <label for="display_name">{{ __('Display name') }}</label>
                    <input type="text" id="display_name" name="display_name" maxlength="160" required
                        placeholder="{{ __('Production blog or staging server') }}" value="{{ old('display_name') }}">
                    @error('display_name')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
                <div class="field target-span-all">
                    <label for="ai_guidance">{{ __('AI guidance (optional)') }}</label>
                    <textarea id="ai_guidance" name="ai_guidance" rows="3"
                        maxlength="{{ \App\Domain\Targets\Target::AI_GUIDANCE_MAX_LENGTH }}"
                        aria-describedby="ai_guidance_help" autocomplete="off"
                        placeholder="{{ __('Example: This is a production server. Explain risks and ask before making changes.') }}">{{ old('ai_guidance') }}</textarea>
                    <p id="ai_guidance_help" class="field-help">{{ __('Shown to authorized AI clients as Target-specific context. This is advice, not enforced approval. Never include credentials or secrets.') }}</p>
                    @error('ai_guidance')<p class="field-error" role="alert">{{ $message }}</p>@enderror
                </div>
            </div>
        </fieldset>

        @foreach ($connectorDefinitions as $connectorDefinition)
            @include($connectorDefinition->enrollmentView)
        @endforeach

        <div class="target-create-actions" data-target-actions @if($selected === '') hidden @endif>
            <button class="button button-primary" type="submit">{{ __('Register Target') }}</button>
            <button class="button button-secondary" type="submit"
                formaction="{{ route('admin.targets.preflight') }}" formnovalidate>
                {{ __('Check endpoint from Gateway (no registration)') }}
            </button>
            <p class="field-help">{{ __('Credentials are encrypted and never restored into this form after validation errors.') }}</p>
        </div>
        @if (session('target_endpoint_preflight'))
            @php($preflight = (array) session('target_endpoint_preflight'))
            <div id="target-endpoint-preflight" class="alert {{ ($preflight['ok'] ?? false) ? 'alert-success' : 'alert-error' }}"
                role="{{ ($preflight['ok'] ?? false) ? 'status' : 'alert' }}"
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
        <p class="field-help">{{ __('Preflight is optional and read-only. It uses the selected connector network policy and does not register, contact, authenticate or trust a Target. Actual connections independently recheck DNS and verify their required identity protections.') }}</p>
    </form>
</section>


@endsection
