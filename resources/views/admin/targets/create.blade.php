@extends('admin.layout')

@section('title', __('Add Target'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Targets') }}</div>
        <h1>{{ __('Add Target') }}</h1>
        <p class="muted">{{ __('Choose a supported connector, then give the Target an immutable ID and its connector-specific settings. Only WordPress is currently available.') }}</p>
    </div>
    <a href="{{ route('admin.targets.index') }}">{{ __('Back to Targets') }}</a>
</div>

<section class="panel" aria-label="{{ __('New Target details') }}">
    <form class="form-stack" method="post" action="{{ route('admin.targets.store') }}">
        @csrf
        <div class="field">
            <label for="connector_type">{{ __('Connector type') }}</label>
            <select id="connector_type" name="connector_type" required aria-describedby="connector_type_help" @error('connector_type') aria-invalid="true" @enderror>
                <option value="wp_ai_bridge" @selected(old('connector_type', 'wp_ai_bridge') === 'wp_ai_bridge')>{{ __('WordPress (WP AI Bridge)') }}</option>
            </select>
            <p id="connector_type_help" class="field-help">{{ __('Only connectors with a working registration flow appear here. SSH and AI Server Agent are not available in this release.') }}</p>
            @error('connector_type')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <h2 class="form-subheading">{{ __('Target identity') }}</h2>
        <div class="field">
            <label for="target_id">{{ __('Stable Target ID') }}</label>
            <input id="target_id" name="target_id" type="text" maxlength="64" pattern="[a-z0-9]+(-[a-z0-9]+)*" required autocomplete="off" spellcheck="false" value="{{ old('target_id') }}" @error('target_id') aria-invalid="true" aria-describedby="target-id-error" @enderror>
            <p class="field-help">{{ __('Lowercase letters, numbers and hyphens; immutable after registration.') }}</p>
            @error('target_id')<p id="target-id-error" class="field-error">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="display_name">{{ __('Display name') }}</label>
            <input id="display_name" name="display_name" type="text" maxlength="160" required autocomplete="off" value="{{ old('display_name') }}" @error('display_name') aria-invalid="true" aria-describedby="display-name-error" @enderror>
            @error('display_name')<p id="display-name-error" class="field-error">{{ $message }}</p>@enderror
        </div>
        <h2 class="form-subheading">{{ __('WordPress connection') }}</h2>
        <div class="field">
            <label for="base_url">{{ __('WordPress public HTTPS URL') }}</label>
            <input id="base_url" name="base_url" type="url" maxlength="2048" required inputmode="url" placeholder="https://wordpress.example.com" value="{{ old('base_url') }}" @error('base_url') aria-invalid="true" aria-describedby="base-url-error" @enderror>
            <p class="field-help">{{ __('Endpoint must satisfy the Gateway outbound network and metadata policy.') }}</p>
            @error('base_url')<p id="base-url-error" class="field-error">{{ $message }}</p>@enderror
        </div>
        <button class="button button-primary" type="submit">{{ __('Verify and add WordPress Target') }}</button>
    </form>
</section>
@endsection
