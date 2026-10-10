@extends('admin.layout')

@section('title', __('Add WordPress Target'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Targets') }}</div>
        <h1>{{ __('Register WordPress Target') }}</h1>
        <p class="muted">{{ __('Only the WP AI Bridge connector can be registered using this form. Its public HTTPS discovery is validated before saving; credentials are not created.') }}</p>
    </div>
    <a href="{{ route('admin.targets.index') }}">{{ __('Back to Targets') }}</a>
</div>

<section class="panel" aria-label="{{ __('WordPress Target details') }}">
    <form class="form-stack" method="post" action="{{ route('admin.targets.store') }}">
        @csrf
        <input type="hidden" name="connector_type" value="wp_ai_bridge">
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
        <div class="field">
            <label for="base_url">{{ __('WordPress public HTTPS URL') }}</label>
            <input id="base_url" name="base_url" type="url" maxlength="2048" required inputmode="url" placeholder="https://wordpress.example.com" value="{{ old('base_url') }}" @error('base_url') aria-invalid="true" aria-describedby="base-url-error" @enderror>
            <p class="field-help">{{ __('Endpoint must satisfy the Gateway outbound network and metadata policy.') }}</p>
            @error('base_url')<p id="base-url-error" class="field-error">{{ $message }}</p>@enderror
        </div>
        <button class="button button-primary" type="submit">{{ __('Verify and register WordPress Target') }}</button>
    </form>
</section>
@endsection
