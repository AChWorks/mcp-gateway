@extends('admin.layout')

@section('title', __('Add site'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Sites') }}</div>
        <h1>{{ __('Add WordPress site') }}</h1>
        <p class="muted">{{ __("The Gateway will verify a public HTTPS target and discover the site's WP AI Bridge OAuth/MCP metadata before saving it.") }}</p>
    </div>
    <a href="{{ route('admin.sites.index') }}">{{ __('Back to sites') }}</a>
</div>

<section class="panel" aria-labelledby="add-site-title">
    <h2 id="add-site-title" class="sr-only">{{ __('Site details') }}</h2>
    <form class="form-stack" method="post" action="{{ route('admin.sites.store') }}">
        @csrf

        <div class="field">
            <label for="display_name">{{ __('Display name') }}</label>
            <input id="display_name" name="display_name" type="text" maxlength="160" required autocomplete="off" value="{{ old('display_name') }}" @error('display_name') aria-invalid="true" aria-describedby="display-name-error" @enderror>
            @error('display_name')<p class="field-error" id="display-name-error">{{ $message }}</p>@enderror
        </div>

        <div class="field">
            <label for="base_url">{{ __('WordPress HTTPS URL') }}</label>
            <input id="base_url" name="base_url" type="url" maxlength="2048" required inputmode="url" placeholder="https://wordpress.example.com" value="{{ old('base_url') }}" @error('base_url') aria-invalid="true" aria-describedby="base-url-error" @enderror>
            <p class="field-help">{{ __('Only a safe public HTTPS target accepted by the Gateway outbound policy can be registered.') }}</p>
            @error('base_url')<p class="field-error" id="base-url-error">{{ $message }}</p>@enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Discover and add site') }}</button>
    </form>
</section>
@endsection
