@extends('admin.layout')

@section('title', __('Sign in'))

@section('content')
<section class="auth-card" aria-labelledby="sign-in-title">
    <div class="eyebrow">{{ __('Administration') }}</div>
    <h1 id="sign-in-title">{{ __('Sign in') }}</h1>
    <p class="muted">{{ __('Use the administrator account created on the Gateway server.') }}</p>

    <form method="post" action="{{ route('admin.login.store') }}" class="form-stack">
        @csrf

        <div class="field">
            <label for="email">{{ __('Email address') }}</label>
            <input
                id="email"
                name="email"
                type="email"
                value="{{ old('email') }}"
                autocomplete="username"
                inputmode="email"
                maxlength="254"
                required
                autofocus
                @error('email') aria-invalid="true" aria-describedby="email-error" @enderror
            >
            @error('email')
                <p class="field-error" id="email-error">{{ $message }}</p>
            @enderror
        </div>

        <div class="field">
            <label for="password">{{ __('Password') }}</label>
            <input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                maxlength="255"
                required
                @error('password') aria-invalid="true" aria-describedby="password-error" @enderror
            >
            @error('password')
                <p class="field-error" id="password-error">{{ $message }}</p>
            @enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Sign in') }}</button>
    </form>
</section>
@endsection
