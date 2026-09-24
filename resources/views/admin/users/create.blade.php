@extends('admin.layout')

@section('title', __('Add user'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Add local user') }}</h1>
        <p class="muted">{{ __('Create a local account with a role ceiling and optional global permission restrictions.') }}</p>
    </div>
    <a href="{{ route('admin.users.index') }}">{{ __('Back to users') }}</a>
</div>

<section class="panel panel-wide">
    <form class="form-stack" method="post" action="{{ route('admin.users.store') }}">
        @csrf

        <div class="form-grid">
            <div class="field">
                <label for="name">{{ __('Name') }}</label>
                <input id="name" name="name" type="text" maxlength="255" required value="{{ old('name') }}">
                @error('name')<p class="field-error">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="email">{{ __('Email') }}</label>
                <input id="email" name="email" type="email" maxlength="254" required autocomplete="off" value="{{ old('email') }}">
                @error('email')<p class="field-error">{{ $message }}</p>@enderror
            </div>
        </div>

        <div class="form-grid">
            <div class="field">
                <label for="password">{{ __('Password') }}</label>
                <input id="password" name="password" type="password" maxlength="255" required autocomplete="new-password">
                @error('password')<p class="field-error">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="password_confirmation">{{ __('Confirm password') }}</label>
                <input id="password_confirmation" name="password_confirmation" type="password" maxlength="255" required autocomplete="new-password">
            </div>
        </div>

        <div class="form-grid">
            <div class="field">
                <label for="role">{{ __('Role') }}</label>
                <select id="role" name="role" required>
                    @foreach ($roles as $role)
                        <option value="{{ $role->value }}" @selected(old('role', 'operator') === $role->value)>{{ \Illuminate\Support\Str::headline($role->value) }}</option>
                    @endforeach
                </select>
            </div>
            <div class="field">
                <label for="site_scope_mode">{{ __('Site scope') }}</label>
                <select id="site_scope_mode" name="site_scope_mode" required>
                    @foreach ($siteScopeModes as $mode)
                        <option value="{{ $mode->value }}" @selected(old('site_scope_mode', 'selected') === $mode->value)>{{ $mode->title() }}</option>
                    @endforeach
                </select>
                <p class="field-help">{{ __('Selected can receive sites through direct allow rules or assigned site groups. Owners are always all-sites.') }}</p>
            </div>
        </div>

        <input type="hidden" name="access_enabled" value="0">
        <label class="checkbox-option">
            <input type="checkbox" name="access_enabled" value="1" @checked((bool) old('access_enabled', true))>
            <span>{{ __('Access enabled') }}</span>
        </label>

        <fieldset class="permission-fieldset">
            <legend>{{ __('Global permission restrictions') }}</legend>
            <p class="field-help">{{ __('Checked permissions are denied. The scope badge describes what the permission acts on; checking a Site-scoped permission here denies it on every site in the user's effective scope. Restrictions never add authority beyond the selected role.') }}</p>
            <div class="checkbox-grid">
                @foreach ($permissions as $permission)
                    @include('admin.partials.permission-option', [
                        'permission' => $permission,
                        'checked' => in_array($permission->value, old('denied_permissions', []), true),
                    ])
                @endforeach
            </div>
        </fieldset>

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            <p class="field-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
            @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Create user') }}</button>
    </form>
</section>
@endsection
