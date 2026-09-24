@extends('admin.layout')

@section('title', __('Manage user'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ $managedUser->name }}</h1>
        <p class="muted">{{ $managedUser->email }}</p>
    </div>
    <div class="action-row">
        <a class="button button-secondary" href="{{ route('admin.users.sites.index', ['user' => $managedUser->id]) }}">{{ __('Site access') }}</a>
        <a href="{{ route('admin.users.index') }}">{{ __('Back to users') }}</a>
    </div>
</div>

<section class="panel panel-wide">
    @if ($managedUser->role->value === 'owner')
        <div class="alert alert-success" role="status">{{ __('Owners retain unrestricted all-site authority for recovery. Global/per-site denials and site-group assignments are cleared for this role.') }}</div>
    @endif

    <form class="form-stack" method="post" action="{{ route('admin.users.update', ['user' => $managedUser->id]) }}">
        @csrf
        @method('PUT')

        <div class="form-grid">
            <div class="field">
                <label for="name">{{ __('Name') }}</label>
                <input id="name" name="name" type="text" maxlength="255" required value="{{ old('name', $managedUser->name) }}">
                @error('name')<p class="field-error">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="email">{{ __('Email') }}</label>
                <input id="email" name="email" type="email" maxlength="254" required autocomplete="off" value="{{ old('email', $managedUser->email) }}">
                @error('email')<p class="field-error">{{ $message }}</p>@enderror
            </div>
        </div>

        <div class="form-grid">
            <div class="field">
                <label for="role">{{ __('Role') }}</label>
                <select id="role" name="role" required>
                    @foreach ($roles as $role)
                        <option value="{{ $role->value }}" @selected(old('role', $managedUser->role->value) === $role->value)>{{ \Illuminate\Support\Str::headline($role->value) }}</option>
                    @endforeach
                </select>
            </div>
            <div class="field">
                <label for="site_scope_mode">{{ __('Site scope') }}</label>
                <select id="site_scope_mode" name="site_scope_mode" required>
                    @foreach ($siteScopeModes as $mode)
                        <option value="{{ $mode->value }}" @selected(old('site_scope_mode', $managedUser->site_scope_mode->value) === $mode->value)>{{ $mode->title() }}</option>
                    @endforeach
                </select>
                <p class="field-help">{{ __('All sites reaches the full fleet unless a direct site deny excludes a target. Selected sites reaches only direct allows and assigned groups; direct denies still win. Owners are always all-sites.') }}</p>
            </div>
        </div>

        <input type="hidden" name="access_enabled" value="0">
        <label class="checkbox-option">
            <input type="checkbox" name="access_enabled" value="1" @checked((bool) old('access_enabled', $managedUser->access_enabled))>
            <span>{{ __('Access enabled') }}</span>
        </label>
        @error('access_enabled')<p class="field-error">{{ $message }}</p>@enderror

        <fieldset class="permission-fieldset">
            <legend>{{ __('Global permission restrictions') }}</legend>
            <p class="field-help">{{ __('Checked permissions are denied beneath the role ceiling. The scope badge describes what the permission acts on; a Site-scoped denial here applies across every site in the user's effective scope. Owner restrictions are intentionally ignored and cleared.') }}</p>
            @php($selectedDenials = old('denied_permissions', $deniedPermissions))
            <div class="checkbox-grid">
                @foreach ($permissions as $permission)
                    @include('admin.partials.permission-option', [
                        'permission' => $permission,
                        'checked' => in_array($permission->value, $selectedDenials, true),
                    ])
                @endforeach
            </div>
        </fieldset>

        <div class="form-grid">
            <div class="field">
                <label for="password">{{ __('New password') }}</label>
                <input id="password" name="password" type="password" maxlength="255" autocomplete="new-password">
                <p class="field-help">{{ __('Leave blank to keep the current password.') }}</p>
                @error('password')<p class="field-error">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="password_confirmation">{{ __('Confirm new password') }}</label>
                <input id="password_confirmation" name="password_confirmation" type="password" maxlength="255" autocomplete="new-password">
            </div>
        </div>

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            <p class="field-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
            @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Save user access') }}</button>
    </form>
</section>
@endsection
