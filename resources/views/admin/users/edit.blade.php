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
        <a class="button button-secondary" href="{{ route('admin.users.targets.index', ['user' => $managedUser->id]) }}">{{ __('Target access') }}</a>
        <a href="{{ route('admin.users.index') }}">{{ __('Back to users') }}</a>
    </div>
</div>

<section class="panel panel-wide">
    @if ($managedUser->role->value === 'owner')
        <div class="alert alert-success" role="status">{{ __('Owners retain unrestricted all-target authority for recovery. Global/per-target denials and target-group assignments are cleared for this role.') }}</div>
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
                <label for="target_scope_mode">{{ __('Target scope') }}</label>
                <select id="target_scope_mode" name="target_scope_mode" required>
                    @foreach ($targetScopeModes as $mode)
                        <option value="{{ $mode->value }}" @selected(old('target_scope_mode', $managedUser->target_scope_mode->value) === $mode->value)>{{ $mode->title() }}</option>
                    @endforeach
                </select>
                <p class="field-help">{{ __('Target scope controls which Targets this user may reach, not the connector type or granted capabilities. All targets includes the fleet except direct denies; Selected uses direct allows and assigned groups. Owners always reach all Targets.') }}</p>
            </div>
        </div>

        <input type="hidden" name="access_enabled" value="0">
        <label class="checkbox-option">
            <input type="checkbox" name="access_enabled" value="1" @checked((bool) old('access_enabled', $managedUser->access_enabled))>
            <span>{{ __('Access enabled') }}</span>
        </label>
        @error('access_enabled')<p class="field-error">{{ $message }}</p>@enderror

        <fieldset class="permission-fieldset">
            <legend>{{ __('Permission restrictions (deny only)') }}</legend>
            <p class="field-help">{{ __('Checked permissions are denied beneath the role ceiling. The scope badge describes what the permission acts on; a Target-scoped denial here applies across every target in the user\'s effective scope. Owner restrictions are intentionally ignored and cleared.') }}</p>
            @php($selectedDenials = old('denied_permissions', $deniedPermissions))
            @include('admin.partials.permission-groups', [
                'permissions' => $permissions,
                'selectedDenials' => $selectedDenials,
                'sshPermissionsEditable' => $sshPermissionsEditable,
            ])
        </fieldset>

        @if ($sshPermissionsEditable && $managedUser->role->value !== 'owner')
            <label class="checkbox-option" for="confirm_ssh_permission_changes">
                <input id="confirm_ssh_permission_changes" type="checkbox" name="confirm_ssh_permission_changes" value="1" @checked(old('confirm_ssh_permission_changes', false))>
                <span>{{ __('Owner confirmation: explicitly apply each SSH command, SFTP read and SFTP write permission above. Unchecked denial boxes grant that capability only on approved Selected Targets. SSH command access can read/write files and use permitted sudo/root regardless of the SFTP switches.') }}</span>
            </label>
        @endif

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
