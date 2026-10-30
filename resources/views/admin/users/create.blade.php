@extends('admin.layout')

@section('title', __('Add user'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Add local user') }}</h1>
        <p class="muted reading-width">{{ __('Create a local account with a role ceiling and optional global permission restrictions.') }}</p>
    </div>
    <a href="{{ route('admin.users.index') }}">{{ __('Back to users') }}</a>
</div>

<section class="panel panel-wide">
    <form class="form-stack form-width" method="post" action="{{ route('admin.users.store') }}">
        @csrf

        <div class="form-grid">
            <div class="field">
                <label for="name">{{ __('Name') }}</label>
                <input id="name" name="name" type="text" maxlength="255" required value="{{ old('name') }}" @error('name') aria-invalid="true" aria-describedby="name-error" @enderror>
                @error('name')<p class="field-error" id="name-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="email">{{ __('Email') }}</label>
                <input id="email" name="email" type="email" maxlength="254" required autocomplete="off" value="{{ old('email') }}" @error('email') aria-invalid="true" aria-describedby="email-error" @enderror>
                @error('email')<p class="field-error" id="email-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>

        <div class="form-grid">
            <div class="field">
                <label for="password">{{ __('Password') }}</label>
                <input id="password" name="password" type="password" maxlength="255" required autocomplete="new-password" @error('password') aria-invalid="true" aria-describedby="password-error" @enderror>
                @error('password')<p class="field-error" id="password-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="password_confirmation">{{ __('Confirm password') }}</label>
                <input id="password_confirmation" name="password_confirmation" type="password" maxlength="255" required autocomplete="new-password" @error('password_confirmation') aria-invalid="true" aria-describedby="password_confirmation-error" @enderror>
                @error('password_confirmation')<p class="field-error" id="password_confirmation-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>

        <div class="form-grid">
            <div class="field">
                <label for="role">{{ __('Role') }}</label>
                <select id="role" name="role" required @error('role') aria-invalid="true" @enderror aria-describedby="role-help{{ $errors->has('role') ? ' role-error' : '' }}">
                    @foreach ($roles as $role)
                        <option value="{{ $role->value }}" @selected(old('role', 'operator') === $role->value)>{{ \Illuminate\Support\Str::headline($role->value) }}</option>
                    @endforeach
                </select>
                <p class="field-help" id="role-help">{{ __('Owner bypasses every permission and Target restriction for recovery. Operator and Administrator can receive SSH only on explicitly Selected Targets; Viewer cannot execute SSH commands or SFTP tools regardless of checkbox state.') }}</p>
                @error('role')<p class="field-error" id="role-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="target_scope_mode">{{ __('Target scope') }}</label>
                <select id="target_scope_mode" name="target_scope_mode" required @error('target_scope_mode') aria-invalid="true" @enderror aria-describedby="target_scope_mode-help{{ $errors->has('target_scope_mode') ? ' target_scope_mode-error' : '' }}">
                    @foreach ($targetScopeModes as $mode)
                        <option value="{{ $mode->value }}" @selected(old('target_scope_mode', 'selected') === $mode->value)>{{ $mode->title() }}</option>
                    @endforeach
                </select>
                <p class="field-help" id="target_scope_mode-help">{{ __('Target scope controls which Targets this user may reach, not the connector type or granted capabilities. Selected uses direct allow rules and Target groups; Owners always reach all Targets.') }}</p>
                @error('target_scope_mode')<p class="field-error" id="target_scope_mode-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>

        <input type="hidden" name="access_enabled" value="0">
        <label class="checkbox-option">
            <input id="access_enabled" type="checkbox" name="access_enabled" value="1" @checked((bool) old('access_enabled', true)) @error('access_enabled') aria-invalid="true" aria-describedby="access_enabled-error" @enderror>
            <span>{{ __('Access enabled') }}</span>
        </label>
        @error('access_enabled')<p class="field-error" id="access_enabled-error" role="alert">{{ $message }}</p>@enderror

        <fieldset class="permission-fieldset">
            <legend>{{ __('AI / MCP connection') }}</legend>
            <input type="hidden" name="ai_access_enabled" value="0">
            <label class="checkbox-option" for="ai_access_enabled">
                <input id="ai_access_enabled" type="checkbox" name="ai_access_enabled" value="1" @checked((bool) old('ai_access_enabled', false)) @error('ai_access_enabled') aria-invalid="true" aria-describedby="ai_access_enabled-error" @enderror>
                <span>{{ __('Allow this account to authorize and use AI/MCP clients') }}</span>
            </label>
            @error('ai_access_enabled')<p class="field-error" id="ai_access_enabled-error" role="alert">{{ $message }}</p>@enderror
            <p class="field-help">{{ __('This Gateway-wide connection gate is independent of the account role and human Admin/Target permissions. It never adds a Target or action permission. Disabling revokes existing AI client consents/tokens; re-enabling requires fresh client authorization. New users start with AI access disabled; existing users retain their prior state after upgrade.') }}</p>
        </fieldset>

        <fieldset class="permission-fieldset">
            <legend>{{ __('Permission restrictions (deny only)') }}</legend>
            <p class="field-help">{{ __('Checked means DENY. New non-owner users start with all SSH tools blocked. Uncheck an SSH denial only to intentionally authorize that tool on explicitly Selected Targets, with Owner confirmation. This does not add Targets to the account; assign Targets or Target Groups after creation.') }}</p>
            <input type="hidden" name="ssh_permissions_reviewed" value="1">
            @include('admin.partials.permission-groups', [
                'permissions' => $permissions,
                'selectedDenials' => old('denied_permissions', $sshDefaultDenials),
                'sshPermissionsEditable' => true,
                'sshPermissionContext' => 'user',
            ])
        </fieldset>
        <label class="checkbox-option" for="confirm_ssh_permission_changes">
            <input id="confirm_ssh_permission_changes" type="checkbox" name="confirm_ssh_permission_changes" value="1"
                @checked(old('confirm_ssh_permission_changes', false)) @error('confirm_ssh_permission_changes') aria-invalid="true" aria-describedby="confirm_ssh_permission_changes-error" @enderror>
            <span>{{ __('Owner confirmation for SSH grants: I reviewed each SSH denial checkbox. Unchecking a denial may enable remote OS commands or file access on an explicitly Selected Target; it does not sandbox remote sudo/root.') }}</span>
        </label>
        @error('confirm_ssh_permission_changes')<p class="field-error" id="confirm_ssh_permission_changes-error" role="alert">{{ $message }}</p>@enderror

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" @enderror aria-describedby="current_password-help{{ $errors->has('current_password') ? ' current_password-error' : '' }}">
            <p class="field-help" id="current_password-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
            @error('current_password')<p class="field-error" id="current_password-error" role="alert">{{ $message }}</p>@enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Create user') }}</button>
    </form>
</section>
@endsection
