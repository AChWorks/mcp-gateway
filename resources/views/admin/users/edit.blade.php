@extends('admin.layout')

@section('title', __('Manage user'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ $managedUser->name }}</h1>
        <p class="muted reading-width">{{ $managedUser->email }}</p>
    </div>
    <div class="action-row">
        <a class="button button-secondary" href="{{ route('admin.users.targets.index', ['user' => $managedUser->id]) }}">{{ __('Target access') }}</a>
        @can('security.manage')
            @if (in_array($managedUser->role, [\App\Domain\Access\GatewayRole::Administrator, \App\Domain\Access\GatewayRole::Operator], true))
                <a class="button button-secondary" href="{{ route('admin.users.publishing.index', ['user' => $managedUser->id]) }}">{{ __('Publishing grants') }}</a>
            @endif
        @endcan
        <a href="{{ route('admin.users.index') }}">{{ __('Back to users') }}</a>
    </div>
</div>

<section class="panel panel-wide">
    @if ($managedUser->role->value === 'owner')
        <div class="alert alert-success" role="status">{{ __('Owners retain unrestricted all-target authority for recovery. Global/per-target denials and target-group assignments are cleared for this role.') }}</div>
    @endif

    <form class="form-stack form-width" method="post" action="{{ route('admin.users.update', ['user' => $managedUser->id]) }}">
        @csrf
        @method('PUT')

        <div class="form-grid">
            <div class="field">
                <label for="name">{{ __('Name') }}</label>
                <input id="name" name="name" type="text" maxlength="255" required value="{{ old('name', $managedUser->name) }}" @error('name') aria-invalid="true" aria-describedby="name-error" @enderror>
                @error('name')<p class="field-error" id="name-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="email">{{ __('Email') }}</label>
                <input id="email" name="email" type="email" maxlength="254" required autocomplete="off" value="{{ old('email', $managedUser->email) }}" @error('email') aria-invalid="true" aria-describedby="email-error" @enderror>
                @error('email')<p class="field-error" id="email-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>

        <div class="form-grid">
            <div class="field">
                <label for="role">{{ __('Role') }}</label>
                <select id="role" name="role" required @error('role') aria-invalid="true" @enderror aria-describedby="role-help{{ $errors->has('role') ? ' role-error' : '' }}">
                    @foreach ($roles as $role)
                        <option value="{{ $role->value }}" @selected(old('role', $managedUser->role->value) === $role->value)>{{ \Illuminate\Support\Str::headline($role->value) }}</option>
                    @endforeach
                </select>
                <p class="field-help" id="role-help">{{ __('Owner bypasses all restrictions. Administrator and Operator SSH grants require Selected Target scope and Owner confirmation; Viewer does not have remote shell/SFTP permissions.') }}</p>
                @error('role')<p class="field-error" id="role-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="target_scope_mode">{{ __('Target scope') }}</label>
                <select id="target_scope_mode" name="target_scope_mode" required @error('target_scope_mode') aria-invalid="true" @enderror aria-describedby="target_scope_mode-help{{ $errors->has('target_scope_mode') ? ' target_scope_mode-error' : '' }}">
                    @foreach ($targetScopeModes as $mode)
                        <option value="{{ $mode->value }}" @selected(old('target_scope_mode', $managedUser->target_scope_mode->value) === $mode->value)>{{ $mode->title() }}</option>
                    @endforeach
                </select>
                <p class="field-help" id="target_scope_mode-help">{{ __('Target scope controls which Targets this user may reach, not the connector type or granted capabilities. All targets includes the fleet except direct denies; Selected uses direct allows and assigned groups. Owners always reach all Targets.') }}</p>
                @error('target_scope_mode')<p class="field-error" id="target_scope_mode-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>

        <input type="hidden" name="access_enabled" value="0">
        <label class="checkbox-option">
            <input id="access_enabled" type="checkbox" name="access_enabled" value="1" @checked((bool) old('access_enabled', $managedUser->access_enabled)) @error('access_enabled') aria-invalid="true" aria-describedby="access_enabled-error" @enderror>
            <span>{{ __('Access enabled') }}</span>
        </label>
        @error('access_enabled')<p class="field-error" id="access_enabled-error" role="alert">{{ $message }}</p>@enderror

        <fieldset class="permission-fieldset">
            <legend>{{ __('AI / MCP connection') }}</legend>
            <input type="hidden" name="ai_access_enabled" value="0">
            <label class="checkbox-option" for="ai_access_enabled">
                <input id="ai_access_enabled" type="checkbox" name="ai_access_enabled" value="1" @checked((bool) old('ai_access_enabled', $managedUser->ai_access_enabled)) @error('ai_access_enabled') aria-invalid="true" aria-describedby="ai_access_enabled-error" @enderror>
                <span>{{ __('Allow this account to authorize and use AI/MCP clients') }}</span>
            </label>
            @error('ai_access_enabled')<p class="field-error" id="ai_access_enabled-error" role="alert">{{ $message }}</p>@enderror
            <p class="field-help">{{ __('This Gateway-wide connection gate is independent of the account role and human Admin/Target permissions. It never adds a Target or action permission. Disabling revokes existing AI client consents/tokens; re-enabling requires fresh client authorization. New users start with AI access disabled; existing users retain their prior state after upgrade.') }}</p>
        </fieldset>

        <fieldset class="permission-fieldset">
            <legend>{{ __('Permission restrictions (deny only)') }}</legend>
            <p class="field-help">{{ __('Checked permissions are denied beneath the role ceiling. Target-scoped denials apply across every Target in the user\'s scope. SSH can be authorized only on Selected Targets with explicit Owner confirmation. Owner restrictions are intentionally ignored and cleared.') }}</p>
            <input type="hidden" name="ssh_permissions_reviewed" value="1">
            @php($selectedDenials = old('denied_permissions', $deniedPermissions))
            @include('admin.partials.permission-groups', [
                'permissions' => $permissions,
                'selectedDenials' => $selectedDenials,
                'sshPermissionsEditable' => $sshPermissionsEditable,
                'sshPermissionContext' => 'user',
            ])
        </fieldset>

        @if ($sshPermissionsEditable && $managedUser->role->value !== 'owner')
            <label class="checkbox-option" for="confirm_ssh_permission_changes">
                <input id="confirm_ssh_permission_changes" type="checkbox" name="confirm_ssh_permission_changes" value="1" @checked(old('confirm_ssh_permission_changes', false)) @error('confirm_ssh_permission_changes') aria-invalid="true" aria-describedby="confirm_ssh_permission_changes-error" @enderror>
                <span>{{ __('Owner confirmation: explicitly apply each SSH command, SFTP read and SFTP write permission above. Unchecked denial boxes grant that capability only on approved Selected Targets. SSH command access can read/write files and use permitted sudo/root regardless of the SFTP switches.') }}</span>
            </label>
            @error('confirm_ssh_permission_changes')<p class="field-error" id="confirm_ssh_permission_changes-error" role="alert">{{ $message }}</p>@enderror
        @endif

        <div class="form-grid">
            <div class="field">
                <label for="password">{{ __('New password') }}</label>
                <input id="password" name="password" type="password" maxlength="255" autocomplete="new-password" @error('password') aria-invalid="true" @enderror aria-describedby="password-help{{ $errors->has('password') ? ' password-error' : '' }}">
                <p class="field-help" id="password-help">{{ __('Leave blank to keep the current password.') }}</p>
                @error('password')<p class="field-error" id="password-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <div class="field">
                <label for="password_confirmation">{{ __('Confirm new password') }}</label>
                <input id="password_confirmation" name="password_confirmation" type="password" maxlength="255" autocomplete="new-password" @error('password_confirmation') aria-invalid="true" aria-describedby="password_confirmation-error" @enderror>
                @error('password_confirmation')<p class="field-error" id="password_confirmation-error" role="alert">{{ $message }}</p>@enderror
            </div>
        </div>

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" @enderror aria-describedby="current_password-help{{ $errors->has('current_password') ? ' current_password-error' : '' }}">
            <p class="field-help" id="current_password-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
            @error('current_password')<p class="field-error" id="current_password-error" role="alert">{{ $message }}</p>@enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Save user access') }}</button>
    </form>
</section>
@endsection
