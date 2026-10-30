@extends('admin.layout')

@section('title', __('Edit target access'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target-specific restriction') }}</div>
        <h1>{{ $target->display_name }}</h1>
        <p class="muted reading-width">{{ $managedUser->name }} · <code dir="ltr">{{ $target->target_id }}</code> · {{ __('Connector') }}: {{ $target->connector_type === 'wp_ai_bridge' ? __('WordPress') : $target->connector_type }}</p>
    </div>
    <a href="{{ route('admin.users.targets.index', ['user' => $managedUser->id]) }}">{{ __('Back to target access') }}</a>
</div>

<section class="panel panel-wide">
    @if ($isOwner)
        <div class="alert alert-success" role="status">{{ __('Owners always retain unrestricted target access for recovery. Change the role first if this account should accept restrictions.') }}</div>
    @else
        <form class="form-stack" method="post" action="{{ route('admin.users.targets.update', ['user' => $managedUser->id, 'target' => $target->target_id]) }}">
            @csrf
            @method('PUT')
            @php
                // Never stamp flashed authorization selections from an old form
                // with a fresh DB revision after an unrelated validation error.
                $submittedTargetRevision = old('target_revision');
                $reuseSubmittedTargetAcl = is_string($submittedTargetRevision)
                    && hash_equals($targetRevision, $submittedTargetRevision)
                    && ! $errors->has('target_revision');
                $staleTargetForm = (session()->hasOldInput('target_revision') || session()->hasOldInput('access_rule'))
                    && ! $reuseSubmittedTargetAcl;
                $selectedAccessRule = $reuseSubmittedTargetAcl
                    ? old('access_rule', $targetRule['access_rule']) : $targetRule['access_rule'];
                $selectedDenials = $reuseSubmittedTargetAcl
                    ? old('denied_permissions', []) : $targetRule['denied_permissions'];
            @endphp
            <input type="hidden" name="target_revision" value="{{ $targetRevision }}">
            @if ($staleTargetForm)
                <div class="alert alert-error" role="alert">{{ __('Target access changed since you opened this form or its revision is missing. Current saved restrictions are displayed. Review them and confirm SSH changes again.') }}</div>
            @endif
            @error('target_revision')<div class="alert alert-error" role="alert">{{ $message }}</div>@enderror

            <div class="field">
                <label for="access_rule">{{ __('Explicit scope rule') }}</label>
                <select id="access_rule" name="access_rule" required @error('access_rule') aria-invalid="true" @enderror aria-describedby="access_rule-help{{ $errors->has('access_rule') ? ' access_rule-error' : '' }}">
                    @foreach (['inherit', 'allow', 'deny'] as $rule)
                        <option value="{{ $rule }}" @selected($selectedAccessRule === $rule)>{{ \Illuminate\Support\Str::headline($rule) }}</option>
                    @endforeach
                </select>
                <p class="field-help" id="access_rule-help">{{ __('Inherit follows the user scope and assigned groups. Allow adds this Target to the selected scope; deny blocks this Target. Role, global and group capability restrictions still apply.') }}</p>
                @error('access_rule')<p class="field-error" id="access_rule-error" role="alert">{{ $message }}</p>@enderror
            </div>

            <fieldset class="permission-fieldset">
                <legend>{{ __('Capability restrictions on this target') }}</legend>
                <p class="field-help">{{ __('Only this Target’s connector capabilities are shown. Checked permissions deny operations on this Target; role ceilings and global/group restrictions still apply.') }}</p>
                @include('admin.partials.permission-groups', [
                    'permissions' => $targetPermissions,
                    'selectedDenials' => $selectedDenials,
                    'connectorType' => $target->connector_type,
                    'sshPermissionsEditable' => $target->connector_type === 'ssh_direct',
                    'sshPermissionContext' => 'target',
                ])
            </fieldset>
            @if ($target->connector_type === 'ssh_direct')
                <label class="checkbox-option" for="confirm_ssh_target_changes">
                    <input id="confirm_ssh_target_changes" type="checkbox" name="confirm_ssh_target_changes" value="1"
                        @checked($reuseSubmittedTargetAcl && old('confirm_ssh_target_changes', false)) @error('confirm_ssh_target_changes') aria-invalid="true" aria-describedby="confirm_ssh_target_changes-error" @enderror>
                    <span>{{ __('Owner confirmation: I reviewed this SSH Target scope rule and the command/SFTP deny checkboxes. Allowing the Target or removing an existing denial may enable authorized remote operations.') }}</span>
                </label>
                @error('confirm_ssh_target_changes')<p class="field-error" id="confirm_ssh_target_changes-error" role="alert">{{ $message }}</p>@enderror
            @endif

            <div class="field">
                <label for="current_password">{{ __('Your current password') }}</label>
                <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" @enderror aria-describedby="current_password-help{{ $errors->has('current_password') ? ' current_password-error' : '' }}">
                <p class="field-help" id="current_password-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
                @error('current_password')<p class="field-error" id="current_password-error" role="alert">{{ $message }}</p>@enderror
            </div>

            <button class="button button-primary" type="submit">{{ __('Save target rule') }}</button>
        </form>
    @endif
</section>
@endsection
