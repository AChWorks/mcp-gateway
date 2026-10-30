@extends('admin.layout')

@section('title', __('Edit target group'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target group') }}</div>
        <h1>{{ $targetGroup->name }}</h1>
        <p class="muted reading-width">{{ __('Group membership broadens selected-target reachability only within the existing role/global ceiling; every configured denial narrows it.') }}</p>
    </div>
    <a href="{{ route('admin.target-groups.index') }}">{{ __('Back to target groups') }}</a>
</div>

<div class="content-grid">
    <section class="panel panel-wide">
        <form class="form-stack form-width" method="post" action="{{ route('admin.target-groups.update', ['targetGroup' => $targetGroup->id]) }}">
            @csrf
            @method('PUT')
            @php
                // A password/name validation redirect may flash old denial
                // checkboxes; never pair them with the current DB revision.
                $submittedDenialRevision = old('denial_revision');
                $reuseSubmittedGroupDenials = is_string($submittedDenialRevision)
                    && hash_equals($denialRevision, $submittedDenialRevision)
                    && ! $errors->has('denial_revision');
                $staleGroupForm = (session()->hasOldInput('denial_revision') || session()->hasOldInput('name'))
                    && ! $reuseSubmittedGroupDenials;
                $selectedDenials = $reuseSubmittedGroupDenials
                    ? old('denied_permissions', []) : $deniedPermissions;
            @endphp
            <input type="hidden" name="denial_revision" value="{{ $denialRevision }}">
            @if ($staleGroupForm)
                <p class="alert alert-error" role="alert">{{ __('Group restrictions changed since you opened this form or its revision is missing. Current saved denials are displayed. Review and confirm changes again.') }}</p>
            @endif
            @error('denial_revision')<p class="alert alert-error" role="alert">{{ $message }}</p>@enderror

            <div class="field">
                <label for="name">{{ __('Group name') }}</label>
                <input id="name" name="name" type="text" maxlength="160" required value="{{ old('name', $targetGroup->name) }}" @error('name') aria-invalid="true" aria-describedby="name-error" @enderror>
                @error('name')<p class="field-error" id="name-error" role="alert">{{ $message }}</p>@enderror
            </div>

            <fieldset class="permission-fieldset">
                <legend>{{ __('Group capability restrictions') }}</legend>
                <p class="field-help">{{ __('Denials from overlapping assigned groups accumulate. Direct target permission denials remain the final capability-narrowing layer.') }}</p>
                @include('admin.partials.permission-groups', [
                    'permissions' => $targetPermissions,
                    'selectedDenials' => $selectedDenials,
                    'sshPermissionsEditable' => true,
                    'sshPermissionContext' => 'group',
                ])
            </fieldset>

            <label class="checkbox-option" for="confirm_ssh_group_changes">
                <input type="checkbox" id="confirm_ssh_group_changes" name="confirm_ssh_group_changes" value="1" @error('confirm_ssh_group_changes') aria-invalid="true" aria-describedby="confirm_ssh_group_changes-error" @enderror>
                <span>{{ __('Confirm SSH group permission changes. Groups only DENY access, but removing an existing denial can expand access for authorized users.') }}</span>
            </label>
            @error('confirm_ssh_group_changes')<p class="field-error" id="confirm_ssh_group_changes-error" role="alert">{{ $message }}</p>@enderror
            <div class="field">
                <label for="current_password">{{ __('Your current password') }}</label>
                <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" aria-describedby="current_password-error" @enderror>
                @error('current_password')<p class="field-error" id="current_password-error" role="alert">{{ $message }}</p>@enderror
            </div>

            <div class="action-row">
                <button class="button button-primary" type="submit">{{ __('Save target group') }}</button>
                <a class="button button-secondary" href="{{ route('admin.target-groups.targets.index', ['targetGroup' => $targetGroup->id]) }}">{{ __('Manage targets') }}</a>
                <a class="button button-secondary" href="{{ route('admin.target-groups.users.index', ['targetGroup' => $targetGroup->id]) }}">{{ __('Manage users') }}</a>
            </div>
        </form>
    </section>

    <section class="panel panel-danger" aria-labelledby="delete-target-group-title">
        <div class="eyebrow">{{ __('Danger zone') }}</div>
        <h2 id="delete-target-group-title">{{ __('Delete target group') }}</h2>
        <p>{{ __('Deleting this group removes only its group memberships and group denials. Users, targets, and direct per-target rules remain intact. Removing SSH group denials can restore previously authorized SSH commands and file access through other memberships.') }}</p>
        <form class="form-stack form-width" method="post" action="{{ route('admin.target-groups.destroy', ['targetGroup' => $targetGroup->id]) }}">
            @csrf
            @method('DELETE')
            <label class="checkbox-option" for="confirm_ssh_group_delete">
                <input type="checkbox" id="confirm_ssh_group_delete" name="confirm_ssh_group_changes" value="1" @error('confirm_ssh_group_changes') aria-invalid="true" aria-describedby="confirm_ssh_group_delete-error" @enderror>
                <span>{{ __('I confirm that deleting this group may remove SSH Target reachability or lift SSH denials for other already-authorized memberships.') }}</span>
            </label>
            @error('confirm_ssh_group_changes')<p class="field-error" id="confirm_ssh_group_delete-error" role="alert">{{ $message }}</p>@enderror
            <div class="field">
                <label for="delete_current_password">{{ __('Your current password') }}</label>
                <input id="delete_current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" aria-describedby="delete_current_password-error" @enderror>
                @error('current_password')<p class="field-error" id="delete_current_password-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <button class="button button-danger" type="submit">{{ __('Delete target group') }}</button>
        </form>
    </section>
</div>
@endsection
