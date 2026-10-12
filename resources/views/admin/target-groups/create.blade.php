@extends('admin.layout')

@section('title', __('Add target group'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Add target group') }}</h1>
        <p class="muted">{{ __('Create a reusable target membership layer with optional denial-only capability restrictions.') }}</p>
    </div>
    <a href="{{ route('admin.target-groups.index') }}">{{ __('Back to target groups') }}</a>
</div>

<section class="panel panel-wide">
    <form class="form-stack" method="post" action="{{ route('admin.target-groups.store') }}">
        @csrf

        <div class="field">
            <label for="name">{{ __('Group name') }}</label>
            <input id="name" name="name" type="text" maxlength="160" required value="{{ old('name') }}">
            @error('name')<p class="field-error">{{ $message }}</p>@enderror
        </div>

        <fieldset class="permission-fieldset">
            <legend>{{ __('Group capability restrictions') }}</legend>
            <p class="field-help">{{ __('Checked permissions are denied on matching Targets for assigned users. Groups can add Target reachability but never grant capabilities beyond the user role or global restrictions.') }}</p>
            @include('admin.partials.permission-groups', [
                'permissions' => $targetPermissions,
                'selectedDenials' => old('denied_permissions', []),
            ])
        </fieldset>

        <label class="checkbox-option" for="confirm_ssh_group_changes">
            <input type="checkbox" id="confirm_ssh_group_changes" name="confirm_ssh_group_changes" value="1">
            <span>{{ __('Confirm SSH group permission changes. Groups only DENY access, but removing an existing denial can expand access for authorized users.') }}</span>
        </label>
        @error('confirm_ssh_group_changes')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            <p class="field-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
            @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Create target group') }}</button>
    </form>
</section>
@endsection
