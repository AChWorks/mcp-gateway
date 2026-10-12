@extends('admin.layout')

@section('title', __('Edit group user assignment'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target group assignment') }}</div>
        <h1>{{ $managedUser->name }}</h1>
        <p class="muted">{{ $targetGroup->name }} · {{ $managedUser->email }}</p>
    </div>
    <a href="{{ route('admin.target-groups.users.index', ['targetGroup' => $targetGroup->id]) }}">{{ __('Back to group users') }}</a>
</div>

<section class="panel panel-wide">
    @if ($isOwner)
        <div class="alert alert-success" role="status">{{ __('Owners remain unrestricted for recovery and cannot be assigned to a narrowing target group.') }}</div>
    @else
        <form class="form-stack" method="post" action="{{ route('admin.target-groups.users.update', ['targetGroup' => $targetGroup->id, 'user' => $managedUser->id]) }}">
            @csrf
            @method('PUT')
            <input type="hidden" name="assigned" value="0">
            <label class="checkbox-option">
                <input type="checkbox" name="assigned" value="1" @checked((bool) old('assigned', $assigned))>
                <span>{{ __('Assign this user to the group') }}</span>
            </label>
            <p class="field-help">{{ __('The group can add selected-target reachability and can narrow target capabilities, but can never grant a permission missing from the user role or global permission ceiling.') }}</p>
            <label class="checkbox-option" for="confirm_ssh_group_changes">
                <input type="checkbox" id="confirm_ssh_group_changes" name="confirm_ssh_group_changes" value="1">
                <span>{{ __('Confirm SSH membership changes. Adding a user may enable already-approved SSH capabilities on this group’s Targets; removing a user may lift a group SSH denial if another group still supplies reachability.') }}</span>
            </label>
            @error('confirm_ssh_group_changes')<p class="form-error" role="alert">{{ $message }}</p>@enderror
            @error('assigned')<p class="field-error">{{ $message }}</p>@enderror

            <div class="field">
                <label for="current_password">{{ __('Your current password') }}</label>
                <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
                @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
            </div>
            <button class="button button-primary" type="submit">{{ __('Save assignment') }}</button>
        </form>
    @endif
</section>
@endsection
