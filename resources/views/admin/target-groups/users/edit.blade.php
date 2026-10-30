@extends('admin.layout')

@section('title', __('Edit group user assignment'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target group assignment') }}</div>
        <h1>{{ $managedUser->name }}</h1>
        <p class="muted reading-width">{{ $targetGroup->name }} · {{ $managedUser->email }}</p>
    </div>
    <a href="{{ route('admin.target-groups.users.index', ['targetGroup' => $targetGroup->id]) }}">{{ __('Back to group users') }}</a>
</div>

@include('admin.access-batches.context-nav', ['context' => 'group-users', 'subject' => ['id' => (string) $targetGroup->getKey()]])

<section class="panel panel-wide">
    @if ($isOwner)
        <div class="alert alert-success" role="status">{{ __('Owners remain unrestricted for recovery and cannot be assigned to a narrowing target group.') }}</div>
    @else
        <form class="form-stack" method="post" action="{{ route('admin.target-groups.users.update', ['targetGroup' => $targetGroup->id, 'user' => $managedUser->id]) }}">
            @csrf
            @method('PUT')
            <input type="hidden" name="assigned" value="0">
            <label class="checkbox-option">
                <input id="assigned" type="checkbox" name="assigned" value="1" @checked((bool) old('assigned', $assigned)) @error('assigned') aria-invalid="true" aria-describedby="assigned-error" @enderror>
                <span>{{ __('Assign this user to the group') }}</span>
            </label>
            @error('assigned')<p class="field-error" id="assigned-error" role="alert">{{ $message }}</p>@enderror
            <p class="field-help">{{ __('The group can add selected-target reachability and can narrow target capabilities, but can never grant a permission missing from the user role or global permission ceiling.') }}</p>
            @if ($sshAccessImpact)
                <label class="checkbox-option" for="confirm_ssh_group_changes">
                    <input type="checkbox" id="confirm_ssh_group_changes" name="confirm_ssh_group_changes" value="1" @error('confirm_ssh_group_changes') aria-invalid="true" aria-describedby="confirm_ssh_group_changes-error" @enderror>
                    <span>{{ __('Confirm SSH membership changes. Adding a user may enable already-approved SSH capabilities on this group’s Targets; removing a user may lift a group SSH denial if another group still supplies reachability.') }}</span>
                </label>
                @error('confirm_ssh_group_changes')<p class="field-error" id="confirm_ssh_group_changes-error" role="alert">{{ $message }}</p>@enderror
            @endif

            <div class="field">
                <label for="current_password">{{ __('Your current password') }}</label>
                <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" aria-describedby="current_password-error" @enderror>
                @error('current_password')<p class="field-error" id="current_password-error" role="alert">{{ $message }}</p>@enderror
            </div>
            <button class="button button-primary" type="submit">{{ __('Save assignment') }}</button>
        </form>
    @endif
</section>
@endsection
