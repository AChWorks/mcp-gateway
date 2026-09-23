@extends('admin.layout')

@section('title', __('Edit group user assignment'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Site group assignment') }}</div>
        <h1>{{ $managedUser->name }}</h1>
        <p class="muted">{{ $siteGroup->name }} · {{ $managedUser->email }}</p>
    </div>
    <a href="{{ route('admin.site-groups.users.index', ['siteGroup' => $siteGroup->id]) }}">{{ __('Back to group users') }}</a>
</div>

<section class="panel panel-wide">
    @if ($isOwner)
        <div class="alert alert-success" role="status">{{ __('Owners remain unrestricted for recovery and cannot be assigned to a narrowing site group.') }}</div>
    @else
        <form class="form-stack" method="post" action="{{ route('admin.site-groups.users.update', ['siteGroup' => $siteGroup->id, 'user' => $managedUser->id]) }}">
            @csrf
            @method('PUT')
            <input type="hidden" name="assigned" value="0">
            <label class="checkbox-option">
                <input type="checkbox" name="assigned" value="1" @checked((bool) old('assigned', $assigned))>
                <span>{{ __('Assign this user to the group') }}</span>
            </label>
            <p class="field-help">{{ __('The group can add selected-site reachability and can narrow site capabilities, but can never grant a permission missing from the user role or global permission ceiling.') }}</p>
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
