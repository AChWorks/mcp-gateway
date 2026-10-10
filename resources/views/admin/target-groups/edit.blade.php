@extends('admin.layout')

@section('title', __('Edit target group'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target group') }}</div>
        <h1>{{ $targetGroup->name }}</h1>
        <p class="muted">{{ __('Group membership broadens selected-target reachability only within the existing role/global ceiling; every configured denial narrows it.') }}</p>
    </div>
    <a href="{{ route('admin.target-groups.index') }}">{{ __('Back to target groups') }}</a>
</div>

<div class="content-grid">
    <section class="panel panel-wide">
        <form class="form-stack" method="post" action="{{ route('admin.target-groups.update', ['targetGroup' => $targetGroup->id]) }}">
            @csrf
            @method('PUT')

            <div class="field">
                <label for="name">{{ __('Group name') }}</label>
                <input id="name" name="name" type="text" maxlength="160" required value="{{ old('name', $targetGroup->name) }}">
                @error('name')<p class="field-error">{{ $message }}</p>@enderror
            </div>

            <fieldset class="permission-fieldset">
                <legend>{{ __('Group capability restrictions') }}</legend>
                <p class="field-help">{{ __('Denials from overlapping assigned groups accumulate. Direct target permission denials remain the final capability-narrowing layer.') }}</p>
                @php($selectedDenials = old('denied_permissions', $deniedPermissions))
                @include('admin.partials.permission-groups', [
                    'permissions' => $targetPermissions,
                    'selectedDenials' => $selectedDenials,
                ])
            </fieldset>

            <div class="field">
                <label for="current_password">{{ __('Your current password') }}</label>
                <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
                @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
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
        <p>{{ __('Deleting this group removes only its group memberships and group denials. Users, targets, and direct per-target rules remain intact.') }}</p>
        <form class="form-stack" method="post" action="{{ route('admin.target-groups.destroy', ['targetGroup' => $targetGroup->id]) }}">
            @csrf
            @method('DELETE')
            <div class="field">
                <label for="delete_current_password">{{ __('Your current password') }}</label>
                <input id="delete_current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            </div>
            <button class="button button-danger" type="submit">{{ __('Delete target group') }}</button>
        </form>
    </section>
</div>
@endsection
