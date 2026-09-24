@extends('admin.layout')

@section('title', __('Edit site group'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Site group') }}</div>
        <h1>{{ $siteGroup->name }}</h1>
        <p class="muted">{{ __('Group membership broadens selected-site reachability only within the existing role/global ceiling; every configured denial narrows it.') }}</p>
    </div>
    <a href="{{ route('admin.site-groups.index') }}">{{ __('Back to site groups') }}</a>
</div>

<div class="content-grid">
    <section class="panel panel-wide">
        <form class="form-stack" method="post" action="{{ route('admin.site-groups.update', ['siteGroup' => $siteGroup->id]) }}">
            @csrf
            @method('PUT')

            <div class="field">
                <label for="name">{{ __('Group name') }}</label>
                <input id="name" name="name" type="text" maxlength="160" required value="{{ old('name', $siteGroup->name) }}">
                @error('name')<p class="field-error">{{ $message }}</p>@enderror
            </div>

            <fieldset class="permission-fieldset">
                <legend>{{ __('Group capability restrictions') }}</legend>
                <p class="field-help">{{ __('Denials from overlapping assigned groups accumulate. Direct site permission denials remain the final capability-narrowing layer.') }}</p>
                @php($selectedDenials = old('denied_permissions', $deniedPermissions))
                <div class="checkbox-grid">
                    @foreach ($sitePermissions as $permission)
                        @include('admin.partials.permission-option', [
                            'permission' => $permission,
                            'checked' => in_array($permission->value, $selectedDenials, true),
                        ])
                    @endforeach
                </div>
            </fieldset>

            <div class="field">
                <label for="current_password">{{ __('Your current password') }}</label>
                <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
                @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
            </div>

            <div class="action-row">
                <button class="button button-primary" type="submit">{{ __('Save site group') }}</button>
                <a class="button button-secondary" href="{{ route('admin.site-groups.sites.index', ['siteGroup' => $siteGroup->id]) }}">{{ __('Manage sites') }}</a>
                <a class="button button-secondary" href="{{ route('admin.site-groups.users.index', ['siteGroup' => $siteGroup->id]) }}">{{ __('Manage users') }}</a>
            </div>
        </form>
    </section>

    <section class="panel panel-danger" aria-labelledby="delete-site-group-title">
        <div class="eyebrow">{{ __('Danger zone') }}</div>
        <h2 id="delete-site-group-title">{{ __('Delete site group') }}</h2>
        <p>{{ __('Deleting this group removes only its group memberships and group denials. Users, sites, and direct per-site rules remain intact.') }}</p>
        <form class="form-stack" method="post" action="{{ route('admin.site-groups.destroy', ['siteGroup' => $siteGroup->id]) }}">
            @csrf
            @method('DELETE')
            <div class="field">
                <label for="delete_current_password">{{ __('Your current password') }}</label>
                <input id="delete_current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            </div>
            <button class="button button-danger" type="submit">{{ __('Delete site group') }}</button>
        </form>
    </section>
</div>
@endsection
