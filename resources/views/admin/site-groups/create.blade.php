@extends('admin.layout')

@section('title', __('Add site group'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Add site group') }}</h1>
        <p class="muted">{{ __('Create a reusable site membership layer with optional denial-only capability restrictions.') }}</p>
    </div>
    <a href="{{ route('admin.site-groups.index') }}">{{ __('Back to site groups') }}</a>
</div>

<section class="panel panel-wide">
    <form class="form-stack" method="post" action="{{ route('admin.site-groups.store') }}">
        @csrf

        <div class="field">
            <label for="name">{{ __('Group name') }}</label>
            <input id="name" name="name" type="text" maxlength="160" required value="{{ old('name') }}">
            @error('name')<p class="field-error">{{ $message }}</p>@enderror
        </div>

        <fieldset class="permission-fieldset">
            <legend>{{ __('Group capability restrictions') }}</legend>
            <p class="field-help">{{ __('Checked site-scoped capabilities are denied on every site in this group for assigned users. A group can never grant authority above the user role/global ceiling.') }}</p>
            <div class="checkbox-grid">
                @foreach ($sitePermissions as $permission)
                    @include('admin.partials.permission-option', [
                        'permission' => $permission,
                        'checked' => in_array($permission->value, old('denied_permissions', []), true),
                    ])
                @endforeach
            </div>
        </fieldset>

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            <p class="field-help">{{ __('Required to confirm this security-sensitive change.') }}</p>
            @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
        </div>

        <button class="button button-primary" type="submit">{{ __('Create site group') }}</button>
    </form>
</section>
@endsection
