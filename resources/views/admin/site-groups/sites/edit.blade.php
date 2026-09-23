@extends('admin.layout')

@section('title', __('Edit group site membership'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Site group membership') }}</div>
        <h1>{{ $site->display_name }}</h1>
        <p class="muted">{{ $siteGroup->name }} · <code>{{ $site->site_id }}</code></p>
    </div>
    <a href="{{ route('admin.site-groups.sites.index', ['siteGroup' => $siteGroup->id]) }}">{{ __('Back to group sites') }}</a>
</div>

<section class="panel panel-wide">
    <form class="form-stack" method="post" action="{{ route('admin.site-groups.sites.update', ['siteGroup' => $siteGroup->id, 'site' => $site->site_id]) }}">
        @csrf
        @method('PUT')
        <input type="hidden" name="assigned" value="0">
        <label class="checkbox-option">
            <input type="checkbox" name="assigned" value="1" @checked((bool) old('assigned', $assigned))>
            <span>{{ __('Include this site in the group') }}</span>
        </label>
        <p class="field-help">{{ __('For selected-scope users, group membership can make this site reachable. A direct site deny still blocks it.') }}</p>

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <button class="button button-primary" type="submit">{{ __('Save membership') }}</button>
    </form>
</section>
@endsection
