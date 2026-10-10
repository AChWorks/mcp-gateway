@extends('admin.layout')

@section('title', __('Edit group target membership'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target group membership') }}</div>
        <h1>{{ $target->display_name }}</h1>
        <p class="muted">{{ $targetGroup->name }} · <code>{{ $target->target_id }}</code></p>
    </div>
    <a href="{{ route('admin.target-groups.targets.index', ['targetGroup' => $targetGroup->id]) }}">{{ __('Back to group targets') }}</a>
</div>

<section class="panel panel-wide">
    <form class="form-stack" method="post" action="{{ route('admin.target-groups.targets.update', ['targetGroup' => $targetGroup->id, 'target' => $target->target_id]) }}">
        @csrf
        @method('PUT')
        <input type="hidden" name="assigned" value="0">
        <label class="checkbox-option">
            <input type="checkbox" name="assigned" value="1" @checked((bool) old('assigned', $assigned))>
            <span>{{ __('Include this target in the group') }}</span>
        </label>
        <p class="field-help">{{ __('For selected-scope users, group membership can make this target reachable. A direct target deny still blocks it.') }}</p>

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password">
            @error('current_password')<p class="field-error">{{ $message }}</p>@enderror
        </div>
        <button class="button button-primary" type="submit">{{ __('Save membership') }}</button>
    </form>
</section>
@endsection
