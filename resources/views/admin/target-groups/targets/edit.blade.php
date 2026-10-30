@extends('admin.layout')

@section('title', __('Edit group target membership'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target group membership') }}</div>
        <h1>{{ $target->display_name }}</h1>
        <p class="muted reading-width">{{ $targetGroup->name }} · <code dir="ltr">{{ $target->target_id }}</code></p>
    </div>
    <a href="{{ route('admin.target-groups.targets.index', ['targetGroup' => $targetGroup->id]) }}">{{ __('Back to group targets') }}</a>
</div>

@include('admin.access-batches.context-nav', ['context' => 'group-targets', 'subject' => ['id' => (string) $targetGroup->getKey()]])

<section class="panel panel-wide">
    <form class="form-stack" method="post" action="{{ route('admin.target-groups.targets.update', ['targetGroup' => $targetGroup->id, 'target' => $target->target_id]) }}">
        @csrf
        @method('PUT')
        <input type="hidden" name="assigned" value="0">
        <label class="checkbox-option">
            <input id="assigned" type="checkbox" name="assigned" value="1" @checked((bool) old('assigned', $assigned)) @error('assigned') aria-invalid="true" aria-describedby="assigned-error" @enderror>
            <span>{{ __('Include this target in the group') }}</span>
        </label>
        @error('assigned')<p class="field-error" id="assigned-error" role="alert">{{ $message }}</p>@enderror
        <p class="field-help">{{ __('For selected-scope users, group membership can make this target reachable. A direct target deny still blocks it.') }}</p>
        @if ($target->connector_type === 'ssh_direct')
            <label class="checkbox-option" for="confirm_ssh_group_changes">
                <input type="checkbox" id="confirm_ssh_group_changes" name="confirm_ssh_group_changes" value="1" @error('confirm_ssh_group_changes') aria-invalid="true" aria-describedby="confirm_ssh_group_changes-error" @enderror>
                <span>{{ __('Confirm SSH Target group membership changes. Adding this SSH Target may enable an already approved capability; removing it may lift this group’s SSH denials when other Target memberships remain.') }}</span>
            </label>
            @error('confirm_ssh_group_changes')<p class="field-error" id="confirm_ssh_group_changes-error" role="alert">{{ $message }}</p>@enderror
        @endif

        <div class="field">
            <label for="current_password">{{ __('Your current password') }}</label>
            <input id="current_password" name="current_password" type="password" maxlength="255" required autocomplete="current-password" @error('current_password') aria-invalid="true" aria-describedby="current_password-error" @enderror>
            @error('current_password')<p class="field-error" id="current_password-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <button class="button button-primary" type="submit">{{ __('Save membership') }}</button>
    </form>
</section>
@endsection
