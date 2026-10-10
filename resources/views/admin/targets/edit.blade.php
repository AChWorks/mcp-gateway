@extends('admin.layout')

@section('title', __('Edit Target'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target administration') }}</div>
        <h1>{{ __('Edit Target') }}</h1>
        <p class="muted">{{ __('Only the display name can be changed. Target ID and connector endpoint stay immutable to protect authorization and credentials.') }}</p>
    </div>
    <a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Back to Target') }}</a>
</div>

<section class="panel panel-wide" aria-label="{{ __('Target settings') }}">
    <form method="post" action="{{ route('admin.targets.update', ['target' => $target->target_id]) }}" class="form-stack">
        @csrf
        @method('PUT')
        <div class="field">
            <label for="target_id">{{ __('Target ID') }}</label>
            <input id="target_id" type="text" value="{{ $target->target_id }}" readonly aria-readonly="true">
        </div>
        <div class="field">
            <label for="display_name">{{ __('Display name') }}</label>
            <input id="display_name" name="display_name" type="text" required maxlength="160"
                value="{{ old('display_name', $target->display_name) }}" aria-describedby="display_name_help">
            <p id="display_name_help" class="muted">{{ __('Changing this label does not reauthorize or change the remote WordPress endpoint.') }}</p>
            @error('display_name')
                <p class="form-error" role="alert">{{ $message }}</p>
            @enderror
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Save changes') }}</button>
            <a class="button button-secondary" href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Cancel') }}</a>
        </div>
    </form>
</section>
@endsection
