@extends('admin.layout')

@section('title', __('Edit Target'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target administration') }}</div>
        <h1>{{ __('Edit Target') }}</h1>
        <p class="muted">{{ __('Keep the stable Target ID, connector, group assignments and existing access rules. Updating connection settings may require new authentication.') }}</p>
    </div>
    <a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Back to Target') }}</a>
</div>

<section class="panel panel-wide target-enrollment" aria-label="{{ __('Target identity') }}">
    <h2>{{ __('Display and identity') }}</h2>
    <form method="post" action="{{ route('admin.targets.update', ['target' => $target->target_id]) }}" class="form-stack">
        @csrf
        @method('PUT')
        <div class="field">
            <label for="target_id">{{ __('Stable Target ID') }}</label>
            <input id="target_id" type="text" value="{{ $target->target_id }}" readonly aria-readonly="true" aria-describedby="target_id-help">
            <p class="field-help" id="target_id-help">{{ __('Target ID and connector type do not change. Existing users, groups and client references keep pointing at this Target.') }}</p>
        </div>
        <div class="field">
            <label for="display_name">{{ __('Display name') }}</label>
            <input id="display_name" name="display_name" type="text" required maxlength="160"
                value="{{ old('display_name', $target->display_name) }}" @error('display_name') aria-invalid="true" aria-describedby="display_name-error" @enderror>
            @error('display_name')<p class="form-error" role="alert" id="display_name-error">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="ai_guidance">{{ __('AI guidance (optional)') }}</label>
            <textarea id="ai_guidance" name="ai_guidance" rows="3"
                maxlength="{{ \App\Domain\Targets\Target::AI_GUIDANCE_MAX_LENGTH }}" autocomplete="off"
                placeholder="{{ __('Example: This is a production server. Explain risks and ask before making changes.') }}" @error('ai_guidance') aria-invalid="true" @enderror aria-describedby="ai_guidance_help{{ $errors->has('ai_guidance') ? ' ai_guidance-error' : '' }}">{{ old('ai_guidance', $target->ai_guidance) }}</textarea>
            <p id="ai_guidance_help" class="field-help">{{ __('Shown to authorized AI clients as Target-specific context. This is advice, not enforced approval. Never include credentials or secrets.') }}</p>
            @error('ai_guidance')<p class="field-error" role="alert" id="ai_guidance-error">{{ $message }}</p>@enderror
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Save Target details') }}</button>
        </div>
    </form>
</section>

@can('security.manage')
@if (! empty($configurationRevision))
    <section class="panel panel-wide target-enrollment" aria-label="{{ __('Connector settings') }}">
        <h2>{{ __('Connection settings') }}</h2>
        <p class="field-help">{{ __('Only Owners can rotate connector endpoints and encrypted credentials. Changes are audited and require the current Owner password. Existing Target access permissions remain unchanged.') }}</p>

        @if ($connectorUi?->configurationView !== null)
            @include($connectorUi->configurationView)
        @endif
    </section>
@else
    <p class="muted">{{ __('This historical connector does not offer a configuration editor while its adapter is paused.') }}</p>
@endif
@endcan
@endsection
