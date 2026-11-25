@extends('admin.layout')

@section('title', __('Edit Target'))
@section('form-page', '1')

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target administration') }}</div>
        <h1>{{ __('Edit Target') }}</h1>
        <p class="muted">{{ __('Keep the stable Target ID, connector, group assignments and existing access rules. Updating connection settings may require new authentication.') }}</p>
    </div>
    <a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Back to Target') }}</a>
</div>

@can('targets.update', $target)
<section class="panel panel-wide target-enrollment" aria-label="{{ __('Target identity') }}">
    <h2>{{ __('Display and identity') }}</h2>
    <form method="post" action="{{ route('admin.targets.update', ['target' => $target->target_id]) }}" class="form-stack">
        @csrf
        @method('PUT')
        <div class="target-field-grid">
            <div class="field">
                <label for="target_id">{{ __('Stable Target ID') }}</label>
                <input id="target_id" type="text" value="{{ $target->target_id }}" readonly aria-readonly="true" aria-describedby="target_id-help">
                <p class="field-help" id="target_id-help">{{ __('Target ID and connector type do not change. Existing users, groups and client references keep pointing at this Target.') }}</p>
            </div>
            <div class="field">
                <label for="display_name">{{ __('Display name') }}</label>
                <input id="display_name" name="display_name" type="text" required maxlength="160" autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ old('display_name', $target->display_name) }}"
                    value="{{ old('display_name', $target->display_name) }}" @error('display_name') aria-invalid="true" aria-describedby="display_name-error" @enderror>
                @error('display_name')<p class="form-error" role="alert" id="display_name-error">{{ $message }}</p>@enderror
            </div>
            <div class="field target-span-all">
                <label for="ai_guidance">{{ __('AI guidance (optional)') }}</label>
                <textarea id="ai_guidance" name="ai_guidance" rows="3"
                    maxlength="{{ \App\Domain\Targets\Target::AI_GUIDANCE_MAX_LENGTH }}" autocomplete="off"
                    placeholder="{{ __('Example: This is a production server. Explain risks and ask before making changes.') }}" @error('ai_guidance') aria-invalid="true" @enderror aria-describedby="ai_guidance_help{{ $errors->has('ai_guidance') ? ' ai_guidance-error' : '' }}">{{ old('ai_guidance', $target->ai_guidance) }}</textarea>
                <p id="ai_guidance_help" class="field-help">{{ __('Shown to authorized AI clients as Target-specific context. This is advice, not enforced approval. Never include credentials or secrets.') }}</p>
                @error('ai_guidance')<p class="field-error" role="alert" id="ai_guidance-error">{{ $message }}</p>@enderror
            </div>
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Save Target details') }}</button>
        </div>
    </form>
</section>
@endcan

@can('targets.configure', $target)
@if($routeRevision !== null)
<section class="panel panel-wide target-enrollment" aria-labelledby="target-route-heading">
    <h2 id="target-route-heading">{{ __('Network routing') }}</h2>
    <p class="field-help">{{ __('All network requests to this Target use the selected route. Changing it resets connection verification and fences retained work. Finish any pending connection transition or authorization revocation first.') }}</p>
    <form class="form-stack" method="post" action="{{ route('admin.targets.relay-route.update', ['target' => $target->target_id]) }}">
        @csrf
        @method('PUT')
        <input type="hidden" name="route_revision" value="{{ $routeRevision }}">
        @include('admin.targets.partials.connection-relay-selector', [
            'selectId' => 'target-edit-connection-relay',
            'initialRelayId' => old('connection_relay_id', $selectedRelay?->relay_id),
            'blockedRelay' => $selectedRelay !== null && ! $connectionRelays->contains(
                fn($relay) => $relay->getKey() === $selectedRelay->getKey(),
            ) ? $selectedRelay : null,
        ])
        @error('route_revision')<p class="field-error" role="alert" id="route-revision-error">{{ $message }}</p>@enderror
        <div class="field">
            <label for="target-edit-route-password">{{ __('Your current Gateway password') }}</label>
            <input id="target-edit-route-password" type="password" name="current_password" maxlength="255"
                data-admin-requires-intent autocomplete="current-password" required>
        </div>
        <button class="button button-primary" type="submit">{{ __('Save connection route and require re-verification') }}</button>
    </form>
</section>
@endif
@endcan

@can('targets.configure', $target)
@if (! empty($configurationRevision))
    <details id="target-connection-settings" class="panel panel-wide target-enrollment admin-collapsible-panel"
        @if (session('target_configuration_failed') || ($errors->any() && old('configuration_revision') !== null)
            || ($target->connector_type === 'arvancloud' && request()->query('section') === 'api-connection')) open @endif>
        <summary><h2 class="admin-disclosure-heading">{{ __('Advanced connector connection settings') }}</h2></summary>
        <p class="field-help">{{ __('Authorized Target configuration editors can rotate connector endpoints and encrypted credentials. Changes are audited and require your current Gateway password. Existing Target access permissions remain unchanged.') }}</p>

        @if ($connectorUi?->configurationView !== null)
            @include($connectorUi->configurationView)
        @endif
    </details>
@else
    <p class="muted">{{ __('This historical connector does not offer a configuration editor while its adapter is paused.') }}</p>
@endif
@endcan
@endsection
