@php
    $canChangeWordpressOrigin = in_array($target->connection_state->value, ['disconnected', 'error'], true)
        && ! ($hasCredential ?? false) && ! ($revocationPending ?? false) && ! ($refreshPending ?? false)
        && ! ($oauthFlowPending ?? false) && ! ($refreshIntent ?? null);
@endphp
@if (! $canChangeWordpressOrigin)
    <div class="alert alert-caution" role="status">
        {{ __('WordPress OAuth is still connected or pending. First use Disconnect WordPress from Target details and wait for confirmed remote token revocation/recovery. Only then can the HTTPS origin change safely. Your users and group assignments stay intact.') }}
    </div>
@else
    <form class="form-stack" method="post"
        action="{{ route('admin.targets.configuration.update', ['target' => $target->target_id]) }}">
        @csrf
        @method('PUT')
        <input type="hidden" name="configuration_revision" value="{{ $configurationRevision }}">
        @error('configuration_revision')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        @error('configuration')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        <div class="field">
            <label for="wp_edit_origin">{{ __('WordPress public HTTPS URL') }}</label>
            <input id="wp_edit_origin" name="base_url" type="url" maxlength="2048" required inputmode="url"
                value="{{ old('base_url', $wpConfig->base_url) }}">
            <p class="field-help">{{ __('The new HTTPS origin is independently discovered and validated. Existing OAuth credentials are never reused; authorize WordPress again afterward.') }}</p>
            @error('base_url')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="field">
            <label for="wp_config_owner_password">{{ __('Current Owner password') }}</label>
            <input id="wp_config_owner_password" type="password" name="current_password" required maxlength="255"
                autocomplete="current-password">
            @error('current_password')<p class="form-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <button class="button button-primary" type="submit">{{ __('Verify and save WordPress origin') }}</button>
    </form>
@endif
