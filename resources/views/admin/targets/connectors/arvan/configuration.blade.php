<form class="form-stack" method="post"
    action="{{ route('admin.targets.configuration.update', ['target' => $target->target_id]) }}">
    @csrf
    @method('PUT')
    <input type="hidden" name="configuration_revision" value="{{ $configurationRevision }}">
    <p class="field-help">{{ __('Changing the API origin requires a fresh Machine User key; an old key will never be forwarded to a different origin. Changing the key invalidates previous verification.') }}</p>
    @error('configuration_revision')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    @error('configuration')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    <div class="field">
        <label for="arvan-edit-api-base-url">{{ __('Registered API base URL') }}</label>
        <input id="arvan-edit-api-base-url" type="url" name="api_base_url" required maxlength="1024"
            value="{{ old('api_base_url', $arvanConfig->base_url) }}">
        @error('api_base_url')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="arvan-edit-api-spec-url">{{ __('OpenAPI description URL') }}</label>
        <input id="arvan-edit-api-spec-url" type="url" name="api_spec_url" maxlength="1024"
            value="{{ old('api_spec_url', $arvanConfig->spec_url) }}">
    </div>
    <div class="field">
        <label for="arvan-edit-api-probe-path">{{ __('Read-only GET probe path') }}</label>
        <input id="arvan-edit-api-probe-path" type="text" name="api_probe_path" maxlength="1024"
            value="{{ old('api_probe_path', $arvanConfig->probe_path) }}">
    </div>
    <div class="field">
        <label for="arvan-edit-api-key">{{ __('New API key (leave empty to keep current)') }}</label>
        <input id="arvan-edit-api-key" type="password" name="api_key" maxlength="4096" autocomplete="new-password">
    </div>
    <div class="field">
        <label for="arvan-edit-owner-password">{{ __('Current Owner password') }}</label>
        <input id="arvan-edit-owner-password" type="password" name="current_password" maxlength="255"
            autocomplete="current-password" data-admin-requires-intent required>
        @error('current_password')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
    <button class="button button-primary" type="submit">{{ __('Save API connection settings') }}</button>
</form>
