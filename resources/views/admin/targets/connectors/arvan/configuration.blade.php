<form class="form-stack" method="post"
    action="{{ route('admin.targets.configuration.update', ['target' => $target->target_id]) }}"
    aria-describedby="arvan-configuration-help{{ $errors->has('configuration_revision') ? ' arvan-configuration-revision-error' : '' }}{{ $errors->has('configuration') ? ' arvan-configuration-error' : '' }}">
    @csrf
    @method('PUT')
    <input type="hidden" name="configuration_revision" value="{{ $configurationRevision }}">
    <p class="field-help" id="arvan-configuration-help">{{ __('Save these connection settings separately from the Target display name. Changing the API root requires a new Machine User key, and changing the root, key or GET probe clears prior connection verification. Save first, then return to Target details for an unauthenticated HTTPS reachability check or, when a known read-only GET probe is configured, API-key verification. Passwords and keys are never restored after errors.') }}</p>
    @error('configuration_revision')<p class="field-error" role="alert" id="arvan-configuration-revision-error">{{ $message }} {{ __('Reload this page if another edit changed the configuration.') }}</p>@enderror
    @error('configuration')<p class="field-error" role="alert" id="arvan-configuration-error">{{ $message }}</p>@enderror

    <div class="field">
        <label for="arvan-edit-api-base-url">{{ __('Registered API base URL (HTTPS)') }}</label>
        <input id="arvan-edit-api-base-url" type="url" name="api_base_url" required maxlength="1024"
            inputmode="url" autocomplete="off" spellcheck="false"
            value="{{ old('api_base_url', $arvanConfig->base_url) }}"
            @error('api_base_url') aria-invalid="true" @enderror
            aria-describedby="arvan-edit-api-base-url-help{{ $errors->has('api_base_url') ? ' arvan-edit-api-base-url-error' : '' }}">
        <p class="field-help" id="arvan-edit-api-base-url-help">{{ __('One product/region HTTPS root per Target; request paths are appended to it. Enter a new API key below if you change this URL.') }}</p>
        @error('api_base_url')<p class="field-error" role="alert" id="arvan-edit-api-base-url-error">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="arvan-edit-api-spec-url">{{ __('OpenAPI description URL (optional)') }}</label>
        <input id="arvan-edit-api-spec-url" type="url" name="api_spec_url" maxlength="1024"
            inputmode="url" autocomplete="off" spellcheck="false"
            value="{{ old('api_spec_url', $arvanConfig->spec_url) }}"
            @error('api_spec_url') aria-invalid="true" @enderror
            aria-describedby="arvan-edit-api-spec-url-help{{ $errors->has('api_spec_url') ? ' arvan-edit-api-spec-url-error' : '' }}">
        <p class="field-help" id="arvan-edit-api-spec-url-help">{{ __('Optional public YAML/JSON catalog source. No Machine User key is sent to this URL, and clearing it does not disable compatible API requests.') }}</p>
        @error('api_spec_url')<p class="field-error" role="alert" id="arvan-edit-api-spec-url-error">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="arvan-edit-api-probe-path">{{ __('Read-only GET probe path (optional)') }}</label>
        <input id="arvan-edit-api-probe-path" type="text" name="api_probe_path" maxlength="1024"
            autocomplete="off" spellcheck="false"
            value="{{ old('api_probe_path', $arvanConfig->probe_path) }}"
            @error('api_probe_path') aria-invalid="true" @enderror
            aria-describedby="arvan-edit-api-probe-path-help{{ $errors->has('api_probe_path') ? ' arvan-edit-api-probe-path-error' : '' }}">
        <p class="field-help" id="arvan-edit-api-probe-path-help">{{ __('Enter a known authenticated GET path beginning with /, such as /domains for CDN. Leaving it blank keeps the key and API operations usable; HTTPS endpoint reachability can still be checked without authentication, but the key is not verified by that check.') }}</p>
        @error('api_probe_path')<p class="field-error" role="alert" id="arvan-edit-api-probe-path-error">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="arvan-edit-api-key">{{ __('New Machine User API key (optional if unchanged)') }}</label>
        <input id="arvan-edit-api-key" type="password" name="api_key" maxlength="4096" autocomplete="new-password"
            @error('api_key') aria-invalid="true" @enderror
            aria-describedby="arvan-edit-api-key-help{{ $errors->has('api_key') ? ' arvan-edit-api-key-error' : '' }}">
        <p class="field-help" id="arvan-edit-api-key-help">{{ __('Leave blank to keep the existing encrypted key when the API root is unchanged. A different API root requires a new key. This is not an S3 credential.') }}</p>
        @error('api_key')<p class="field-error" role="alert" id="arvan-edit-api-key-error">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="arvan-edit-owner-password">{{ __('Current Owner password') }}</label>
        <input id="arvan-edit-owner-password" type="password" name="current_password" maxlength="255"
            autocomplete="current-password" data-admin-requires-intent required
            @if(session('target_configuration_failed')) @error('current_password') aria-invalid="true" @enderror @endif
            aria-describedby="arvan-edit-owner-password-help{{ session('target_configuration_failed') && $errors->has('current_password') ? ' arvan-edit-owner-password-error' : '' }}">
        <p class="field-help" id="arvan-edit-owner-password-help">{{ __('Confirms this Gateway settings change; your password is not sent to ArvanCloud.') }}</p>
        @if(session('target_configuration_failed'))
            @error('current_password')<p class="field-error" role="alert" id="arvan-edit-owner-password-error">{{ $message }}</p>@enderror
        @endif
    </div>
    <button class="button button-primary" type="submit">{{ __('Save API connection settings') }}</button>
</form>
