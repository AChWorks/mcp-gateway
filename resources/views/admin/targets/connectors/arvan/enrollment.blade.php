<fieldset class="target-form-section" data-connector-panel="arvancloud" @if($selected !== 'arvancloud') hidden disabled @endif>
    <legend>{{ __('3. ArvanCloud API') }}</legend>
    <p class="field-help">{{ __('Register ONE product/region HTTPS API root. Use another Target for a different API root. The account key stays encrypted in Gateway and cannot be read through MCP. An authenticated GET probe must be explicitly configured to verify the connection.') }}</p>
    <div class="field">
        <label for="arvan-api-base-url">{{ __('API base URL (HTTPS)') }}</label>
        <input type="url" id="arvan-api-base-url" name="api_base_url" maxlength="1024" required
            inputmode="url" autocomplete="off" value="{{ old('api_base_url') }}"
            placeholder="https://napi.arvancloud.ir/cdn/4.0"
            @error('api_base_url') aria-invalid="true" aria-describedby="arvan-api-base-error" @enderror>
        @error('api_base_url')<p class="field-error" role="alert" id="arvan-api-base-error">{{ $message }}</p>@enderror
    </div>
    <div class="field">
        <label for="arvan-api-spec-url">{{ __('OpenAPI description URL (optional)') }}</label>
        <input type="url" id="arvan-api-spec-url" name="api_spec_url" maxlength="1024"
            inputmode="url" autocomplete="off" value="{{ old('api_spec_url') }}"
            placeholder="https://www.arvancloud.ir/api-docs/cdn-4.0.yml">
        <p class="field-help">{{ __('Catalog is fetched on demand; it never supplies credentials, destinations or authorization. Compatible new API paths can be executed even before a catalog update.') }}</p>
    </div>
    <div class="field">
        <label for="arvan-api-probe-path">{{ __('Read-only GET probe path (optional)') }}</label>
        <input type="text" id="arvan-api-probe-path" name="api_probe_path" maxlength="1024"
            autocomplete="off" value="{{ old('api_probe_path') }}" placeholder="/domains">
        <p class="field-help">{{ __('Use a known, authenticated read-only path under the registered API root. Never configure a mutating URL as the probe.') }}</p>
    </div>
    <div class="field">
        <label for="arvan-api-key">{{ __('Machine User API key') }}</label>
        <input type="password" id="arvan-api-key" name="api_key" maxlength="4096"
            autocomplete="new-password" required>
        <p class="field-help">{{ __('The key is stored encrypted, never redisplayed, never logged and never sent to ChatGPT.') }}</p>
    </div>
    <div class="field">
        <label for="arvan-owner-password">{{ __('Current Owner password') }}</label>
        <input type="password" id="arvan-owner-password" name="current_password" maxlength="255"
            autocomplete="current-password" data-admin-requires-intent required>
        <p class="field-help">{{ __('Only a Gateway Owner can enroll a privileged API key. Actions still require Target-scoped permissions.') }}</p>
    </div>
</fieldset>
