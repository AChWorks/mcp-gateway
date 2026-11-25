<fieldset class="target-form-section" data-connector-panel="arvancloud" @if($selected !== 'arvancloud') hidden disabled @endif>
    <legend>{{ __('3. ArvanCloud API') }}</legend>
    <p class="field-help">{{ __('Register one ArvanCloud product and region API root per Target. Saving stores an encrypted Machine User key, but does not test that key or grant AI clients access.') }}</p>

    <div class="field">
        <label for="arvan-api-base-url">{{ __('API base URL (HTTPS)') }}</label>
        <input type="url" id="arvan-api-base-url" name="api_base_url" maxlength="1024" required
            inputmode="url" autocomplete="off" spellcheck="false" value="{{ old('api_base_url') }}"
            placeholder="https://napi.arvancloud.ir/cdn/4.0"
            @error('api_base_url') aria-invalid="true" @enderror
            aria-describedby="arvan-api-base-url-help{{ $errors->has('api_base_url') ? ' arvan-api-base-url-error' : '' }}">
        <p class="field-help" id="arvan-api-base-url-help">{{ __('Use the published HTTPS API root, not an individual operation URL. The Gateway appends each request path to this base. Different products or regions need separate Targets.') }}</p>
        @error('api_base_url')<p class="field-error" role="alert" id="arvan-api-base-url-error">{{ $message }}</p>@enderror
    </div>

    <details class="target-help-details">
        <summary>{{ __('API root examples and version paths') }}</summary>
        <p class="field-help">{{ __('CDN 4.0 root:') }} <code>https://napi.arvancloud.ir/cdn/4.0</code> {{ __('with request path') }} <code>/domains</code>.</p>
        <p class="field-help">{{ __('Object Storage management root:') }} <code>https://storage.arvanapis.ir</code> {{ __('with request path') }} <code>/v1/access-points</code>. {{ __('Do not repeat /v1 in both places.') }}</p>
        <p class="field-help">{{ __('For IaaS or CaaS, choose the real published regional or zone-specific API root. S3 object transfers use different credentials and are not this Machine User connector.') }}</p>
    </details>

    <div class="field">
        <label for="arvan-api-spec-url">{{ __('OpenAPI description URL (optional)') }}</label>
        <input type="url" id="arvan-api-spec-url" name="api_spec_url" maxlength="1024"
            inputmode="url" autocomplete="off" spellcheck="false" value="{{ old('api_spec_url') }}"
            placeholder="https://www.arvancloud.ir/api-docs/cdn-4.0.yml"
            @error('api_spec_url') aria-invalid="true" @enderror
            aria-describedby="arvan-api-spec-url-help{{ $errors->has('api_spec_url') ? ' arvan-api-spec-url-error' : '' }}">
        <p class="field-help" id="arvan-api-spec-url-help">{{ __('Optional public YAML/JSON description for API catalog discovery. It is fetched on demand without your key, and never changes the registered API destination or permissions. Compatible paths work without a catalog.') }}</p>
        @error('api_spec_url')<p class="field-error" role="alert" id="arvan-api-spec-url-error">{{ $message }}</p>@enderror
    </div>

    <div class="field">
        <label for="arvan-api-probe-path">{{ __('Read-only GET probe path (optional)') }}</label>
        <input type="text" id="arvan-api-probe-path" name="api_probe_path" maxlength="1024"
            autocomplete="off" spellcheck="false" value="{{ old('api_probe_path') }}" placeholder="/domains"
            @error('api_probe_path') aria-invalid="true" @enderror
            aria-describedby="arvan-api-probe-path-help{{ $errors->has('api_probe_path') ? ' arvan-api-probe-path-error' : '' }}">
        <p class="field-help" id="arvan-api-probe-path-help">{{ __('Enter a known, authenticated, non-mutating path beginning with / under the selected API root. Example for CDN: /domains. Leave it blank if no safe authenticated GET path is known: the Target and authorized API requests still work, and the HTTPS endpoint check remains available without verifying the API key.') }}</p>
        @error('api_probe_path')<p class="field-error" role="alert" id="arvan-api-probe-path-error">{{ $message }}</p>@enderror
    </div>

    <div class="field">
        <label for="arvan-api-key">{{ __('Machine User API key') }}</label>
        <input type="password" id="arvan-api-key" name="api_key" maxlength="4096" required
            autocomplete="new-password" @error('api_key') aria-invalid="true" @enderror
            aria-describedby="arvan-api-key-help{{ $errors->has('api_key') ? ' arvan-api-key-error' : '' }}">
        <p class="field-help" id="arvan-api-key-help">{{ __('Use the ArvanCloud Machine User API key permitted for this product. It is encrypted, never shown again or sent to ChatGPT. This is not an S3 Access Key or Secret Key.') }}</p>
        @error('api_key')<p class="field-error" role="alert" id="arvan-api-key-error">{{ $message }}</p>@enderror
    </div>

    <div class="field">
        <label for="arvan-owner-password">{{ __('Your current Gateway password') }}</label>
        <input type="password" id="arvan-owner-password" name="current_password" maxlength="255"
            autocomplete="current-password" data-admin-requires-intent required
            @error('current_password') aria-invalid="true" @enderror
            aria-describedby="arvan-owner-password-help{{ $errors->has('current_password') ? ' arvan-owner-password-error' : '' }}">
        <p class="field-help" id="arvan-owner-password-help">{{ __('Confirms this privileged Gateway registration. Your Gateway password is not sent to ArvanCloud; Target permissions still govern API operations.') }}</p>
        @error('current_password')<p class="field-error" role="alert" id="arvan-owner-password-error">{{ $message }}</p>@enderror
    </div>
    <p class="field-help">{{ __('Next: Register Target, open its details and run Test connection for the configured GET probe. The optional endpoint check below checks Gateway reachability only, not API key validity.') }}</p>
</fieldset>
