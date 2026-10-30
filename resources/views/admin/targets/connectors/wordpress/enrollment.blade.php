<fieldset class="target-form-section" data-connector-panel="wp_ai_bridge" @if($selected !== 'wp_ai_bridge') hidden disabled @endif>
    <legend>{{ __('3. WordPress (WP AI Bridge)') }}</legend>
    <p class="field-help">{{ __('Use the public HTTPS URL of a WordPress site with WP AI Bridge installed. Authorization is completed after registration.') }}</p>
    <div class="field">
        <label for="base_url">{{ __('WordPress public HTTPS URL') }}</label>
        <input type="url" id="base_url" name="base_url" maxlength="2048" inputmode="url"
            autocomplete="url" placeholder="https://wordpress.example.com" required value="{{ old('base_url') }}">
        @error('base_url')<p class="field-error" role="alert">{{ $message }}</p>@enderror
    </div>
</fieldset>
