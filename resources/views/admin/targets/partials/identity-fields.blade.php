        <fieldset class="target-form-section" data-target-shared @if($selected === '') hidden disabled @endif>
            <legend>{{ __('2. Target details') }}</legend>
            <p class="field-help">{{ __('A stable ID identifies this Target across clients and permissions; the display name can change later.') }}</p>
            <div class="target-field-grid">
                <div class="field">
                    <label for="target_id">{{ __('Stable Target ID') }}</label>
                    <input type="text" id="target_id" name="target_id" maxlength="64" pattern="[a-z0-9]+(-[a-z0-9]+)*" required
                        autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ old('target_id') }}" spellcheck="false" placeholder="my-target" value="{{ old('target_id') }}" @error('target_id') aria-invalid="true" @enderror aria-describedby="target_id-help{{ $errors->has('target_id') ? ' target_id-error' : '' }}">
                    <p class="field-help" id="target_id-help">{{ __('Lowercase letters, numbers and hyphens.') }}</p>
                    @error('target_id')<p class="field-error" role="alert" id="target_id-error">{{ $message }}</p>@enderror
                </div>
                <div class="field">
                    <label for="display_name">{{ __('Display name') }}</label>
                    <input type="text" id="display_name" name="display_name" maxlength="160" required
                        autocomplete="off" data-admin-manual-entry data-admin-server-value="{{ old('display_name') }}" placeholder="{{ __('Production blog or staging server') }}" value="{{ old('display_name') }}" @error('display_name') aria-invalid="true" aria-describedby="display_name-error" @enderror>
                    @error('display_name')<p class="field-error" role="alert" id="display_name-error">{{ $message }}</p>@enderror
                </div>
                <div class="field target-span-all">
                    <label for="ai_guidance">{{ __('AI guidance (optional)') }}</label>
                    <textarea id="ai_guidance" name="ai_guidance" rows="3"
                        maxlength="{{ \App\Domain\Targets\Target::AI_GUIDANCE_MAX_LENGTH }}" autocomplete="off"
                        placeholder="{{ __('Example: This is a production server. Explain risks and ask before making changes.') }}" @error('ai_guidance') aria-invalid="true" @enderror aria-describedby="ai_guidance_help{{ $errors->has('ai_guidance') ? ' ai_guidance-error' : '' }}">{{ old('ai_guidance') }}</textarea>
                    <p id="ai_guidance_help" class="field-help">{{ __('Shown to authorized AI clients as Target-specific context. This is advice, not enforced approval. Never include credentials or secrets.') }}</p>
                    @error('ai_guidance')<p class="field-error" role="alert" id="ai_guidance-error">{{ $message }}</p>@enderror
                </div>
            </div>
            @if(auth()->user()?->getRawOriginal('role') === 'owner')
                <div class="target-subsection">
                    <h3>{{ __('Connection route') }}</h3>
                    @include('admin.targets.partials.connection-relay-selector', [
                        'selectId' => 'connection_relay_id',
                        'initialRelayId' => old('connection_relay_id'),
                        'disabled' => $selected === 'ssh_direct' && $selectedSshMode !== 'direct',
                    ])
                    <div class="field" data-relay-owner-group>
                        <label for="target-relay-owner-password">{{ __('Current Owner password (required when using a Relay)') }}</label>
                        <input id="target-relay-owner-password" type="password" name="current_password" data-admin-requires-intent
                            data-relay-owner-password maxlength="255" autocomplete="current-password"
                            @if($selected === 'ssh_direct' && $selectedSshMode !== 'direct') disabled @endif>
                    </div>
                </div>
            @endif
        </fieldset>
