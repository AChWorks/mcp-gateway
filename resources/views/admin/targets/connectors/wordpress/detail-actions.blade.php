@if ($refreshPending)
    <p class="muted" role="status">{{ __('WordPress token refresh could not be confirmed. Credential use, reconnection and disconnection are blocked until the full remote authorization has been invalidated.') }}</p>
    @can('security.manage')
        @can('targets.disconnect', $target)
            <section class="panel panel-danger" aria-labelledby="refresh-recovery-title">
                <h3 id="refresh-recovery-title">{{ __('Manual WordPress refresh recovery (Owner only)') }}</h3>
                <p id="reconcile-refresh-help">{{ __('Before proceeding, sign in as a WordPress administrator on the exact origin above. In WP AI Bridge → OAuth Clients, REMOVE this Gateway client ID from the approved list and SAVE. This changes the shared additional-client approval revision: all other non-ChatGPT OAuth clients on that WordPress site are also invalidated and must reconnect. Keep Gateway unapproved until local recovery finishes. A WordPress logout or revocation of the old refresh token alone is NOT enough.') }}</p>
                <p>{{ __('Verify the updated WordPress approval list and preserve operator evidence. Wait until every in-flight refresh is finished (at least 75 seconds). Gateway cannot independently verify WordPress revocation: this is your explicit security attestation. If you cannot verify the change or accept the effect on other clients, leave the Target blocked and do not submit.') }}</p>
                <p>{{ __('Exact Gateway client ID') }}: <code>{{ config('bridge.client.id') }}</code></p>
                <form class="form-stack" method="post" action="{{ route('admin.targets.reconcile-refresh', ['target' => $target->target_id]) }}" aria-label="{{ __('Confirm WordPress refresh recovery for :target', ['target' => $target->display_name]) }}" aria-describedby="reconcile-refresh-help">
                    @csrf
                    <input type="hidden" name="intent_id" value="{{ $refreshIntent?->id }}">
                    <label>
                        {{ __('Confirm exact Target ID') }}
                        <input name="confirm_target_id" required maxlength="64" autocomplete="off" placeholder="{{ $target->target_id }}" id="reconcile_refresh_target_id" @error('confirm_target_id') aria-invalid="true" aria-describedby="reconcile_refresh_target_id-error" @enderror>
                    </label>
                    @error('confirm_target_id')<p class="field-error" id="reconcile_refresh_target_id-error" role="alert">{{ $message }}</p>@enderror
                    <label><input type="checkbox" name="wordpress_client_revoked" value="yes" required id="reconcile_refresh_client_revoked" @error('wordpress_client_revoked') aria-invalid="true" aria-describedby="reconcile_refresh_client_revoked-error" @enderror> {{ __('I personally verified WordPress saved removal of this exact Gateway client from Approved OAuth Clients, invalidating any unknown successor tokens.') }}</label>
                    @error('wordpress_client_revoked')<p class="field-error" id="reconcile_refresh_client_revoked-error" role="alert">{{ $message }}</p>@enderror
                    <label><input type="checkbox" name="other_clients_affected" value="yes" required id="reconcile_refresh_other_clients" @error('other_clients_affected') aria-invalid="true" aria-describedby="reconcile_refresh_other_clients-error" @enderror> {{ __('I accept that this revokes other additional OAuth clients on that WordPress site.') }}</label>
                    @error('other_clients_affected')<p class="field-error" id="reconcile_refresh_other_clients-error" role="alert">{{ $message }}</p>@enderror
                    <label>
                        {{ __('Your current Gateway password') }}
                        <input type="password" name="current_password" required maxlength="255" autocomplete="current-password" id="reconcile_refresh_password" @error('current_password') aria-invalid="true" aria-describedby="reconcile_refresh_password-error" @enderror>
                    </label>
                    @error('current_password')<p class="field-error" id="reconcile_refresh_password-error" role="alert">{{ $message }}</p>@enderror
                    <button type="submit" class="button button-danger">{{ __('Clear local credential after confirmed WordPress revocation') }}</button>
                </form>
            </section>
        @endcan
    @endcan
@elseif ($revocationPending)
    <p class="muted">{{ __('Credential revocation is pending. Use the guided recovery options above. Other authenticated WordPress operations remain blocked until a safe outcome is confirmed.') }}</p>
@elseif (! $hasCredential)
    <p class="muted">{{ __('Authorize this Target to connect WordPress securely.') }}</p>
@endif
