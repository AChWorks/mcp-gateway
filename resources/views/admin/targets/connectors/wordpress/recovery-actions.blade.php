<div class="target-recovery-actions" aria-label="{{ __('Safe WordPress recovery actions') }}">
    @if ($refreshPending)
        <p class="muted">{{ __('A token refresh is unresolved. Disconnect, Cancel disconnect and Reauthorize are unavailable. Follow the separate Owner-only refresh reconciliation procedure below.') }}</p>
    @elseif ($revocationPending && $revocationIntent !== null)
        @if ($recovery['canFinish'])
            @can('targets.disconnect', $target)
                <form method="post" action="{{ route('admin.targets.finish-disconnect', ['target' => $target->target_id]) }}">
                    @csrf
                    <input type="hidden" name="intent_id" value="{{ $revocationIntent->id }}">
                    <button class="button button-primary" type="submit">{{ $revocationIntent->phase === 'confirmed' ? __('Finish confirmed disconnect') : __('Finish disconnect — retry unsent revoke only') }}</button>
                </form>
            @endcan
        @else
            <p class="target-recovery-warning">{{ __('Do not retry this revoke or restore the old credential: WordPress may have already processed it. The only supported remote recovery is to independently revoke the whole Gateway client authorization in WordPress and attest to that action.') }}</p>
        @endif

        @if ($recovery['cancelGuidance'] ?? null)
            <p class="muted">{{ $recovery['cancelGuidance'] }}</p>
        @endif

        @if ($recovery['canCancel'])
            @can('security.manage')
                @can('targets.connect', $target)
                    @can('targets.disconnect', $target)
                        @if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner)
                            <details class="target-recovery-details">
                                <summary>{{ __('Cancel pending disconnect — verify no revoke was sent') }}</summary>
                                <p id="cancel-disconnect-help">{{ __('This option is offered only because the stored revoke attempt is proven never dispatched and zero token revocations were acknowledged. Gateway must also confirm that the existing access token still works with an authenticated WordPress catalog request. Metadata alone is not enough. If verification fails, the Target stays blocked.') }}</p>
                                <form class="form-stack" method="post" action="{{ route('admin.targets.cancel-disconnect', ['target' => $target->target_id]) }}" aria-label="{{ __('Cancel pending disconnect for :target', ['target' => $target->display_name]) }}" aria-describedby="cancel-disconnect-help">
                                    @csrf
                                    <input type="hidden" name="intent_id" value="{{ $revocationIntent->id }}">
                                    <label>{{ __('Type exact Target ID') }}
                                        <input name="confirm_target_id" required maxlength="64" autocomplete="off" placeholder="{{ $target->target_id }}" id="cancel_disconnect_target_id" @error('confirm_target_id') aria-invalid="true" aria-describedby="cancel_disconnect_target_id-error" @enderror>
                                    </label>
                                    @error('confirm_target_id')<p class="field-error" id="cancel_disconnect_target_id-error" role="alert">{{ $message }}</p>@enderror
                                    <label>{{ __('Your current Gateway password') }}
                                        <input type="password" name="current_password" required maxlength="255" autocomplete="current-password" id="cancel_disconnect_password" @error('current_password') aria-invalid="true" aria-describedby="cancel_disconnect_password-error" @enderror>
                                    </label>
                                    @error('current_password')<p class="field-error" id="cancel_disconnect_password-error" role="alert">{{ $message }}</p>@enderror
                                    <button class="button button-secondary" type="submit">{{ __('Verify WordPress authorization and cancel') }}</button>
                                </form>
                            </details>
                        @endif
                    @endcan
                @endcan
            @endcan
        @endif

        @if ($recovery['needsExternalProof'])
            @can('security.manage')
                @can('targets.disconnect', $target)
                    @if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner)
                        <details class="target-recovery-details">
                            <summary>{{ __('WordPress-side recovery for uncertain revocation (Owner)') }}</summary>
                            <p id="reconcile-disconnect-help">{{ __('Sign in to the exact WordPress origin below. In WP AI Bridge → OAuth Clients, REMOVE this Gateway client from Approved OAuth Clients and SAVE. This invalidates unknown token successors but also revokes other non-ChatGPT OAuth clients for that WordPress site. WordPress logout or revoking one old token is insufficient.') }}</p>
                            <p>{{ __('Verify the change and retain evidence. Do not proceed while any operation could still be in flight. The Gateway does not independently verify your WordPress-side revocation; the action below only clears its local credential after your explicit attestation.') }}</p>
                            <p>{{ __('Gateway OAuth client ID') }}: <code class="small-code">{{ config('bridge.client.id') }}</code></p>
                            <form class="form-stack" method="post" action="{{ route('admin.targets.reconcile-disconnect', ['target' => $target->target_id]) }}" aria-label="{{ __('Confirm WordPress-side revocation for :target', ['target' => $target->display_name]) }}" aria-describedby="reconcile-disconnect-help">
                                @csrf
                                <input type="hidden" name="intent_id" value="{{ $revocationIntent->id }}">
                                <label>{{ __('Type exact Target ID') }}
                                    <input name="confirm_target_id" required maxlength="64" autocomplete="off" placeholder="{{ $target->target_id }}" id="reconcile_disconnect_target_id" @error('confirm_target_id') aria-invalid="true" aria-describedby="reconcile_disconnect_target_id-error" @enderror>
                                </label>
                                @error('confirm_target_id')<p class="field-error" id="reconcile_disconnect_target_id-error" role="alert">{{ $message }}</p>@enderror
                                <label><input type="checkbox" name="wordpress_client_revoked" value="yes" required id="reconcile_disconnect_client_revoked" @error('wordpress_client_revoked') aria-invalid="true" aria-describedby="reconcile_disconnect_client_revoked-error" @enderror>
                                    {{ __('I verified WordPress saved removal of this exact Gateway OAuth client, invalidating all possible successor tokens.') }}
                                </label>
                                @error('wordpress_client_revoked')<p class="field-error" id="reconcile_disconnect_client_revoked-error" role="alert">{{ $message }}</p>@enderror
                                <label><input type="checkbox" name="other_clients_affected" value="yes" required id="reconcile_disconnect_other_clients" @error('other_clients_affected') aria-invalid="true" aria-describedby="reconcile_disconnect_other_clients-error" @enderror>
                                    {{ __('I understand this also revokes other additional OAuth clients on the WordPress site.') }}
                                </label>
                                @error('other_clients_affected')<p class="field-error" id="reconcile_disconnect_other_clients-error" role="alert">{{ $message }}</p>@enderror
                                <label>{{ __('Your current Gateway password') }}
                                    <input type="password" name="current_password" required maxlength="255" autocomplete="current-password" id="reconcile_disconnect_password" @error('current_password') aria-invalid="true" aria-describedby="reconcile_disconnect_password-error" @enderror>
                                </label>
                                @error('current_password')<p class="field-error" id="reconcile_disconnect_password-error" role="alert">{{ $message }}</p>@enderror
                                <button class="button button-danger" type="submit">{{ __('Clear Gateway credential after WordPress-side revocation') }}</button>
                            </form>
                        </details>
                    @endif
                @endcan
            @else
            @endcan
        @endif
    @elseif (! $hasCredential)
        @if ($oauthFlowPending)
            <p class="muted">{{ __('A WordPress OAuth browser flow is pending. Continue it in the original tab, or restart it here. Restarting invalidates the old callback state; it does not restore a revoked credential.') }}</p>
        @endif
        @can('targets.connect', $target)
            <form method="post" action="{{ route('admin.targets.connect', ['target' => $target->target_id]) }}">
                @csrf
                <button class="button button-primary" type="submit">{{ $oauthFlowPending ? __('Restart WordPress authorization') : __('Authorize WordPress') }}</button>
            </form>
        @endcan
    @else
        @can('targets.reconnect', $target)
            @can('targets.disconnect', $target)
                @can('targets.connect', $target)
                    <form method="post" action="{{ route('admin.targets.reconnect', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-secondary" type="submit">{{ __('Reauthorize WordPress (revoke previous grant first)') }}</button>
                    </form>
                @endcan
            @endcan
        @endcan
        @can('targets.disconnect', $target)
            <form method="post" action="{{ route('admin.targets.disconnect', ['target' => $target->target_id]) }}">
                @csrf
                <button class="button button-secondary" type="submit">{{ __('Disconnect WordPress') }}</button>
            </form>
        @endcan
    @endif
    @if (! $target->operations_paused)
    @can('targets.test', $target)
        <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}">
            @csrf
            <button class="button button-secondary" type="submit">{{ __('Check public WordPress metadata (not OAuth)') }}</button>
        </form>
    @endcan
    @endif
</div>
