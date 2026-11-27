@if ($sshConfig !== null)
        @if ($sshHasCredential)
            <p class="muted">{{ __('SSH login credentials are stored locally. Verify the pinned host key and login separately. Command and file access also requires the applicable Target permissions.') }}</p>
            <div class="filter-actions">
                @if (! $target->operations_paused)
                @can('targets.test', $target)
                    <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-primary" type="submit">{{ __('Verify SSH host and login') }}</button>
                    </form>
                @endcan
                @endif
                @can('targets.disconnect', $target)
                    <form method="post" action="{{ route('admin.targets.disconnect', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-secondary" type="submit">{{ __('Delete Gateway SSH credential') }}</button>
                    </form>
                @endcan
            </div>
        @else
            <p class="muted">{{ __('No SSH credential remains. Removing the local credential does not revoke the remote Unix account.') }}
                @can('targets.configure', $target)
                    <a href="{{ route('admin.targets.edit', ['target' => $target->target_id]).'#target-connection-settings' }}">{{ __('Open advanced connection settings to add a credential') }}</a>
                @else
                    {{ __('Ask an authorized Target configuration editor to add a credential.') }}
                @endcan
            </p>
        @endif
@endif

@php($initialSetup = $managedReverse !== null && $sshHasCredential && $managedReverse->login_public_key !== '')
@if ($managedReverse !== null)
@canany(['targets.configure', 'targets.disconnect'], $target)
    <div class="target-subsection">
        @if ($errors->has('current_password') || $errors->has('confirm_target_id'))
            <div class="alert alert-error" role="alert">
                <p>{{ __('Managed Reverse SSH action was not completed. Review the confirmation fields and retry.') }}</p>
                @error('current_password')<p>{{ $message }}</p>@enderror
                @error('confirm_target_id')<p>{{ $message }}</p>@enderror
            </div>
        @endif
        @can('targets.configure', $target)
        @if ($managedReverse->state !== 'revoked' && $target->usesReverseRoute())
            <details class="target-help-details" @if ($errors->any() && old('managed_reverse_action') === 'reissue') open @endif >
                <summary><h3 class="admin-disclosure-heading">{{ __('Reissue Managed Reverse route (advanced)') }}</h3></summary>
            <p class="field-help">{{ $initialSetup
                ? __('The new setup command can install the current initial SSH login key.')
                : __('The transport command preserves existing SSH login credentials and does not restore a deliberately removed login key.') }}
                {{ __('The old token and control key are fenced, and the old listener port is quarantined. Any old Target service must be stopped separately. The new install command is shown once.') }}</p>
            <form class="form-stack" method="post" action="{{ route('admin.reverse-ssh.targets.reissue', ['target' => $target->target_id]) }}">
                @csrf
                <input type="hidden" name="managed_reverse_action" value="reissue">
                <div class="field">
                    <label for="reverse_reissue_id">{{ __('Type exact Target ID to reissue') }}: <code>{{ $target->target_id }}</code></label>
                    <input id="reverse_reissue_id" name="confirm_target_id" required maxlength="64" autocomplete="off" data-admin-manual-entry data-admin-server-value="">
                </div>
                <div class="field">
                    <label for="reverse_reissue_password">{{ __('Your current Gateway password') }}</label>
                    <input id="reverse_reissue_password" type="password" name="current_password" data-admin-requires-intent required autocomplete="current-password">
                </div>
                <button class="button button-secondary" type="submit">{{ $initialSetup ? __('Reissue setup command') : __('Reissue transport command') }}</button>
            </form>
            </details>
        @endif
        @endcan
        @if ($managedReverse->state === 'revoked' && $managedReverse->publication_pending)
            <div class="alert alert-error" role="status">{{ __('Gateway route was revoked; publication of the updated control key reader is still pending. Retry reconciliation below. Do not forget this Target until the reader is reconciled.') }}</div>
        @elseif ($managedReverse->state === 'revoked')
            <p class="field-help">{{ __('Managed Reverse SSH authorization was revoked and the host key policy reconciled. The old managed enrollment is retired; select a different network route without replacing stored login credentials.') }}</p>
        @endif
        @can('targets.configure', $target)
        @if ($managedReverse->state !== 'revoked' || $managedReverse->publication_pending)
        <details class="target-help-details" @if ($errors->any() && old('managed_reverse_action') === 'revoke') open @endif >
            <summary><h3 class="admin-disclosure-heading">{{ $managedReverse->state === 'revoked' ? __('Reconcile revoked host key (advanced)') : __('Revoke managed Reverse SSH (destructive)') }}</h3></summary>
        <p class="field-help">{{ __('Revokes this network route and its restricted control key authorization. Target login credentials are preserved. Existing remote control sessions and the Target-side systemd service are NOT stopped by this request. Perform Target-side cleanup separately.') }}</p>
        <form class="form-stack" method="post" action="{{ route('admin.reverse-ssh.targets.revoke', ['target' => $target->target_id]) }}">
            @csrf
            <input type="hidden" name="managed_reverse_action" value="revoke">
            <div class="field">
                <label for="reverse_revoke_id">{{ __('Type exact Target ID to revoke') }}: <code>{{ $target->target_id }}</code></label>
                <input id="reverse_revoke_id" name="confirm_target_id" required maxlength="64" autocomplete="off" data-admin-manual-entry data-admin-server-value="">
            </div>
            <div class="field">
                <label for="reverse_revoke_password">{{ __('Your current Gateway password') }}</label>
                <input id="reverse_revoke_password" type="password" name="current_password" data-admin-requires-intent required autocomplete="current-password">
            </div>
            <div class="target-create-actions">
                <button class="button button-danger" type="submit">{{ $managedReverse->state === 'revoked' ? __('Retry host key revocation') : __('Revoke managed Reverse SSH access') }}</button>
            </div>
        </form>
        </details>
        @endif
        @endcan
    </div>
@endcanany
@endif
