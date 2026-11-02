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
            <p class="muted">{{ __('No SSH credential remains. Register a new Target for a fresh independently verified host key and login secret. Removing the local credential does not revoke the remote Unix account.') }}</p>
        @endif
@endif

@php
    $managedReverse = \App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment::query()
        ->where('target_record_id', $target->getKey())->first();
@endphp
@if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner && $managedReverse !== null)
    <div class="target-subsection">
        @if ($errors->has('current_password') || $errors->has('confirm_target_id'))
            <div class="alert alert-error" role="alert">
                <p>{{ __('Managed Reverse SSH action was not completed. Review the confirmation fields and retry.') }}</p>
                @error('current_password')<p>{{ $message }}</p>@enderror
                @error('confirm_target_id')<p>{{ $message }}</p>@enderror
            </div>
        @endif
        @if ($managedReverse->state !== 'revoked' && $target->connection_state === \App\Domain\Targets\TargetConnectionState::Pending)
            <h3>{{ __('Retry Pending Setup without deleting this Target') }}</h3>
            <p class="field-help">{{ __('An expired, rejected or ambiguous one-use claim can be reissued with the same Target ID. The old token and control key are fenced, and the old listener port is quarantined. Any old Target service must be stopped separately. The new install command is shown once.') }}</p>
            <form class="form-stack" method="post" action="{{ route('admin.reverse-ssh.targets.reissue', ['target' => $target->target_id]) }}">
                @csrf
                <div class="field">
                    <label for="reverse_reissue_id">{{ __('Type exact Target ID to reissue') }}: <code>{{ $target->target_id }}</code></label>
                    <input id="reverse_reissue_id" name="confirm_target_id" required maxlength="64" autocomplete="off">
                </div>
                <div class="field">
                    <label for="reverse_reissue_password">{{ __('Current Owner password') }}</label>
                    <input id="reverse_reissue_password" type="password" name="current_password" required autocomplete="current-password">
                </div>
                <button class="button button-secondary" type="submit">{{ __('Reissue one-use install command') }}</button>
            </form>
        @endif
        @if ($managedReverse->state === 'revoked' && $managedReverse->publication_pending)
            <div class="alert alert-error" role="status">{{ __('Gateway credential and route were revoked; publication of the updated control key reader is still pending. Retry reconciliation below. Do not forget this Target until the reader is reconciled.') }}</div>
        @elseif ($managedReverse->state === 'revoked')
            <p class="field-help">{{ __('Managed Reverse SSH authorization was revoked and the host key policy reconciled. No further enrollment is permitted for this Target record.') }}</p>
        @endif
        @if ($managedReverse->state !== 'revoked' || $managedReverse->publication_pending)
        <h3>{{ $managedReverse->state === 'revoked' ? __('Reconcile revoked host key') : __('Revoke managed Reverse SSH') }}</h3>
        <p class="field-help">{{ __('Stops future Gateway operations, removes restricted control key authorization and local login credentials. Existing remote control sessions and the Target-side systemd service are NOT stopped by this request. Perform Target-side cleanup separately.') }}</p>
        <form class="form-stack" method="post" action="{{ route('admin.reverse-ssh.targets.revoke', ['target' => $target->target_id]) }}">
            @csrf
            <div class="field">
                <label for="reverse_revoke_id">{{ __('Type exact Target ID to revoke') }}: <code>{{ $target->target_id }}</code></label>
                <input id="reverse_revoke_id" name="confirm_target_id" required maxlength="64" autocomplete="off">
            </div>
            <div class="field">
                <label for="reverse_revoke_password">{{ __('Current Owner password') }}</label>
                <input id="reverse_revoke_password" type="password" name="current_password" required autocomplete="current-password">
            </div>
            <div class="target-create-actions">
                <button class="button button-danger" type="submit">{{ $managedReverse->state === 'revoked' ? __('Retry host key revocation') : __('Revoke managed Reverse SSH access') }}</button>
            </div>
        </form>
        @endif
    </div>
@endif
