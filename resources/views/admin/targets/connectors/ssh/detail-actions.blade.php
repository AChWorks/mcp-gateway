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

@if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner
    && \App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment::query()
        ->where('target_record_id', $target->getKey())->where('state', '!=', 'revoked')->exists())
    <div class="target-subsection">
        <h3>{{ __('Revoke managed Reverse SSH') }}</h3>
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
                <button class="button button-danger" type="submit">{{ __('Revoke managed Reverse SSH access') }}</button>
            </div>
        </form>
    </div>
@endif
