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
