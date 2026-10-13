@extends('admin.layout')

@section('title', __('Target details'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Target details') }}</div>
        <h1>{{ $target->display_name }}</h1>
        <p class="muted">{{ __('Local Target identity and non-secret connector information. Credentials are never displayed.') }}</p>
    </div>
    <div class="filter-actions">
        @can('targets.update', $target)
            <a class="button button-secondary" href="{{ route('admin.targets.edit', ['target' => $target->target_id]) }}">{{ __('Edit Target') }}</a>
        @endcan
        <a href="{{ route('admin.targets.index') }}">{{ __('Back to Targets') }}</a>
    </div>
</div>

<section class="panel panel-wide" aria-label="{{ __('Target information') }}">
    <dl class="detail-list">
        <dt>{{ __('Target ID') }}</dt><dd><code>{{ $target->target_id }}</code></dd>
        <dt>{{ __('Connector') }}</dt><dd>{{ $target->connector_type === 'wp_ai_bridge' ? __('WordPress (WP AI Bridge)') : $target->connector_type }} <code class="small-code">{{ $target->connector_type }}</code></dd>
        <dt>{{ __('Connection state') }}</dt><dd>{{ str_replace('_', ' ', ucfirst($target->connection_state->value)) }}</dd>
        <dt>{{ __('Last tested') }}</dt><dd>{{ $target->last_tested_at?->toIso8601String() ?? __('Not yet tested') }}</dd>
        <dt>{{ __('Last error') }}</dt><dd><code>{{ $target->last_error_code ?? __('No recorded error') }}</code></dd>
        @if ($target->last_error_code !== null)
            <dt>{{ __('What happened') }}</dt>
            <dd>{{ \App\Support\OperationDiagnostics::summary($target->last_error_code) }}</dd>
            <dt>{{ __('Suggested checks') }}</dt>
            <dd>{{ \App\Support\OperationDiagnostics::nextStep($target->last_error_code) }}</dd>
        @endif
        <dt>{{ __('Last failure') }}</dt><dd>{{ $target->last_failure_at?->toIso8601String() ?? __('No recorded failure') }}</dd>
        @if ($wpConfig !== null)
            <dt>{{ __('WordPress origin') }}</dt><dd><code class="small-code">{{ $wpConfig->base_url }}</code></dd>
            <dt>{{ __('MCP resource') }}</dt><dd><code class="small-code">{{ $wpConfig->mcp_resource_url }}</code></dd>
            <dt>{{ __('OAuth issuer') }}</dt><dd><code class="small-code">{{ $wpConfig->oauth_issuer_url }}</code></dd>
        @endif
        @if ($sshConfig !== null)
            <dt>{{ __('SSH registered endpoint') }}</dt><dd><code class="small-code">{{ $sshConfig->endpoint()->destinationLabel() }}</code></dd>
            <dt>{{ __('SSH verified address') }}</dt>
            <dd>
                @if ($sshConfig->observed_peer_ip !== null)
                    <code class="small-code">{{ $sshConfig->username.'@'.(str_contains($sshConfig->observed_peer_ip, ':') ? '['.$sshConfig->observed_peer_ip.']' : $sshConfig->observed_peer_ip).':'.$sshConfig->port }}</code>
                    <small>{{ $target->connection_state->value === 'connected' ? __('Last verified, not a live heartbeat') : __('Stale prior verification, not current reachability') }}</small>
                    <small>{{ $sshConfig->observed_at?->toIso8601String() }}</small>
                @else
                    {{ __('IP not yet verified') }}
                @endif
            </dd>
            <dt>{{ __('SSH pinned host key') }}</dt><dd><code class="small-code">{{ $sshFingerprint }}</code></dd>
            <dt>{{ __('Authentication mode') }}</dt><dd>{{ $sshConfig->auth_method === 'private_key' ? __('Private key') : __('Password') }} ({{ __('encrypted and write-only') }})</dd>
        @endif
    </dl>
    @if ($target->connector_type === 'wp_ai_bridge')
        <div class="filter-actions">
            @if (! $hasCredential && ! $revocationPending && ! $refreshPending)
                @can('targets.connect', $target)
                    <form method="post" action="{{ route('admin.targets.connect', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-primary" type="submit">{{ __('Authorize WordPress') }}</button>
                    </form>
                @endcan
            @endif
            @if ($hasCredential && ! $revocationPending && ! $refreshPending)
                @can('targets.reconnect', $target)
                    @can('targets.disconnect', $target)
                        @can('targets.connect', $target)
                            <form method="post" action="{{ route('admin.targets.reconnect', ['target' => $target->target_id]) }}">
                                @csrf
                                <button class="button button-secondary" type="submit">{{ __('Reauthorize') }}</button>
                            </form>
                        @endcan
                    @endcan
                @endcan
            @endif
            @if (($hasCredential || $revocationPending || $target->connection_state->value === 'pending') && ! $refreshPending)
                @can('targets.disconnect', $target)
                    <form method="post" action="{{ route('admin.targets.disconnect', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-secondary" type="submit">{{ __('Disconnect WordPress') }}</button>
                    </form>
                @endcan
            @endif
            @can('targets.test', $target)
                <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}">
                    @csrf
                    <button class="button button-secondary" type="submit">{{ __('Check WordPress metadata') }}</button>
                </form>
            @endcan
        </div>
        @if ($refreshPending)
            <p class="muted" role="status">{{ __('WordPress token refresh could not be confirmed. Credential use, reconnection and disconnection are blocked until the full remote authorization has been invalidated.') }}</p>
            @can('security.manage')
                @can('targets.disconnect', $target)
                    <section class="panel panel-danger" aria-labelledby="refresh-recovery-title">
                        <h3 id="refresh-recovery-title">{{ __('Manual WordPress refresh recovery (Owner only)') }}</h3>
                        <p>{{ __('Before proceeding, sign in as a WordPress administrator on the exact origin above. In WP AI Bridge → OAuth Clients, REMOVE this Gateway client ID from the approved list and SAVE. This changes the shared additional-client approval revision: all other non-ChatGPT OAuth clients on that WordPress site are also invalidated and must reconnect. Keep Gateway unapproved until local recovery finishes. A WordPress logout or revocation of the old refresh token alone is NOT enough.') }}</p>
                        <p>{{ __('Verify the updated WordPress approval list and preserve operator evidence. Wait until every in-flight refresh is finished (at least 75 seconds). Gateway cannot independently verify WordPress revocation: this is your explicit security attestation. If you cannot verify the change or accept the effect on other clients, leave the Target blocked and do not submit.') }}</p>
                        <p>{{ __('Exact Gateway client ID') }}: <code>{{ config('bridge.client.id') }}</code></p>
                        <form class="form-stack" method="post" action="{{ route('admin.targets.reconcile-refresh', ['target' => $target->target_id]) }}">
                            @csrf
                            <input type="hidden" name="intent_id" value="{{ $refreshIntent?->id }}">
                            <label>
                                {{ __('Confirm exact Target ID') }}
                                <input name="confirm_target_id" required maxlength="64" autocomplete="off" placeholder="{{ $target->target_id }}">
                            </label>
                            <label><input type="checkbox" name="wordpress_client_revoked" value="yes" required> {{ __('I personally verified WordPress saved removal of this exact Gateway client from Approved OAuth Clients, invalidating any unknown successor tokens.') }}</label>
                            <label><input type="checkbox" name="other_clients_affected" value="yes" required> {{ __('I accept that this revokes other additional OAuth clients on that WordPress site.') }}</label>
                            <label>
                                {{ __('Your current Gateway password') }}
                                <input type="password" name="current_password" required maxlength="255" autocomplete="current-password">
                            </label>
                            <button type="submit" class="button button-danger">{{ __('Clear local credential after confirmed WordPress revocation') }}</button>
                        </form>
                    </section>
                @endcan
            @endcan
        @elseif ($revocationPending)
            <p class="muted">{{ __('Credential revocation is pending. Retry Disconnect when WordPress is reachable; other operations remain blocked.') }}</p>
        @elseif (! $hasCredential)
            <p class="muted">{{ __('Authorize this Target to connect WordPress securely.') }}</p>
        @endif
    @elseif ($target->connector_type === 'ssh_direct' && $sshConfig !== null)
        @if ($sshHasCredential)
            <p class="muted">{{ __('SSH login credentials are stored locally. You can test the pinned host key and login; commands and SFTP are not yet available.') }}</p>
            <div class="filter-actions">
                @can('targets.test', $target)
                    <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-primary" type="submit">{{ __('Verify SSH host and login') }}</button>
                    </form>
                @endcan
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
    @else
        <p class="muted">{{ __('This connector is not yet available for enrollment.') }}</p>
    @endif
</section>
@can('targets.remove', $target)
<section class="panel panel-danger" aria-labelledby="target-remove-title">
    <h2 id="target-remove-title">{{ __('Remove Target') }}</h2>
    @if ($canRemoveSafely)
        <p class="muted">{{ __('Removing a Target permanently removes its scoped assignments and local connector metadata. Disconnect its connector first. A later Target with the same ID cannot inherit prior permissions.') }}</p>
        <form method="post" action="{{ route('admin.targets.destroy', ['target' => $target->target_id]) }}" class="form-stack">
            @csrf
            @method('DELETE')
            <label>
                <input type="checkbox" name="confirm_remove" value="yes" required>
                {{ __('I understand this permanently removes the registered Target and its assignments.') }}
            </label>
            <div class="filter-actions">
                <button class="button button-danger" type="submit">{{ __('Remove Target') }}</button>
            </div>
        </form>
    @else
        <p class="muted">{{ __('Normal removal requires a completed connector disconnect and resolved credentials. If the remote service is permanently unavailable, the Owner may explicitly forget the Target locally instead.') }}</p>
        @can('security.manage')
            @if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner)
                <div class="target-subsection" aria-labelledby="forget-target-title">
                    <h3 id="forget-target-title">{{ __('Remove locally without remote revocation (Owner only)') }}</h3>
                    <p class="field-help">{{ __('This permanently deletes the Target, encrypted credentials, pending OAuth/refresh/revocation state and Target-specific access assignments from this Gateway. No WordPress or SSH connection is attempted. Existing remote OAuth authorization or Unix-account access may remain valid, and remote in-flight operations cannot be undone. Revoke access separately at the remote service when possible.') }}</p>
                    <form method="post" action="{{ route('admin.targets.forget', ['target' => $target->target_id]) }}" class="form-stack">
                        @csrf
                        @method('DELETE')
                        <div class="field">
                            <label for="forget_target_id">{{ __('Type the exact Target ID to permanently remove locally:') }} <code>{{ $target->target_id }}</code></label>
                            <input id="forget_target_id" name="confirm_target_id" type="text" maxlength="64" required autocomplete="off" spellcheck="false">
                            @error('confirm_target_id')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                        </div>
                        <label class="target-trust-confirmation">
                            <input type="checkbox" name="confirm_local_only" value="yes" required>
                            <span>{{ __('I understand this permanently erases the local Target and its credentials and assignments.') }}</span>
                        </label>
                        @error('confirm_local_only')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                        <label class="target-trust-confirmation">
                            <input type="checkbox" name="confirm_remote_revocation_unknown" value="yes" required>
                            <span>{{ __('I understand WordPress OAuth or remote SSH access is NOT revoked or verified by this action.') }}</span>
                        </label>
                        @error('confirm_remote_revocation_unknown')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                        <div class="field">
                            <label for="forget_owner_password">{{ __('Current Owner password') }}</label>
                            <input id="forget_owner_password" name="current_password" type="password" required maxlength="255" autocomplete="current-password">
                            @error('current_password')<p class="form-error" role="alert">{{ $message }}</p>@enderror
                        </div>
                        <div class="filter-actions">
                            <button class="button button-danger" type="submit">{{ __('Permanently remove Target locally') }}</button>
                        </div>
                    </form>
                </div>
            @endif
        @endcan
    @endif
    @error('target')
        <p class="form-error" role="alert">{{ $message }}</p>
    @enderror
</section>
@endcan

@endsection
