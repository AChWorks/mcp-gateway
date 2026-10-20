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

<section class="panel panel-wide" aria-labelledby="target-operations-title">
    <h2 id="target-operations-title">{{ __('Gateway operations') }}</h2>
    <p role="status"><strong>{{ $target->operations_paused ? __('Paused') : __('Enabled') }}</strong>
        — {{ $target->operations_paused
            ? __('New Gateway operations against this Target are blocked. Stored connection, credentials, grants and existing remote Jobs are preserved; running Jobs are not stopped.')
            : __('This Target can accept new authorized Gateway operations. Connection status is shown separately below.') }}
    </p>
    @if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner)
        <form method="post" action="{{ route('admin.targets.operations.update', ['target' => $target->target_id]) }}">
            @csrf
            <input type="hidden" name="state" value="{{ $target->operations_paused ? 'enabled' : 'paused' }}">
            <button class="button {{ $target->operations_paused ? 'button-primary' : 'button-secondary' }}" type="submit">
                {{ $target->operations_paused ? __('Resume Target operations') : __('Pause Target operations') }}
            </button>
        </form>
    @endif
    <p class="field-help">{{ __('Pausing does not revoke WordPress authorization or SSH credentials. Explicit administrative credential recovery and local inventory remain available.') }}</p>
    @if ($target->ai_guidance !== null && $target->ai_guidance !== '')
        <div class="target-subsection" aria-label="{{ __('AI guidance') }}">
            <h3>{{ __('AI guidance') }}</h3>
            <p class="target-ai-guidance-text">{{ $target->ai_guidance }}</p>
            <p class="field-help">{{ __('A contextual note for AI clients. It does not grant access or require confirmation.') }}</p>
        </div>
    @endif
</section>

@if ($target->connector_type === 'wp_ai_bridge' && ! $target->operations_paused)
    @can('wordpress.abilities.execute.readonly', $target)
        <section class="panel panel-wide" aria-labelledby="wordpress-bridge-info-title">
            <h2 id="wordpress-bridge-info-title">{{ __('WordPress operations') }}</h2>
            <p class="field-help">{{ __('First shared Admin/AI operation: inspect the selected WordPress Bridge without granting mutating, destructive or unclassified ability execution.') }}</p>
            <form method="post" action="{{ route('admin.targets.wordpress.bridge-info', ['target' => $target->target_id]) }}">
                @csrf
                <button class="button button-secondary" type="submit">{{ __('Inspect Bridge information (read-only)') }}</button>
            </form>
        </section>
    @endcan
@endif

<section class="panel panel-wide target-recovery-panel" aria-labelledby="target-recovery-title">
    <div class="section-heading">
        <div>
            <div class="eyebrow">{{ __('Connection and recovery') }}</div>
            <h2 id="target-recovery-title">{{ $recovery['title'] }}</h2>
        </div>
        @if ($target->connector_type === 'wp_ai_bridge')
            <span class="badge badge-{{ ! $revocationPending && ! $refreshPending && $hasCredential && $target->connection_state === \App\Domain\Targets\TargetConnectionState::Connected ? 'success' : 'neutral' }}">{{ $revocationPending || $refreshPending ? __('Action required') : __('Status') }}</span>
        @endif
    </div>
    <p class="target-recovery-intro" role="status">{{ $recovery['description'] }}</p>
    <dl class="target-recovery-grid">
        <div><dt>{{ $target->connector_type === 'wp_ai_bridge' ? __('WordPress reachability') : __('Reachability evidence') }}</dt><dd>{{ $recovery['reachability'] }}</dd></div>
        <div><dt>{{ __('Authorization') }}</dt><dd>{{ $recovery['authorization'] }}</dd></div>
        <div><dt>{{ __('Ongoing operation') }}</dt><dd>{{ $recovery['operation'] }}</dd></div>
    </dl>
    @if ($recovery['history'] !== null)
        <p class="target-recovery-history"><strong>{{ __('Diagnostic history') }}:</strong> {{ $recovery['history'] }}</p>
    @endif

    @if ($target->connector_type === 'wp_ai_bridge')
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
                                        <p>{{ __('This option is offered only because the stored revoke attempt is proven never dispatched and zero token revocations were acknowledged. Gateway must also confirm that the existing access token still works with an authenticated WordPress catalog request. Metadata alone is not enough. If verification fails, the Target stays blocked.') }}</p>
                                        <form class="form-stack" method="post" action="{{ route('admin.targets.cancel-disconnect', ['target' => $target->target_id]) }}">
                                            @csrf
                                            <input type="hidden" name="intent_id" value="{{ $revocationIntent->id }}">
                                            <label>{{ __('Type exact Target ID') }}
                                                <input name="confirm_target_id" required maxlength="64" autocomplete="off" placeholder="{{ $target->target_id }}">
                                            </label>
                                            <label>{{ __('Your current Gateway password') }}
                                                <input type="password" name="current_password" required maxlength="255" autocomplete="current-password">
                                            </label>
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
                                    <p>{{ __('Sign in to the exact WordPress origin below. In WP AI Bridge → OAuth Clients, REMOVE this Gateway client from Approved OAuth Clients and SAVE. This invalidates unknown token successors but also revokes other non-ChatGPT OAuth clients for that WordPress site. WordPress logout or revoking one old token is insufficient.') }}</p>
                                    <p>{{ __('Verify the change and retain evidence. Do not proceed while any operation could still be in flight. The Gateway does not independently verify your WordPress-side revocation; the action below only clears its local credential after your explicit attestation.') }}</p>
                                    <p>{{ __('Gateway OAuth client ID') }}: <code class="small-code">{{ config('bridge.client.id') }}</code></p>
                                    <form class="form-stack" method="post" action="{{ route('admin.targets.reconcile-disconnect', ['target' => $target->target_id]) }}">
                                        @csrf
                                        <input type="hidden" name="intent_id" value="{{ $revocationIntent->id }}">
                                        <label>{{ __('Type exact Target ID') }}
                                            <input name="confirm_target_id" required maxlength="64" autocomplete="off" placeholder="{{ $target->target_id }}">
                                        </label>
                                        <label><input type="checkbox" name="wordpress_client_revoked" value="yes" required>
                                            {{ __('I verified WordPress saved removal of this exact Gateway OAuth client, invalidating all possible successor tokens.') }}
                                        </label>
                                        <label><input type="checkbox" name="other_clients_affected" value="yes" required>
                                            {{ __('I understand this also revokes other additional OAuth clients on the WordPress site.') }}
                                        </label>
                                        <label>{{ __('Your current Gateway password') }}
                                            <input type="password" name="current_password" required maxlength="255" autocomplete="current-password">
                                        </label>
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
    @endif
</section>

<section class="panel panel-wide" aria-label="{{ __('Target information') }}">
    <dl class="detail-list">
        <dt>{{ __('Target ID') }}</dt><dd><code>{{ $target->target_id }}</code></dd>
        <dt>{{ __('Connector') }}</dt><dd>{{ $target->connector_type === 'wp_ai_bridge' ? __('WordPress (WP AI Bridge)') : $target->connector_type }} <code class="small-code">{{ $target->connector_type }}</code></dd>
        <dt>{{ __('Connection state') }}</dt><dd>{{ str_replace('_', ' ', ucfirst($target->connection_state->value)) }}</dd>
        <dt>{{ __('Last tested') }}</dt><dd>{{ $target->last_tested_at?->toIso8601String() ?? __('Not yet tested') }}</dd>
        <dt>{{ __('Recorded diagnostic (may be historical)') }}</dt><dd><code>{{ $target->last_error_code ?? __('No recorded error') }}</code></dd>
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
            <p class="muted">{{ __('Credential revocation is pending. Use the guided recovery options above. Other authenticated WordPress operations remain blocked until a safe outcome is confirmed.') }}</p>
        @elseif (! $hasCredential)
            <p class="muted">{{ __('Authorize this Target to connect WordPress securely.') }}</p>
        @endif
    @elseif ($target->connector_type === 'ssh_direct' && $sshConfig !== null)
        @if ($sshHasCredential)
            <p class="muted">{{ __('SSH login credentials are stored locally. You can test the pinned host key and login; commands and SFTP are not yet available.') }}</p>
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
    @else
        <p class="muted">{{ __('This connector is not yet available for enrollment.') }}</p>
    @endif
</section>
@if ($target->connector_type === 'ssh_direct' && $sshHasCredential)
    @canany(['ssh.file.read', 'ssh.file.write'], $target)
        <section class="panel panel-wide" aria-labelledby="ssh-browser-file-title">
            <div class="section-heading">
                <div>
                    <div class="eyebrow">{{ __('Authenticated browser file handoff') }}</div>
                    <h2 id="ssh-browser-file-title">{{ __('SSH file upload and download') }}</h2>
                </div>
            </div>
            @if ($target->operations_paused)
                <p class="muted">{{ __('SSH browser upload and download are unavailable while this Target is paused.') }}</p>
            @elseif (config('ssh.file_transfer.enabled', false) === true)
                <p class="muted">{{ __('Select an actual local file in this browser for an SSH Target. ChatGPT message attachments do not automatically reach MCP tools. Remote file limits and SSH OS-account permissions still apply.') }}</p>
                @if ($errors->has('file_exchange'))
                    <p class="target-recovery-warning" role="alert">{{ $errors->first('file_exchange') }}</p>
                @endif
                @can('ssh.file.write', $target)
                    <form method="post" enctype="multipart/form-data" class="form-stack" action="{{ route('admin.targets.ssh-files.upload', ['target' => $target->target_id]) }}">
                        @csrf
                        <h3>{{ __('Upload local file to SSH Target') }}</h3>
                        <label>{{ __('Choose a local file') }}
                            <input type="file" name="local_file" required>
                        </label>
                        <label>{{ __('Absolute remote destination path') }}
                            <input name="destination" type="text" required maxlength="1024" autocomplete="off" placeholder="/home/account/uploads/document.bin">
                        </label>
                        <label>{{ __('Pre-created private remote staging directory (0700)') }}
                            <input name="private_staging_dir" type="text" required maxlength="1024" autocomplete="off" placeholder="/home/account/.gateway-private-transfer">
                        </label>
                        <p class="field-help">{{ __('Create this private directory in advance under the authenticated remote SSH account and verify mode 0700. No file data is sent if staging is missing or unsafe. Large uploads require sufficient PHP and proxy body limits.') }}</p>
                        <label><input type="checkbox" name="overwrite" value="1"> {{ __('Allow atomic replacement if destination already exists (last writer wins)') }}</label>
                        <button type="submit" class="button button-primary">{{ __('Upload and verify SHA-256') }}</button>
                    </form>
                @endcan
                @can('ssh.file.read', $target)
                    <form method="post" class="form-stack" action="{{ route('admin.targets.ssh-files.download', ['target' => $target->target_id]) }}">
                        @csrf
                        <h3>{{ __('Download SSH file to this browser') }}</h3>
                        <label>{{ __('Absolute remote source path') }}
                            <input type="text" name="path" required maxlength="1024" autocomplete="off" placeholder="/home/account/reports/report.zip">
                        </label>
                        <button type="submit" class="button button-secondary">{{ __('Download verified file') }}</button>
                    </form>
                @endcan
                <p class="field-help">{{ __('Downloads are forced as attachments with content sniffing disabled; verify reported size and SHA-256. Interrupted transfers are not resumable. Failed writes must be inspected before retry.') }}</p>
            @else
                <p class="muted">{{ __('Whole-file browser exchange is disabled on this Gateway. It requires an explicitly approved SSH_FILE_TRANSFER_ENABLED deployment change; bounded SFTP tools remain independent.') }}</p>
            @endif
        </section>
    @endcanany
@endif

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
