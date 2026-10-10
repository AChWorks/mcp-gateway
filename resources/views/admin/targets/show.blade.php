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
        <dt>{{ __('Last error') }}</dt><dd>{{ $target->last_error_code ?? __('No recorded error') }}</dd>
        <dt>{{ __('Last failure') }}</dt><dd>{{ $target->last_failure_at?->toIso8601String() ?? __('No recorded failure') }}</dd>
        @if ($wpConfig !== null)
            <dt>{{ __('WordPress origin') }}</dt><dd><code class="small-code">{{ $wpConfig->base_url }}</code></dd>
            <dt>{{ __('MCP resource') }}</dt><dd><code class="small-code">{{ $wpConfig->mcp_resource_url }}</code></dd>
            <dt>{{ __('OAuth issuer') }}</dt><dd><code class="small-code">{{ $wpConfig->oauth_issuer_url }}</code></dd>
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
    @else
        <p class="muted">{{ __('This connector is not yet available for enrollment.') }}</p>
    @endif
</section>
@can('targets.remove', $target)
<section class="panel panel-danger" aria-labelledby="target-remove-title">
    <h2 id="target-remove-title">{{ __('Remove Target') }}</h2>
    @if ($canRemoveSafely)
        <p class="muted">{{ __('Removing a Target permanently removes its scoped assignments and local connector metadata. Disconnect WordPress first. The immutable Target ID cannot be reused to inherit prior permissions.') }}</p>
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
        <p class="muted">{{ __('Disconnect and complete or revoke any pending WordPress authorization before the Target can be removed safely.') }}</p>
    @endif
    @error('target')
        <p class="form-error" role="alert">{{ $message }}</p>
    @enderror
</section>
@endcan

@endsection
