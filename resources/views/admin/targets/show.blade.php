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

<section class="panel panel-wide target-recovery-panel" aria-labelledby="target-recovery-title">
    <div class="section-heading">
        <div>
            <div class="eyebrow">{{ __('Connection and recovery') }}</div>
            <h2 id="target-recovery-title">{{ $recovery['title'] }}</h2>
        </div>
        <span class="badge badge-{{ $recovery['tone'] === 'caution' ? 'warning' : 'neutral' }}">{{ $recovery['tone'] === 'caution' ? __('Action required') : __('Status') }}</span>
    </div>
    <p class="target-recovery-intro" role="status">{{ $recovery['description'] }}</p>
    <dl class="target-recovery-grid">
        <div><dt>{{ __('Reachability evidence') }}</dt><dd>{{ $recovery['reachability'] }}</dd></div>
        <div><dt>{{ __('Authorization') }}</dt><dd>{{ $recovery['authorization'] }}</dd></div>
        <div><dt>{{ __('Ongoing operation') }}</dt><dd>{{ $recovery['operation'] }}</dd></div>
    </dl>
    @if ($recovery['history'] !== null)
        <p class="target-recovery-history"><strong>{{ __('Diagnostic history') }}:</strong> {{ $recovery['history'] }}</p>
    @endif

    @if ($connectorUi?->recoveryActionsView !== null)
        @include($connectorUi->recoveryActionsView)
    @endif
</section>

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
    <p class="field-help">{{ __('Pausing does not revoke connector authorization or delete stored credentials. Explicit administrative credential recovery and local inventory remain available.') }}</p>
    @if ($target->ai_guidance !== null && $target->ai_guidance !== '')
        <div class="target-subsection" aria-label="{{ __('AI guidance') }}">
            <h3>{{ __('AI guidance') }}</h3>
            <p class="target-ai-guidance-text">{{ $target->ai_guidance }}</p>
            <p class="field-help">{{ __('A contextual note for AI clients. It does not grant access or require confirmation.') }}</p>
        </div>
    @endif
</section>

@if ($connectorUi?->operationsView !== null && ! $target->operations_paused)
    @include($connectorUi->operationsView)
@endif

<section class="panel panel-wide" aria-label="{{ __('Target information') }}">
    <dl class="detail-list">
        <dt>{{ __('Target ID') }}</dt><dd><code>{{ $target->target_id }}</code></dd>
        <dt>{{ __('Connector') }}</dt><dd>{{ $connectorUi?->label ?? __('Unsupported connector') }} <code class="small-code">{{ $target->connector_type }}</code></dd>
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
        @if ($connectorUi?->detailRowsView !== null)
            @include($connectorUi->detailRowsView)
        @endif
    </dl>
    @if ($connectorUi?->detailActionsView !== null)
        @include($connectorUi->detailActionsView)
    @else
        <p class="muted">{{ __('This connector is not yet available for enrollment. Its stored record does not establish supported authentication or operation semantics.') }}</p>
    @endif
</section>
@if ($connectorUi?->extraView !== null)
    @include($connectorUi->extraView)
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
                    <p class="field-help">{{ __('This permanently deletes the Target, encrypted credentials, pending OAuth/refresh/revocation state and Target-specific access assignments from this Gateway. No remote connection or revocation is attempted. Existing remote OAuth authorization or Unix-account access may remain valid, and remote in-flight operations cannot be undone. Revoke access separately at the remote service when possible.') }}</p>
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
                            <span>{{ __('I understand remote authorization or access is NOT revoked or verified by this action.') }}</span>
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
