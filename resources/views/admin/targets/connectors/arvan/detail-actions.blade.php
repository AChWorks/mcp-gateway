@php
    // Mirrors the two independent gates in TargetConfigurationController.
    $canConfigureArvan = \Illuminate\Support\Facades\Gate::allows('targets.update', $target)
        && \Illuminate\Support\Facades\Gate::allows('security.manage');
@endphp
@if ($arvanConfig !== null)
    @if ($arvanHasCredential)
        <p class="field-help">{{ __('The Machine User key is stored securely. Recorded connection state reflects the last successful configured authenticated GET check, not whether other permitted API requests can succeed. Changing the API root, key or probe resets that verification.') }}</p>
    @else
        <div class="alert alert-info" role="status">
            {{ __('No Machine User key is stored. Only the public HTTPS endpoint can be checked; authenticated API requests need a key.') }}
            @if ($canConfigureArvan)
                <a href="{{ route('admin.targets.edit', ['target' => $target->target_id, 'section' => 'api-connection']).'#target-connection-settings' }}">{{ __('Open advanced connection settings to add a key') }}</a>
            @else
                {{ __('Ask a Gateway Owner to add a Machine User API key in advanced connection settings. You cannot replace this credential yourself.') }}
            @endif
        </div>
    @endif

    @if ($arvanHasCredential && $arvanConfig->probe_path === null)
        <div class="alert alert-info" role="status">
            {{ __('The authenticated GET probe is optional and not configured. API requests may still succeed, but the saved API key cannot be verified by this connection test. Use the endpoint check below without a key or configure a known read-only GET endpoint.') }}
            @if ($canConfigureArvan)
                <a href="{{ route('admin.targets.edit', ['target' => $target->target_id, 'section' => 'api-connection']).'#target-connection-settings' }}">{{ __('Set a GET probe in advanced connection settings') }}</a>
            @else
                {{ __('Ask a Gateway Owner to configure a read-only GET probe for this Target. You cannot change its API connection settings.') }}
            @endif
        </div>
    @endif

    @can('targets.test', $target)
        <div class="target-subsection" aria-labelledby="arvan-connection-check-title">
            <h3 id="arvan-connection-check-title">{{ __('Connection checks') }}</h3>
            <p class="field-help" id="arvan-endpoint-check-help">{{ __('HTTPS endpoint check sends only HEAD to the registered API base without an API key. An HTTP response shows reachability, not authentication, and never changes the recorded connection state.') }}</p>
            <div class="filter-actions">
                <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}" aria-describedby="arvan-endpoint-check-help">
                    @csrf
                    <input type="hidden" name="arvan_check" value="endpoint">
                    <button class="button button-secondary" type="submit" @disabled($target->operations_paused)>{{ __('Check HTTPS endpoint (no API key)') }}</button>
                </form>
                @if ($arvanHasCredential && $arvanConfig->probe_path !== null)
                    <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}" aria-describedby="arvan-verified-check-help">
                        @csrf
                        <input type="hidden" name="arvan_check" value="authenticated">
                        <button class="button button-primary" type="submit" @disabled($target->operations_paused)>{{ __('Verify API key (read-only GET)') }}</button>
                    </form>
                @endif
            </div>
            @if ($target->operations_paused)
                <p class="field-help" role="status">{{ __('Resume Target operations above before running either connection check. Both actions are disabled while paused.') }}</p>
            @elseif ($arvanHasCredential && $arvanConfig->probe_path !== null)
                <p class="field-help" id="arvan-verified-check-help">{{ __('The second action makes only one authenticated GET to the configured read-only probe. Its success verifies that request and stored key at test time; it does not grant permissions for other API operations.') }}</p>
            @endif
        </div>
    @endcan

    @if ($arvanHasCredential)
        @can('targets.disconnect', $target)
            <details class="target-help-details">
                <summary>{{ __('Remove stored API key (advanced)') }}</summary>
                <p class="field-help">
                    {{ __('This permanently deletes the encrypted key stored by this Gateway. It does not revoke the Machine User key in ArvanCloud; revoke that key separately if external access should end.') }}
                    @if ($canConfigureArvan)
                        {{ __('To use this Target again, enter a new key in its connection settings.') }}
                    @else
                        {{ __('A Gateway Owner must add a new key before this Target can be used again. Contact an Owner after deleting the local key.') }}
                    @endif
                </p>
                <form method="post" action="{{ route('admin.targets.disconnect', ['target' => $target->target_id]) }}">
                    @csrf
                    <button class="button button-secondary" type="submit">{{ __('Delete Gateway API key') }}</button>
                </form>
            </details>
        @endcan
    @endif
@else
    <p class="field-help">{{ __('ArvanCloud configuration is unavailable. Review the Target and its diagnostic history before attempting another connection.') }}</p>
@endif
