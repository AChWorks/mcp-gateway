@php
    // Mirrors the two independent gates in TargetConfigurationController.
    $canConfigureArvan = \Illuminate\Support\Facades\Gate::allows('targets.update', $target)
        && \Illuminate\Support\Facades\Gate::allows('security.manage');
@endphp
@if ($arvanConfig !== null)
    @if ($arvanHasCredential)
        <p class="field-help">{{ __('An encrypted Machine User key is stored. A successful authenticated GET probe confirms only the configured read-only endpoint and key at the time of testing; it does not grant new API permissions or prove every product operation.') }}</p>
        @if ($arvanConfig->probe_path === null)
            <div class="alert alert-info" role="status">
                {{ __('Connection testing needs a known read-only GET probe path. The Target is saved, but its credential has not been verified through this check.') }}
                @if ($canConfigureArvan)
                    <a href="{{ route('admin.targets.edit', ['target' => $target->target_id, 'section' => 'api-connection']).'#target-connection-settings' }}">{{ __('Set a GET probe in advanced connection settings') }}</a>
                @else
                    {{ __('Ask a Gateway Owner to configure a read-only GET probe for this Target. You cannot change its API connection settings.') }}
                @endif
            </div>
        @elseif ($target->operations_paused)
            <p class="field-help">{{ __('Resume Target operations above before running a new authenticated connection test.') }}</p>
        @endif

        @if (! $target->operations_paused && $arvanConfig->probe_path !== null)
            @can('targets.test', $target)
                <div class="filter-actions">
                    <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-primary" type="submit">{{ __('Test ArvanCloud API key (read-only GET)') }}</button>
                    </form>
                </div>
            @endcan
        @endif
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
    @else
        <div class="alert alert-info" role="status">
            {{ __('No Machine User key is stored. This Target cannot make authenticated ArvanCloud requests until a key is entered again.') }}
            @if ($canConfigureArvan)
                <a href="{{ route('admin.targets.edit', ['target' => $target->target_id, 'section' => 'api-connection']).'#target-connection-settings' }}">{{ __('Open advanced connection settings to add a key') }}</a>
            @else
                {{ __('Ask a Gateway Owner to add a Machine User API key in advanced connection settings. You cannot replace this credential yourself.') }}
            @endif
        </div>
    @endif
@else
    <p class="field-help">{{ __('ArvanCloud configuration is unavailable. Review the Target and its diagnostic history before attempting another connection.') }}</p>
@endif
