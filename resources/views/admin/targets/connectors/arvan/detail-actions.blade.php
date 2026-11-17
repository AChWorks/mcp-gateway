@if ($arvanConfig !== null)
    @if ($arvanHasCredential)
        <p class="field-help">{{ __('An encrypted Machine User key is stored. A successful authenticated GET probe confirms only the configured read-only endpoint and key at the time of testing; it does not grant new API permissions or prove every product operation.') }}</p>
        @if ($arvanConfig->probe_path === null)
            <div class="alert alert-info" role="status">
                {{ __('Connection testing needs a known read-only GET probe path. The Target is saved, but its credential has not been verified through this check.') }}
                @can('targets.update', $target)
                    <a href="{{ route('admin.targets.edit', ['target' => $target->target_id, 'section' => 'api-connection']).'#target-connection-settings' }}">{{ __('Set a GET probe in advanced connection settings') }}</a>
                @endcan
            </div>
        @elseif ($target->operations_paused)
            <p class="field-help">{{ __('Resume Target operations above before running a new authenticated connection test.') }}</p>
        @endif

        <div class="filter-actions">
            @if (! $target->operations_paused && $arvanConfig->probe_path !== null)
                @can('targets.test', $target)
                    <form method="post" action="{{ route('admin.targets.test', ['target' => $target->target_id]) }}">
                        @csrf
                        <button class="button button-primary" type="submit">{{ __('Test ArvanCloud API key (read-only GET)') }}</button>
                    </form>
                @endcan
            @endif
        </div>
        @can('targets.disconnect', $target)
            <details class="target-help-details">
                <summary>{{ __('Remove stored API key (advanced)') }}</summary>
                <p class="field-help">{{ __('This permanently deletes the encrypted key stored by this Gateway. It does not revoke the Machine User key in ArvanCloud; revoke that key separately if external access should end. To use this Target again, enter a new key in its connection settings.') }}</p>
                <form method="post" action="{{ route('admin.targets.disconnect', ['target' => $target->target_id]) }}">
                    @csrf
                    <button class="button button-secondary" type="submit">{{ __('Delete Gateway API key') }}</button>
                </form>
            </details>
        @endcan
    @else
        <div class="alert alert-info" role="status">
            {{ __('No Machine User key is stored. This Target cannot make authenticated ArvanCloud requests until a key is entered again.') }}
            @can('targets.update', $target)
                <a href="{{ route('admin.targets.edit', ['target' => $target->target_id, 'section' => 'api-connection']).'#target-connection-settings' }}">{{ __('Open advanced connection settings to add a key') }}</a>
            @endcan
        </div>
    @endif
@else
    <p class="field-help">{{ __('ArvanCloud configuration is unavailable. Review the Target and its diagnostic history before attempting another connection.') }}</p>
@endif
