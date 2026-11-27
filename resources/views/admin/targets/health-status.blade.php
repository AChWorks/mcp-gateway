@if ($health['route_unavailable'])
    <span class="target-meta target-status-attention"><strong>{{ __('Route unavailable') }}</strong></span>
    <span class="target-meta">{{ __('Selected route is unavailable; stored authorization is unchanged. Restore the route or select another permitted route.') }}</span>
@endif
@foreach ($health['checks'] as $check)
    @if (!($reviewOnly ?? false) || $check['tone'] === 'warning')
        <div class="target-meta">
            <strong>{{ $check['kind'] }}:</strong>
            <span class="{{ $check['tone'] === 'warning' ? 'target-status-attention' : '' }}">{{ $check['label'] }}</span>
            @if ($check['time'] !== null)
                <span>{{ $check['time'] }} — {{ __('Recorded observation, not a live heartbeat') }}</span>
            @endif
            @if ($check['error'] !== null)
                <code>{{ $check['error'] }}</code>
            @endif
            @if ($check['history'] !== null)
                <span>{{ $check['history'] }}</span>
            @endif
        </div>
    @endif
@endforeach
