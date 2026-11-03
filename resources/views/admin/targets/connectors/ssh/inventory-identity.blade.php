@if ($identity !== null)
    <code class="small-code target-meta">{{ $identity['destination_label'] }}</code>
    <span class="target-meta">{{ __('SSH IP status') }}: {{ str_replace('_', ' ', $identity['ip_status']) }}</span>
    @if ($identity['route_mode'] === 'reverse')
        <span class="target-meta">{{ __('Reverse SSH (NL loopback)') }}: 127.0.0.1:{{ $identity['reverse_listener_port'] }}</span>
    @endif
@endif
