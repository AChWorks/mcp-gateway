@if ($sshConfig !== null)
    <dt>{{ __('SSH registered endpoint') }}</dt><dd><code class="small-code">{{ $sshConfig->endpoint()->destinationLabel() }}</code></dd>
    <dt>{{ __('SSH route') }}</dt>
    <dd>
        @if (($sshConfig->route_mode ?? 'direct') === 'reverse')
            {{ __('Owner-approved Reverse SSH') }} — <code class="small-code">127.0.0.1:{{ $sshConfig->reverse_listener_port }}</code>
            <small>{{ __('Gateway host loopback forward; tunnel identity:') }} {{ $sshConfig->reverse_tunnel_identity }}</small>
            <small>{{ __('This local address is NOT the Target server IP. The server host-key pin is verified across the forward.') }}</small>
        @else
            {{ __('Direct public SSH TCP') }}
        @endif
    </dd>
    <dt>{{ __('SSH verified address') }}</dt>
    <dd>
        @if ($sshConfig->observed_peer_ip !== null)
            <code class="small-code">{{ $sshConfig->username.'@'.(str_contains($sshConfig->observed_peer_ip, ':') ? '['.$sshConfig->observed_peer_ip.']' : $sshConfig->observed_peer_ip).':'.$sshConfig->port }}</code>
            <small>{{ $target->connection_state->value === 'connected' ? __('Last verified, not a live heartbeat') : __('Stale prior verification, not current reachability') }}</small>
            <small>{{ $sshConfig->observed_at?->toIso8601String() }}</small>
        @elseif (($sshConfig->route_mode ?? 'direct') === 'reverse' && $sshConfig->observed_at !== null)
            {{ __('Remote host-key pin and login verified across the approved local reverse listener; remote IP not independently observed.') }}
            <small>{{ $sshConfig->observed_at?->toIso8601String() }} — {{ __('Last verified, not a live heartbeat') }}</small>
        @else
            {{ __('IP not yet verified') }}
        @endif
    </dd>
    <dt>{{ __('SSH pinned host key') }}</dt><dd><code class="small-code">{{ $sshFingerprint }}</code></dd>
    <dt>{{ __('Authentication mode') }}</dt><dd>{{ $sshConfig->auth_method === 'private_key' ? __('Private key') : __('Password') }} ({{ __('encrypted and write-only') }})</dd>
@endif
