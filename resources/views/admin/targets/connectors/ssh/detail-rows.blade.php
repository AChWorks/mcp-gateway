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
