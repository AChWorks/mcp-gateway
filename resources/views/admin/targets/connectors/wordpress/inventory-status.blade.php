<span class="target-meta target-auth-status {{ $recovery['tone'] === 'caution' || ! $recovery['credential_present'] ? 'target-status-attention' : '' }}">
    <strong>{{ __('OAuth') }}:</strong> {{ $recovery['title'] }}
</span>
@if ($recovery['canFinish'])
    <span class="target-meta">{{ __('Safe completion available — inspect Target') }}</span>
@endif
