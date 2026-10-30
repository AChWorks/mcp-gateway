@if ($identity !== null)
    <code class="small-code target-meta">{{ $identity['destination_label'] }}</code>
    <span class="target-meta">{{ __('SSH IP status') }}: {{ str_replace('_', ' ', $identity['ip_status']) }}</span>
@endif
