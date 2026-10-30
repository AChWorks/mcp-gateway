<span class="target-meta">{{ __('SSH connection last verified; not a live check') }}</span>
@if (! empty($identity['observed_at']))
    <time class="target-meta" datetime="{{ $identity['observed_at'] }}">{{ $identity['observed_at'] }}</time>
@endif
