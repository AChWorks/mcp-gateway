@if (! empty($identity['observed_at']))
    <span class="target-meta">{{ __('SSH connection verification recorded; not a live check') }}</span>
    <time class="target-meta" datetime="{{ $identity['observed_at'] }}">{{ $identity['observed_at'] }}</time>
@else
    <span class="target-meta">{{ __('No recorded SSH connection verification') }}</span>
@endif
