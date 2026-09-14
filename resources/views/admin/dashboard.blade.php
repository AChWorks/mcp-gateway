@extends('admin.layout')

@section('title', __('Administration'))

@section('content')
<section class="panel" aria-labelledby="dashboard-title">
    <div class="eyebrow">{{ __('Administration') }}</div>
    <h1 id="dashboard-title">{{ __('Gateway administration') }}</h1>
    <p>{{ __('Your administrator session is active.') }}</p>

    <dl class="summary-list">
        <div>
            <dt>{{ __('Signed in as') }}</dt>
            <dd>{{ auth()->user()->email }}</dd>
        </div>
        <div>
            <dt>{{ __('Gateway MCP endpoint') }}</dt>
            <dd><code>{{ config('oauth.resource') }}</code></dd>
        </div>
    </dl>

    <p><a href="{{ route('admin.connection') }}">{{ __('View connection information') }}</a></p>
</section>
@endsection
