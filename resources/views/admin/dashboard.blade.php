@extends('admin.layout')

@section('title', __('Dashboard'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Administration') }}</div>
        <h1>{{ __('Gateway dashboard') }}</h1>
        <p class="muted">{{ __('A bounded operational summary. Credentials and MCP payloads are never shown here.') }}</p>
    </div>
    @can('sites.create')
        <a class="button button-primary" href="{{ route('admin.sites.create') }}">{{ __('Add site') }}</a>
    @endcan
</div>

<section class="stats-grid" aria-label="{{ __('Gateway summary') }}">
    <article class="stat-card">
        <span class="stat-value">{{ $siteCount }}</span>
        <span class="stat-label">{{ __('Configured sites') }}</span>
    </article>
    <article class="stat-card">
        <span class="stat-value">{{ $connectedCount }}</span>
        <span class="stat-label">{{ __('Connected') }}</span>
    </article>
    <article class="stat-card">
        <span class="stat-value">{{ $attentionCount }}</span>
        <span class="stat-label">{{ __('Lifecycle attention') }}</span>
    </article>
    <article class="stat-card">
        <span class="stat-value">{{ $staleCount }}</span>
        <span class="stat-label">{{ __('Stale or unknown evidence') }}</span>
    </article>
</section>

<div class="content-grid">
    @can('activity.view')
    <section class="panel panel-wide" aria-labelledby="recent-activity-title">
        <div class="section-heading">
            <div>
                <div class="eyebrow">{{ __('Recent activity') }}</div>
                <h2 id="recent-activity-title">{{ __('Latest routed operations') }}</h2>
            </div>
            <a href="{{ route('admin.activity') }}">{{ __('View all activity') }}</a>
        </div>

        @if ($recentActivity === [])
            <p class="empty-state">{{ __('No routed activity has been recorded yet.') }}</p>
        @else
            <div class="table-wrap">
                <table>
                    <thead>
                    <tr>
                        <th scope="col">{{ __('Time') }}</th>
                        <th scope="col">{{ __('Site') }}</th>
                        <th scope="col">{{ __('Operation') }}</th>
                        <th scope="col">{{ __('Outcome') }}</th>
                    </tr>
                    </thead>
                    <tbody>
                    @foreach ($recentActivity as $item)
                        <tr>
                            <td><time datetime="{{ $item['created_at'] }}">{{ $item['created_at'] }}</time></td>
                            <td><code>{{ $item['site_id'] ?? __('Gateway') }}</code></td>
                            <td>{{ $item['operation'] }}</td>
                            <td><span class="badge badge-{{ $item['outcome'] === 'success' ? 'success' : 'danger' }}">{{ $item['outcome'] }}</span></td>
                        </tr>
                    @endforeach
                    </tbody>
                </table>
            </div>
        @endif
    </section>
    @endcan

    @can('connection.view')
    <aside class="panel" aria-labelledby="gateway-info-title">
        <div class="eyebrow">{{ __('Gateway') }}</div>
        <h2 id="gateway-info-title">{{ __('Connection information') }}</h2>
        <p class="muted">{{ __('Public endpoint and non-secret setup details for the ChatGPT MCP App.') }}</p>
        <p><a href="{{ route('admin.connection') }}">{{ __('View connection information') }}</a></p>
    </aside>
    @endcan
</div>
@endsection
