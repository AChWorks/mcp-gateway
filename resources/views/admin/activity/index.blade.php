@extends('admin.layout')

@section('title', __('Activity'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Activity') }}</div>
        <h1>{{ __('Operator activity view') }}</h1>
        <p class="muted">{{ __('Only bounded metadata is shown. Raw MCP payloads and credentials are not stored in this feed.') }}</p>
    </div>
</div>

<section class="panel panel-wide">
    <form class="filter-grid" method="get" action="{{ route('admin.activity') }}">
        <div class="field">
            <label for="site_id">{{ __('Site ID') }}</label>
            <input id="site_id" name="site_id" type="text" maxlength="128" value="{{ $filters['site_id'] ?? '' }}">
        </div>
        <div class="field">
            <label for="operation">{{ __('Operation') }}</label>
            <input id="operation" name="operation" type="text" maxlength="128" value="{{ $filters['operation'] ?? '' }}">
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.activity') }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @if ($feed['items'] === [])
        <p class="empty-state">{{ __('No activity matches these filters.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">{{ __('Time') }}</th>
                    <th scope="col">{{ __('Site') }}</th>
                    <th scope="col">{{ __('Operation') }}</th>
                    <th scope="col">{{ __('Outcome') }}</th>
                    <th scope="col">{{ __('Error') }}</th>
                    <th scope="col">{{ __('Correlation ID') }}</th>
                </tr>
                </thead>
                <tbody>
                @foreach ($feed['items'] as $item)
                    <tr>
                        <td><time datetime="{{ $item['created_at'] }}">{{ $item['created_at'] }}</time></td>
                        <td><code>{{ $item['site_id'] ?? '—' }}</code></td>
                        <td>{{ $item['operation'] }}</td>
                        <td><span class="badge badge-{{ $item['outcome'] === 'success' ? 'success' : 'danger' }}">{{ $item['outcome'] }}</span></td>
                        <td><code>{{ $item['error_code'] ?? '—' }}</code></td>
                        <td><code class="small-code">{{ $item['correlation_id'] }}</code></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
    @endif

    @php
        $baseQuery = array_filter([
            'site_id' => $filters['site_id'] ?? null,
            'operation' => $filters['operation'] ?? null,
        ], static fn ($value) => $value !== null && $value !== '');
    @endphp
    <nav class="pagination" aria-label="{{ __('Activity pages') }}">
        @if ($feed['page'] > 1)
            <a class="button button-secondary" rel="prev" href="{{ route('admin.activity', [...$baseQuery, 'page' => $feed['page'] - 1]) }}">{{ __('Previous') }}</a>
        @else
            <span></span>
        @endif

        <span>{{ __('Page :page', ['page' => $feed['page']]) }}</span>

        @if ($feed['has_more'])
            <a class="button button-secondary" rel="next" href="{{ route('admin.activity', [...$baseQuery, 'page' => $feed['page'] + 1]) }}">{{ __('Next') }}</a>
        @endif
    </nav>
</section>
@endsection
