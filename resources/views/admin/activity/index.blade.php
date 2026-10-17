@extends('admin.layout')

@section('title', __('Activity'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Activity') }}</div>
        <h1>{{ __('Operator activity view') }}</h1>
        <p class="muted">{{ __('Only bounded metadata is shown. Raw MCP payloads and credentials are not stored in this feed.') }}</p>
        <p class="muted">{{ __('Filter by an exact diagnostic reference, then expand the failure for recorded evidence and suggested checks. Older events may have only the error code; detailed stages are never inferred.') }}</p>
    </div>
</div>

<section class="panel panel-wide">
    <form class="filter-grid" method="get" action="{{ route('admin.activity') }}">
        <div class="field">
            <label for="target_id">{{ __('Target ID') }}</label>
            <input id="target_id" name="target_id" type="text" maxlength="64" value="{{ $filters['target_id'] ?? '' }}">
        </div>
        <div class="field">
            <label for="operation">{{ __('Operation') }}</label>
            <input id="operation" name="operation" type="text" maxlength="128" value="{{ $filters['operation'] ?? '' }}">
        </div>
        <div class="field">
            <label for="diagnostic_reference">{{ __('Diagnostic reference') }}</label>
            <input id="diagnostic_reference" name="diagnostic_reference" type="text" maxlength="36" spellcheck="false" value="{{ $filters['diagnostic_reference'] ?? '' }}" placeholder="00000000-0000-0000-0000-000000000000">
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
                    <th scope="col">{{ __('Target') }}</th>
                    <th scope="col">{{ __('Client profile') }}</th>
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
                        <td><code>{{ $item['target_id'] ?? '—' }}</code></td>
                        <td><code>{{ $item['client_profile_key'] ?? '—' }}</code></td>
                        <td>{{ $item['operation'] }}</td>
                        <td><span class="badge badge-{{ $item['outcome'] === 'success' ? 'success' : 'danger' }}">{{ $item['outcome'] }}</span></td>
                        <td>
                            <code>{{ $item['error_code'] ?? '—' }}</code>
                            @if ($item['error_code'] !== null)
                                <details>
                                    <summary>{{ __('Explain error') }}</summary>
                                    <p>{{ \App\Support\OperationDiagnostics::summary($item['error_code']) }}</p>
                                    <p><strong>{{ __('Suggested checks') }}:</strong> {{ \App\Support\OperationDiagnostics::nextStep($item['error_code']) }}</p>
                                    @if ($item['diagnostics'] !== [])
                                        @foreach ($item['diagnostics'] as $field => $value)
                                            <p><strong>{{ __(ucwords(str_replace('_', ' ', $field))) }}:</strong> <code style="white-space: pre-wrap; overflow-wrap: anywhere;">{{ is_bool($value) ? ($value ? 'true' : 'false') : (is_array($value) ? json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) : $value) }}</code></p>
                                        @endforeach
                                    @else
                                        <p class="muted">{{ __('Structured stage details were not retained for this event; do not infer a provider cause.') }}</p>
                                    @endif
                                </details>
                            @endif
                        </td>
                        <td><code class="small-code">{{ $item['correlation_id'] }}</code></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
    @endif

    @php
        $baseQuery = array_filter([
            'target_id' => $filters['target_id'] ?? null,
            'operation' => $filters['operation'] ?? null,
            'diagnostic_reference' => $filters['diagnostic_reference'] ?? null,
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
