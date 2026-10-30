@extends('admin.layout')

@section('title', __('Activity'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Activity') }}</div>
        <h1>{{ __('Operator activity view') }}</h1>
        <p class="muted reading-width">{{ __('Only bounded metadata is shown. Raw MCP payloads and credentials are not stored in this feed.') }}</p>
        <p class="muted reading-width">{{ __('Filter by an exact diagnostic reference, then expand the failure for recorded evidence and suggested checks. Older events may have only the error code; detailed stages are never inferred.') }}</p>
    </div>
</div>

<section class="panel panel-wide">
    <form class="filter-grid" method="get" action="{{ route('admin.activity') }}">
        <div class="field">
            <label for="target_id">{{ __('Target ID') }}</label>
            <input id="target_id" name="target_id" type="text" maxlength="64" value="{{ $filters['target_id'] ?? '' }}" @error('target_id') aria-invalid="true" aria-describedby="target_id-error" @enderror>
                @error('target_id')<p class="field-error" id="target_id-error" role="alert">{{ $message }}</p>@enderror
            </div>
        <div class="field">
            <label for="operation">{{ __('Operation') }}</label>
            <input id="operation" name="operation" type="text" maxlength="128" value="{{ $filters['operation'] ?? '' }}" @error('operation') aria-invalid="true" aria-describedby="operation-error" @enderror>
                @error('operation')<p class="field-error" id="operation-error" role="alert">{{ $message }}</p>@enderror
            </div>
        <div class="field">
            <label for="diagnostic_reference">{{ __('Diagnostic reference') }}</label>
            <input id="diagnostic_reference" name="diagnostic_reference" type="text" maxlength="36" spellcheck="false" value="{{ $filters['diagnostic_reference'] ?? '' }}" placeholder="00000000-0000-0000-0000-000000000000" @error('diagnostic_reference') aria-invalid="true" aria-describedby="diagnostic_reference-error" @enderror>
                @error('diagnostic_reference')<p class="field-error" id="diagnostic_reference-error" role="alert">{{ $message }}</p>@enderror
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
                        <td><code dir="ltr">{{ $item['target_id'] ?? '—' }}</code></td>
                        <td><code dir="ltr">{{ $item['client_profile_key'] ?? '—' }}</code></td>
                        <td>{{ $item['operation'] }}</td>
                        <td>
                            @php
                                $outcomeTone = match ($item['outcome']) {
                                    'success' => 'success',
                                    'failure' => 'danger',
                                    default => 'warning',
                                };
                                $outcomeLabel = match ($item['outcome']) {
                                    'success' => __('Succeeded'),
                                    'failure' => __('Failed'),
                                    'unknown' => __('Unknown outcome'),
                                    default => $item['outcome'],
                                };
                            @endphp
                            <span class="badge badge-{{ $outcomeTone }}">{{ $outcomeLabel }}</span>
                            @if ($item['outcome'] === 'unknown')
                                <p class="field-help">{{ __('The effect could not be confirmed. Check the recorded evidence before retrying.') }}</p>
                            @endif
                        </td>
                        <td>
                            <code dir="ltr">{{ $item['error_code'] ?? '—' }}</code>
                            @if ($item['error_code'] !== null)
                                <details>
                                    <summary>{{ __('Explain error') }}</summary>
                                    <p>{{ \App\Support\OperationDiagnostics::summary($item['error_code']) }}</p>
                                    <p><strong>{{ __('Suggested checks') }}:</strong> {{ \App\Support\OperationDiagnostics::nextStep($item['error_code']) }}</p>
                                    @if ($item['diagnostics'] !== [])
                                        @foreach ($item['diagnostics'] as $field => $value)
                                            <div>
                                                <p><strong>{{ __(ucwords(str_replace('_', ' ', $field))) }}:</strong></p>
                                                <pre class="operation-result-preview" dir="ltr"><code>{{ is_bool($value) ? ($value ? 'true' : 'false') : (is_array($value) ? json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) : $value) }}</code></pre>
                                            </div>
                                        @endforeach
                                    @else
                                        <p class="muted reading-width">{{ __('Structured stage details were not retained for this event; do not infer a provider cause.') }}</p>
                                    @endif
                                </details>
                            @endif
                        </td>
                        <td><code dir="ltr" class="small-code">{{ $item['correlation_id'] }}</code></td>
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
