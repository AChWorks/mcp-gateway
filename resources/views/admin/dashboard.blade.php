@extends('admin.layout')

@section('title', __('Dashboard'))

@section('content')
@php
    $stateLabels = array_column($lifecycle, 'label', 'state');
@endphp
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Workspace') }}</div>
        <h1>{{ __('Gateway overview') }}</h1>
        <p class="muted">{{ __('Registered Targets in your effective access scope. Connection records and observations are not live monitoring.') }}</p>
    </div>
    @can('targets.create')
        <a class="button button-primary" href="{{ route('admin.targets.create') }}">{{ __('Add Target') }}</a>
    @endcan
</div>

<section class="stats-grid" aria-label="{{ __('Gateway summary') }}">
    <article class="stat-card">
        <span class="stat-value">{{ $targetCount }}</span>
        <span class="stat-label">{{ __('Visible Targets') }}</span>
        <p class="field-help">{{ __('Within your effective access') }}</p>
    </article>
    <article class="stat-card">
        <span class="stat-value">{{ $connectedCount }}</span>
        <span class="stat-label">{{ __('Recorded connected') }}</span>
        <p class="field-help">{{ __('Local state; not a live check') }}</p>
    </article>
    <article class="stat-card">
        <span class="stat-value">{{ $attentionCount }}</span>
        <span class="stat-label">{{ __('Needs review') }}</span>
        <p class="field-help">{{ __('Inspect the recorded condition before acting') }}</p>
    </article>
    <article class="stat-card">
        <span class="stat-value">{{ $pausedCount }}</span>
        <span class="stat-label">{{ __('Paused') }}</span>
        <p class="field-help">{{ __('Independent of connection state') }}</p>
    </article>
</section>

<section class="panel panel-wide" aria-labelledby="needs-review-title">
    <div class="section-heading">
        <div>
            <h2 id="needs-review-title">{{ __('Needs review') }}</h2>
            <p class="muted">{{ __('Recorded attention states or blocked recovery evidence. An unresolved result is not a confirmed failure.') }}</p>
        </div>
        @can('targets.view')
            <a href="{{ route('admin.targets.index', ['needs_review' => 1]) }}">{{ __('View all Targets needing review') }}</a>
        @endcan
    </div>

    @if ($reviewTargets === [])
        <p class="empty-state">{{ __('No permitted Targets currently match the review criteria. This does not verify live remote health.') }}</p>
    @else
        <div class="table-wrap">
            <table class="table-readable">
                <thead>
                <tr>
                    <th scope="col" class="table-identity">{{ __('Target') }}</th>
                    <th scope="col">{{ __('Recorded condition') }}</th>
                    <th scope="col">{{ __('Evidence') }}</th>
                    <th scope="col">{{ __('Next step') }}</th>
                </tr>
                </thead>
                <tbody>
                @foreach ($reviewTargets as $target)
                    @php
                        $state = $target->connection_state->value;
                        $attentionState = in_array($state, ['error', 'reconnect_required', 'reassigning'], true);
                        $evidenceAt = $target->last_failure_at ?? $target->last_tested_at ?? $target->last_success_at;
                        $evidenceLabel = $target->last_failure_at !== null
                            ? __('Failure observation recorded')
                            : ($target->last_tested_at !== null ? __('Connection test recorded') : __('Successful operation recorded'));
                    @endphp
                    <tr>
                        <td>
                            <strong>{{ $target->display_name }}</strong><br>
                            <bdi><code>{{ $target->target_id }}</code></bdi><br>
                            <span class="muted">{{ $connectorLabels->label($target->connector_type) }}</span>
                        </td>
                        <td>
                            <span class="badge badge-{{ $state === 'error' ? 'danger' : 'warning' }}">
                                {{ $attentionState ? $stateLabels[$state] : __('Unresolved recovery') }}
                            </span>
                            @if ($target->operations_paused)
                                <span class="badge badge-neutral">{{ __('Paused') }}</span>
                            @endif
                        </td>
                        <td>
                            @if ($evidenceAt !== null)
                                {{ $evidenceLabel }}<br>
                                <time datetime="{{ $evidenceAt->format(DATE_ATOM) }}">{{ $evidenceAt->format(DATE_ATOM) }}</time>
                            @else
                                <span class="muted">{{ __('No recorded verification') }}</span>
                            @endif
                        </td>
                        <td><a class="button button-secondary" href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Inspect') }}</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
        <p class="field-help">{{ __('Showing up to five permitted Targets. Open the filtered inventory for the complete list.') }}</p>
    @endif
</section>

<div class="content-grid">
    @can('activity.view')
    <section class="panel panel-wide" aria-labelledby="recent-activity-title">
        <div class="section-heading">
            <div>
                <h2 id="recent-activity-title">{{ __('Recent Activity') }}</h2>
                <p class="muted">{{ __('Latest routed operations within your Activity access') }}</p>
            </div>
            <a href="{{ route('admin.activity') }}">{{ __('View all activity') }}</a>
        </div>

        @if ($recentActivity === [])
            <p class="empty-state">{{ __('No routed activity has been recorded yet.') }}</p>
        @else
            <div class="table-wrap">
                <table class="table-readable">
                    <thead>
                    <tr>
                        <th scope="col">{{ __('Time') }}</th>
                        <th scope="col" class="table-identity">{{ __('Target') }}</th>
                        <th scope="col">{{ __('Operation') }}</th>
                        <th scope="col">{{ __('Outcome') }}</th>
                    </tr>
                    </thead>
                    <tbody>
                    @foreach ($recentActivity as $item)
                        @php
                            $outcomeTone = match ($item['outcome']) {
                                'success' => 'success',
                                'failure' => 'danger',
                                'unknown' => 'warning',
                                default => 'neutral',
                            };
                        @endphp
                        <tr>
                            <td><time datetime="{{ $item['created_at'] }}">{{ $item['created_at'] }}</time></td>
                            <td><bdi><code>{{ $item['target_id'] ?? __('Gateway') }}</code></bdi></td>
                            <td>{{ $item['operation'] }}</td>
                            <td><span class="badge badge-{{ $outcomeTone }}">{{ $item['outcome'] === 'unknown' ? __('Outcome unknown') : $item['outcome'] }}</span></td>
                        </tr>
                    @endforeach
                    </tbody>
                </table>
            </div>
        @endif
    </section>
    @endcan

    <aside class="panel panel-wide" aria-labelledby="lifecycle-title">
        <h2 id="lifecycle-title">{{ __('Lifecycle breakdown') }}</h2>
        <dl class="summary-list">
            @foreach ($lifecycle as $item)
                <div><dt>{{ $item['label'] }}</dt><dd>{{ $item['count'] }}</dd></div>
            @endforeach
        </dl>
        <p class="field-help">{{ __('All connection states are included. Pause and review counts may overlap these states.') }}</p>

        <h2>{{ __('Targets by connector') }}</h2>
        @if ($connectorBreakdown === [])
            <p class="muted">{{ __('No permitted Targets are registered.') }}</p>
        @else
            <dl class="summary-list">
                @foreach ($connectorBreakdown as $item)
                    <div>
                        <dt>
                            @if ($connectorLabels->forType($item['type']) !== null)
                                <a href="{{ route('admin.targets.index', ['connector_type' => $item['type']]) }}">{{ $item['label'] }}</a>
                            @else
                                {{ $item['label'] }}
                            @endif
                        </dt>
                        <dd>{{ $item['count'] }}</dd>
                    </div>
                @endforeach
            </dl>
        @endif

        @can('gateway.connection.view')
            <p><a href="{{ route('admin.connection') }}">{{ __('View connection information') }}</a></p>
        @endcan
    </aside>
</div>
@endsection
