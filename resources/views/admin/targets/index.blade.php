@extends('admin.layout')

@section('title', __('Targets'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Connectors') }}</div>
        <h1>{{ __('Gateway Targets') }}</h1>
        <p class="muted">{{ __('One stable Target ID per connector endpoint. Results are limited to your permitted Targets.') }}</p>
    </div>
    @can('targets.create')
        <a class="button button-primary" href="{{ route('admin.targets.create') }}">{{ __('Add Target') }}</a>
    @endcan
</div>

<section class="panel panel-wide" aria-labelledby="targets-list-title">
    <h2 id="targets-list-title" class="sr-only">{{ __('Registered Targets') }}</h2>
    <form method="get" action="{{ route('admin.targets.index') }}" class="filter-grid">
        <div class="field">
            <label for="search">{{ __('Search Target name or ID') }}</label>
            <input id="search" name="search" type="search" maxlength="160" value="{{ $filters['search'] ?? '' }}">
        </div>
        <div class="field">
            <label for="connection_state">{{ __('Connection state') }}</label>
            <select id="connection_state" name="connection_state">
                <option value="">{{ __('Any state') }}</option>
                @foreach ($connectionStates as $state)
                    <option value="{{ $state->value }}" @selected($filters['connection_state'] === $state->value)>{{ str_replace('_', ' ', ucfirst($state->value)) }}</option>
                @endforeach
            </select>
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.targets.index') }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @if ($inventory['items'] === [])
        <p class="empty-state">{{ __('No permitted Targets match the selected filters.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th scope="col">{{ __('Target') }}</th>
                        <th scope="col">{{ __('Connector') }}</th>
                        <th scope="col">{{ __('Connection state') }}</th>
                        <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($inventory['items'] as $target)
                        <tr>
                            <td><strong>{{ $target->display_name }}</strong>
                                <code class="small-code">{{ $target->target_id }}</code>
                            </td>
                            <td>
                                <strong>{{ $target->connector_type === 'wp_ai_bridge' ? __('WordPress') : $target->connector_type }}</strong>
                                <small><code class="small-code">{{ $target->connector_type }}</code></small>
                            </td>
                            <td>
                                <span class="badge badge-{{ $target->connection_state->value === 'connected' ? 'success' : 'neutral' }}">
                                    {{ str_replace('_', ' ', ucfirst($target->connection_state->value)) }}
                                </span>
                            </td>
                            <td class="table-action">
                                <a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Inspect') }}</a>
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    @endif

    <nav class="pagination" aria-label="{{ __('Target pages') }}">
        @if ($inventory['page'] > 1)
            <a class="button button-secondary" rel="prev" href="{{ route('admin.targets.index', [...$baseQuery, 'page' => $inventory['page'] - 1]) }}">{{ __('Previous') }}</a>
        @else
            <span></span>
        @endif
        <span>{{ __('Page :page', ['page' => $inventory['page']]) }}</span>
        @if ($inventory['has_more'])
            <a class="button button-secondary" rel="next" href="{{ route('admin.targets.index', [...$baseQuery, 'page' => $inventory['page'] + 1]) }}">{{ __('Next') }}</a>
        @endif
    </nav>
</section>
@endsection
