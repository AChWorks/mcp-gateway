@extends('admin.layout')

@section('title', __('Sites'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Sites') }}</div>
        <h1>{{ __('WordPress sites') }}</h1>
        <p class="muted">{{ __('Each site has its own target, OAuth credential lifecycle and explicit routing identity.') }}</p>
    </div>
    @can('sites.create')
        <a class="button button-primary" href="{{ route('admin.sites.create') }}">{{ __('Add site') }}</a>
    @endcan
</div>

@can('connections.test')
    @if ($activeBulkCheck !== null)
        <section class="panel panel-wide" aria-label="{{ __('Active bulk site check') }}">
            <div class="section-heading">
                <div>
                    <div class="eyebrow">{{ __('Bulk site check') }}</div>
                    <h2>{{ __('A bulk check is still active') }}</h2>
                    <p class="muted">{{ __('Resume it before starting another selected-site check.') }}</p>
                </div>
                <a class="button button-primary" href="{{ route('admin.site-checks.show', ['operation' => $activeBulkCheck->getKey()]) }}">
                    {{ __('Resume check') }}
                </a>
            </div>
        </section>
    @endif
@endcan

<section class="panel panel-wide" aria-label="{{ __('Configured WordPress sites') }}">
    <form class="filter-grid" method="get" action="{{ route('admin.sites.index') }}">
        <div class="field">
            <label for="search">{{ __('Search') }}</label>
            <input
                id="search"
                name="search"
                type="search"
                maxlength="160"
                value="{{ $filters['search'] ?? '' }}"
                placeholder="{{ __('Name or site ID') }}"
            >
        </div>
        <div class="field">
            <label for="connection_state">{{ __('Connection state') }}</label>
            <select id="connection_state" name="connection_state">
                <option value="">{{ __('All states') }}</option>
                @foreach ($connectionStates as $value => $label)
                    <option value="{{ $value }}" @selected(($filters['connection_state'] ?? null) === $value)>{{ $label }}</option>
                @endforeach
            </select>
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.sites.index') }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @error('bulk_check')
        <p class="field-error" role="alert">{{ $message }}</p>
    @enderror
    @error('site_ids')
        <p class="field-error" role="alert">{{ $message }}</p>
    @enderror

    @if ($sites->isEmpty())
        <div class="empty-state">
            @if (($filters['search'] ?? null) !== null || ($filters['connection_state'] ?? null) !== null)
                <h2>{{ __('No sites match these filters') }}</h2>
                <p>{{ __('Clear or change the filters to continue browsing the registered fleet.') }}</p>
                <a class="button button-secondary" href="{{ route('admin.sites.index') }}">{{ __('Clear filters') }}</a>
            @else
                <h2>{{ __('No sites configured') }}</h2>
                <p>{{ __('Add the first WordPress site to discover its WP AI Bridge endpoint.') }}</p>
                @can('sites.create')
                    <a class="button button-primary" href="{{ route('admin.sites.create') }}">{{ __('Add site') }}</a>
                @endcan
            @endif
        </div>
    @else
        @can('connections.test')
            <form method="post" action="{{ route('admin.site-checks.store') }}">
                @csrf
                <input type="hidden" name="idempotency_key" value="{{ $bulkCheckIdempotencyKey }}">
        @endcan

        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    @can('connections.test')
                        <th scope="col">{{ __('Check') }}</th>
                    @endcan
                    <th scope="col">{{ __('Site') }}</th>
                    <th scope="col">{{ __('WordPress URL') }}</th>
                    <th scope="col">{{ __('Status') }}</th>
                    <th scope="col">{{ __('Latest evidence') }}</th>
                    <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($sites as $item)
                    <tr>
                        @can('connections.test')
                            <td>
                                @can('connections.test', $item['site'])
                                    <input
                                        type="checkbox"
                                        name="site_ids[]"
                                        value="{{ $item['site']->site_id }}"
                                        aria-label="{{ __('Select :site for bulk check', ['site' => $item['site']->display_name]) }}"
                                        @checked(in_array($item['site']->site_id, old('site_ids', []), true))
                                        @disabled($activeBulkCheck !== null)
                                    >
                                @else
                                    <span class="muted" aria-label="{{ __('Connection test not authorized') }}">—</span>
                                @endcan
                            </td>
                        @endcan
                        <td>
                            <strong>{{ $item['site']->display_name }}</strong><br>
                            <code class="small-code">{{ $item['site']->site_id }}</code>
                        </td>
                        <td><a href="{{ $item['site']->base_url }}" rel="noreferrer">{{ $item['site']->base_url }}</a></td>
                        <td><span class="badge badge-{{ $item['status_tone'] }}">{{ $item['status_label'] }}</span></td>
                        <td>
                            <span class="muted">{{ __('Success') }}:</span>
                            {{ $item['site']->last_success_at?->format('Y-m-d H:i:s') ?? __('Never') }}<br>
                            <span class="muted">{{ __('Check') }}:</span>
                            {{ $item['site']->last_tested_at?->format('Y-m-d H:i:s') ?? __('Never') }}
                            @if ($item['site']->last_failure_at !== null)
                                <br><span class="muted">{{ __('Failure') }}:</span>
                                {{ $item['site']->last_failure_at->format('Y-m-d H:i:s') }}
                                <code>{{ $item['site']->last_failure_code ?? 'failure' }}</code>
                            @endif
                        </td>
                        <td class="table-action"><a href="{{ route('admin.sites.show', ['site' => $item['site']->site_id]) }}">{{ __('Manage') }}</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>

        @can('connections.test')
                <div class="action-row">
                    <p class="muted">{{ __('Select 2–50 sites from this page. Checks run one target per request and can be resumed.') }}</p>
                    <button class="button button-primary" type="submit" @disabled($activeBulkCheck !== null)>
                        {{ __('Start bulk check') }}
                    </button>
                </div>
            </form>
        @endcan
    @endif

    @if ($pagination['previous_url'] !== null || $pagination['next_url'] !== null)
        <nav class="pagination" aria-label="{{ __('Site pages') }}">
            @if ($pagination['previous_url'] !== null)
                <a class="button button-secondary" rel="prev" href="{{ $pagination['previous_url'] }}">{{ __('Previous') }}</a>
            @else
                <span></span>
            @endif

            <span>{{ __('Page :page', ['page' => $pagination['page']]) }}</span>

            @if ($pagination['next_url'] !== null)
                <a class="button button-secondary" rel="next" href="{{ $pagination['next_url'] }}">{{ __('Next') }}</a>
            @endif
        </nav>
    @endif
</section>
@endsection
