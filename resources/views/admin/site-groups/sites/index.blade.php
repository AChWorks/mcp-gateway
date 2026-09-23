@extends('admin.layout')

@section('title', __('Site group sites'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Site group sites') }}</div>
        <h1>{{ $siteGroup->name }}</h1>
        <p class="muted">{{ __('Browse the authorized fleet in bounded pages and change one group membership at a time.') }}</p>
    </div>
    <a href="{{ route('admin.site-groups.edit', ['siteGroup' => $siteGroup->id]) }}">{{ __('Back to group') }}</a>
</div>

<section class="panel panel-wide">
    <form class="filter-grid" method="get" action="{{ route('admin.site-groups.sites.index', ['siteGroup' => $siteGroup->id]) }}">
        <div class="field">
            <label for="search">{{ __('Search') }}</label>
            <input id="search" name="search" type="search" maxlength="160" value="{{ $filters['search'] ?? '' }}" placeholder="{{ __('Name or site ID') }}">
        </div>
        <div class="field">
            <label for="connection_state">{{ __('Connection state') }}</label>
            <select id="connection_state" name="connection_state">
                <option value="">{{ __('All states') }}</option>
                @foreach ($connectionStates as $state)
                    <option value="{{ $state->value }}" @selected(($filters['connection_state'] ?? null) === $state->value)>{{ $state->value }}</option>
                @endforeach
            </select>
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.site-groups.sites.index', ['siteGroup' => $siteGroup->id]) }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @if ($sites === [])
        <p class="empty-state">{{ __('No sites match these filters.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead><tr><th scope="col">{{ __('Site') }}</th><th scope="col">{{ __('Membership') }}</th><th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th></tr></thead>
                <tbody>
                @foreach ($sites as $site)
                    <tr>
                        <td><strong>{{ $site->display_name }}</strong><br><code class="small-code">{{ $site->site_id }}</code></td>
                        <td><span class="badge badge-{{ $memberships[(string) $site->getKey()] ? 'success' : 'neutral' }}">{{ $memberships[(string) $site->getKey()] ? __('Included') : __('Not included') }}</span></td>
                        <td class="table-action"><a href="{{ route('admin.site-groups.sites.edit', ['siteGroup' => $siteGroup->id, 'site' => $site->site_id]) }}">{{ __('Edit membership') }}</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
    @endif

    @if ($pagination['previous_url'] !== null || $pagination['next_url'] !== null)
        <nav class="pagination" aria-label="{{ __('Site pages') }}">
            @if ($pagination['previous_url'] !== null)<a class="button button-secondary" rel="prev" href="{{ $pagination['previous_url'] }}">{{ __('Previous') }}</a>@else<span></span>@endif
            <span>{{ __('Page :page', ['page' => $pagination['page']]) }}</span>
            @if ($pagination['next_url'] !== null)<a class="button button-secondary" rel="next" href="{{ $pagination['next_url'] }}">{{ __('Next') }}</a>@endif
        </nav>
    @endif
</section>
@endsection
