@extends('admin.layout')

@section('title', __('Site access'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('User site access') }}</div>
        <h1>{{ $managedUser->name }}</h1>
        <p class="muted">{{ __('Browse the fleet in bounded pages and configure only the site that needs an exception.') }}</p>
    </div>
    <a href="{{ route('admin.users.edit', ['user' => $managedUser->id]) }}">{{ __('Back to user') }}</a>
</div>

@if ($isOwner)
    <div class="alert alert-success" role="status">{{ __('This user is an owner. Owners always have unrestricted all-site access and do not accept site overrides.') }}</div>
@endif

<section class="panel panel-wide">
    <form class="filter-grid" method="get" action="{{ route('admin.users.sites.index', ['user' => $managedUser->id]) }}">
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
            <a class="button button-secondary" href="{{ route('admin.users.sites.index', ['user' => $managedUser->id]) }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @if ($sites === [])
        <p class="empty-state">{{ __('No sites match these filters.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">{{ __('Site') }}</th>
                    <th scope="col">{{ __('Explicit scope rule') }}</th>
                    <th scope="col">{{ __('Capability denials') }}</th>
                    <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($sites as $site)
                    @php($rule = $siteRules[(string) $site->getKey()])
                    <tr>
                        <td>
                            <strong>{{ $site->display_name }}</strong><br>
                            <code class="small-code">{{ $site->site_id }}</code>
                        </td>
                        <td><code>{{ $rule['access_rule'] }}</code></td>
                        <td>{{ $rule['denied_count'] }}</td>
                        <td class="table-action">
                            @unless ($isOwner)
                                <a href="{{ route('admin.users.sites.edit', ['user' => $managedUser->id, 'site' => $site->site_id]) }}">{{ __('Edit rule') }}</a>
                            @endunless
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
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
