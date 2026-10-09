@extends('admin.layout')

@section('title', __('Target access'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('User target access') }}</div>
        <h1>{{ $managedUser->name }}</h1>
        <p class="muted">{{ __('Browse the fleet in bounded pages and configure only the target that needs an exception.') }}</p>
    </div>
    <a href="{{ route('admin.users.edit', ['user' => $managedUser->id]) }}">{{ __('Back to user') }}</a>
</div>

@if ($isOwner)
    <div class="alert alert-success" role="status">{{ __('This user is an owner. Owners always have unrestricted all-target access and do not accept target overrides.') }}</div>
@endif

<section class="panel panel-wide">
    <form class="filter-grid" method="get" action="{{ route('admin.users.targets.index', ['user' => $managedUser->id]) }}">
        <div class="field">
            <label for="search">{{ __('Search') }}</label>
            <input id="search" name="search" type="search" maxlength="160" value="{{ $filters['search'] ?? '' }}" placeholder="{{ __('Name or target ID') }}">
        </div>
        <div class="field">
            <label for="connection_state">{{ __('Connection state') }}</label>
            <select id="connection_state" name="connection_state">
                <option value="">{{ __('All states') }}</option>
                @foreach ($connectionStates as $state)
                    <option value="{{ $state->value }}" @selected(($filters['connection_state'] ?? null) === $state->value)>{{ \Illuminate\Support\Str::headline(str_replace('_', ' ', $state->value)) }}</option>
                @endforeach
            </select>
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.users.targets.index', ['user' => $managedUser->id]) }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @if ($targets === [])
        <p class="empty-state">{{ __('No targets match these filters.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">{{ __('Target') }}</th>
                    <th scope="col">{{ __('Explicit scope rule') }}</th>
                    <th scope="col">{{ __('Capability denials') }}</th>
                    <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($targets as $target)
                    @php($rule = $targetRules[(string) $target->getKey()])
                    <tr>
                        <td>
                            <strong>{{ $target->display_name }}</strong><br>
                            <code class="small-code">{{ $target->target_id }}</code>
                        </td>
                        <td><span class="badge badge-{{ $rule['access_rule'] === 'allow' ? 'success' : ($rule['access_rule'] === 'deny' ? 'danger' : 'neutral') }}">{{ \Illuminate\Support\Str::headline($rule['access_rule']) }}</span></td>
                        <td>{{ $rule['denied_count'] }}</td>
                        <td class="table-action">
                            @unless ($isOwner)
                                <a href="{{ route('admin.users.targets.edit', ['user' => $managedUser->id, 'target' => $target->target_id]) }}">{{ __('Edit rule') }}</a>
                            @endunless
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
    @endif

    @if ($pagination['previous_url'] !== null || $pagination['next_url'] !== null)
        <nav class="pagination" aria-label="{{ __('Target pages') }}">
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
