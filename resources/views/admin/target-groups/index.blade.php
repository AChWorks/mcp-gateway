@extends('admin.layout')

@section('title', __('Target groups'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Target groups') }}</h1>
        <p class="muted reading-width">{{ __('Groups add reusable target membership and denial-only capability restrictions without replacing direct target rules.') }}</p>
    </div>
    <a class="button button-primary" href="{{ route('admin.target-groups.create') }}">{{ __('Add target group') }}</a>
</div>

<section class="panel panel-wide" aria-label="{{ __('Target groups') }}">
    <form class="filter-grid" method="get" action="{{ route('admin.target-groups.index') }}">
        <div class="field">
            <label for="group-search">{{ __('Search groups') }}</label>
            <input id="group-search" name="search" type="search" maxlength="160" value="{{ $search }}" @error('search') aria-invalid="true" aria-describedby="group-search-error" @enderror>
            @error('search')<p id="group-search-error" class="field-error" role="alert">{{ $message }}</p>@enderror
        </div>
        <div class="filter-actions">
            <button class="button button-secondary" type="submit">{{ __('Search') }}</button>
            <a href="{{ route('admin.target-groups.index') }}">{{ __('Clear') }}</a>
        </div>
    </form>
    @if ($groups->isEmpty())
        <p class="empty-state">{{ $search === '' ? __('No target groups are configured.') : __('No groups match this search.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">{{ __('Group') }}</th>
                    <th scope="col">{{ __('Targets') }}</th>
                    <th scope="col">{{ __('Users') }}</th>
                    <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($groups as $group)
                    <tr>
                        <td><strong><a href="{{ route('admin.target-groups.targets.index', ['targetGroup' => $group->id]) }}">{{ $group->name }}</a></strong></td>
                        <td><a href="{{ route('admin.target-groups.targets.index', ['targetGroup' => $group->id]) }}" aria-label="{{ __('View Targets in :group', ['group' => $group->name]) }}">{{ $group->targets_count }}</a></td>
                        <td><a href="{{ route('admin.target-groups.users.index', ['targetGroup' => $group->id]) }}" aria-label="{{ __('View users in :group', ['group' => $group->name]) }}">{{ $group->users_count }}</a></td>
                        <td class="table-action"><a aria-label="{{ __('Manage :name', ['name' => $group->name]) }}" href="{{ route('admin.target-groups.edit', ['targetGroup' => $group->id]) }}">{{ __('Settings') }}</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>

        @if ($groups->previousPageUrl() !== null || $groups->nextPageUrl() !== null)
            <nav class="pagination" aria-label="{{ __('Target group pages') }}">
                @if ($groups->previousPageUrl() !== null)
                    <a class="button button-secondary" rel="prev" href="{{ $groups->previousPageUrl() }}">{{ __('Previous') }}</a>
                @else
                    <span></span>
                @endif
                <span>{{ __('Page :page', ['page' => $groups->currentPage()]) }}</span>
                @if ($groups->nextPageUrl() !== null)
                    <a class="button button-secondary" rel="next" href="{{ $groups->nextPageUrl() }}">{{ __('Next') }}</a>
                @endif
            </nav>
        @endif
    @endif
</section>
@endsection
