@extends('admin.layout')

@section('title', __('Site group users'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Site group users') }}</div>
        <h1>{{ $siteGroup->name }}</h1>
        <p class="muted">{{ __('User assignments are paginated and never change the role/global permission ceiling.') }}</p>
    </div>
    <a href="{{ route('admin.site-groups.edit', ['siteGroup' => $siteGroup->id]) }}">{{ __('Back to group') }}</a>
</div>

<section class="panel panel-wide">
    <form class="filter-grid" method="get" action="{{ route('admin.site-groups.users.index', ['siteGroup' => $siteGroup->id]) }}">
        <div class="field">
            <label for="search">{{ __('Search') }}</label>
            <input id="search" name="search" type="search" maxlength="160" value="{{ $search ?? '' }}" placeholder="{{ __('Name or email') }}">
        </div>
        <div class="filter-actions">
            <button class="button button-primary" type="submit">{{ __('Filter') }}</button>
            <a class="button button-secondary" href="{{ route('admin.site-groups.users.index', ['siteGroup' => $siteGroup->id]) }}">{{ __('Clear') }}</a>
        </div>
    </form>

    @if ($users->isEmpty())
        <p class="empty-state">{{ __('No users match these filters.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead><tr><th scope="col">{{ __('User') }}</th><th scope="col">{{ __('Role') }}</th><th scope="col">{{ __('Assignment') }}</th><th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th></tr></thead>
                <tbody>
                @foreach ($users as $user)
                    <tr>
                        <td><strong>{{ $user->name }}</strong><br><span class="muted">{{ $user->email }}</span></td>
                        <td><code>{{ $user->role->value }}</code></td>
                        <td>
                            @if ($user->role->value === 'owner')
                                <span class="badge badge-neutral">{{ __('Owner unrestricted') }}</span>
                            @else
                                <span class="badge badge-{{ $assignments[(int) $user->id] ? 'success' : 'neutral' }}">{{ $assignments[(int) $user->id] ? __('Assigned') : __('Not assigned') }}</span>
                            @endif
                        </td>
                        <td class="table-action"><a href="{{ route('admin.site-groups.users.edit', ['siteGroup' => $siteGroup->id, 'user' => $user->id]) }}">{{ __('Edit assignment') }}</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>

        @if ($users->previousPageUrl() !== null || $users->nextPageUrl() !== null)
            <nav class="pagination" aria-label="{{ __('User pages') }}">
                @if ($users->previousPageUrl() !== null)<a class="button button-secondary" rel="prev" href="{{ $users->previousPageUrl() }}">{{ __('Previous') }}</a>@else<span></span>@endif
                <span>{{ __('Page :page', ['page' => $users->currentPage()]) }}</span>
                @if ($users->nextPageUrl() !== null)<a class="button button-secondary" rel="next" href="{{ $users->nextPageUrl() }}">{{ __('Next') }}</a>@endif
            </nav>
        @endif
    @endif
</section>
@endsection
