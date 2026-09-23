@extends('admin.layout')

@section('title', __('Site groups'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Site groups') }}</h1>
        <p class="muted">{{ __('Groups add reusable site membership and denial-only capability restrictions without replacing direct site rules.') }}</p>
    </div>
    <a class="button button-primary" href="{{ route('admin.site-groups.create') }}">{{ __('Add site group') }}</a>
</div>

<section class="panel panel-wide" aria-label="{{ __('Site groups') }}">
    @if ($groups->isEmpty())
        <p class="empty-state">{{ __('No site groups are configured.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">{{ __('Group') }}</th>
                    <th scope="col">{{ __('Sites') }}</th>
                    <th scope="col">{{ __('Users') }}</th>
                    <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($groups as $group)
                    <tr>
                        <td><strong>{{ $group->name }}</strong></td>
                        <td>{{ $group->sites_count }}</td>
                        <td>{{ $group->users_count }}</td>
                        <td class="table-action"><a href="{{ route('admin.site-groups.edit', ['siteGroup' => $group->id]) }}">{{ __('Manage') }}</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>

        @if ($groups->previousPageUrl() !== null || $groups->nextPageUrl() !== null)
            <nav class="pagination" aria-label="{{ __('Site group pages') }}">
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
