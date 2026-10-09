@extends('admin.layout')

@section('title', __('Target groups'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Target groups') }}</h1>
        <p class="muted">{{ __('Groups add reusable target membership and denial-only capability restrictions without replacing direct target rules.') }}</p>
    </div>
    <a class="button button-primary" href="{{ route('admin.target-groups.create') }}">{{ __('Add target group') }}</a>
</div>

<section class="panel panel-wide" aria-label="{{ __('Target groups') }}">
    @if ($groups->isEmpty())
        <p class="empty-state">{{ __('No target groups are configured.') }}</p>
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
                        <td><strong>{{ $group->name }}</strong></td>
                        <td>{{ $group->targets_count }}</td>
                        <td>{{ $group->users_count }}</td>
                        <td class="table-action"><a href="{{ route('admin.target-groups.edit', ['targetGroup' => $group->id]) }}">{{ __('Manage') }}</a></td>
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
