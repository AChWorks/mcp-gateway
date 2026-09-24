@extends('admin.layout')

@section('title', __('Users'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Access control') }}</div>
        <h1>{{ __('Local users') }}</h1>
        <p class="muted">{{ __('Roles define the permission ceiling. Global, group, and direct per-site rules can only narrow that authority.') }}</p>
    </div>
    @can('users.manage')
        <a class="button button-primary" href="{{ route('admin.users.create') }}">{{ __('Add user') }}</a>
    @endcan
</div>

<section class="panel panel-wide" aria-label="{{ __('Local users') }}">
    @if ($users->isEmpty())
        <p class="empty-state">{{ __('No local users are available.') }}</p>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">{{ __('User') }}</th>
                    <th scope="col">{{ __('Role') }}</th>
                    <th scope="col">{{ __('Site scope') }}</th>
                    <th scope="col">{{ __('Status') }}</th>
                    <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($users as $user)
                    <tr>
                        <td>
                            <strong>{{ $user->name }}</strong><br>
                            <span class="muted">{{ $user->email }}</span>
                        </td>
                        <td><span class="badge badge-neutral">{{ \Illuminate\Support\Str::headline($user->role->value) }}</span></td>
                        <td><span class="badge badge-neutral" title="{{ $user->site_scope_mode->description() }}">{{ $user->site_scope_mode->title() }}</span></td>
                        <td>
                            <span class="badge badge-{{ $user->access_enabled ? 'success' : 'danger' }}">
                                {{ $user->access_enabled ? __('Enabled') : __('Disabled') }}
                            </span>
                        </td>
                        <td class="table-action">
                            @can('users.manage')
                                <a href="{{ route('admin.users.edit', ['user' => $user->id]) }}">{{ __('Manage') }}</a>
                            @endcan
                        </td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>

        @if ($users->previousPageUrl() !== null || $users->nextPageUrl() !== null)
            <nav class="pagination" aria-label="{{ __('User pages') }}">
                @if ($users->previousPageUrl() !== null)
                    <a class="button button-secondary" rel="prev" href="{{ $users->previousPageUrl() }}">{{ __('Previous') }}</a>
                @else
                    <span></span>
                @endif

                <span>{{ __('Page :page', ['page' => $users->currentPage()]) }}</span>

                @if ($users->nextPageUrl() !== null)
                    <a class="button button-secondary" rel="next" href="{{ $users->nextPageUrl() }}">{{ __('Next') }}</a>
                @endif
            </nav>
        @endif
    @endif
</section>
@endsection
