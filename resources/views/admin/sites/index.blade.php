@extends('admin.layout')

@section('title', __('Sites'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Sites') }}</div>
        <h1>{{ __('WordPress sites') }}</h1>
        <p class="muted">{{ __('Each site has its own target, OAuth credential lifecycle and explicit routing identity.') }}</p>
    </div>
    <a class="button button-primary" href="{{ route('admin.sites.create') }}">{{ __('Add site') }}</a>
</div>

<section class="panel panel-wide" aria-label="{{ __('Configured WordPress sites') }}">
    @if ($sites->isEmpty())
        <div class="empty-state">
            <h2>{{ __('No sites configured') }}</h2>
            <p>{{ __('Add the first WordPress site to discover its WP AI Bridge endpoint.') }}</p>
            <a class="button button-primary" href="{{ route('admin.sites.create') }}">{{ __('Add site') }}</a>
        </div>
    @else
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">{{ __('Site') }}</th>
                    <th scope="col">{{ __('WordPress URL') }}</th>
                    <th scope="col">{{ __('Status') }}</th>
                    <th scope="col">{{ __('Last error') }}</th>
                    <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
                </tr>
                </thead>
                <tbody>
                @foreach ($sites as $item)
                    @php($site = $item['site'])
                    <tr>
                        <td>
                            <strong>{{ $site->display_name }}</strong><br>
                            <code class="small-code">{{ $site->site_id }}</code>
                        </td>
                        <td><a href="{{ $site->base_url }}" rel="noreferrer">{{ $site->base_url }}</a></td>
                        <td><span class="badge badge-{{ $item['status_tone'] }}">{{ $item['status_label'] }}</span></td>
                        <td><code>{{ $site->last_error_code ?? '—' }}</code></td>
                        <td class="table-action"><a href="{{ route('admin.sites.show', ['site' => $site->site_id]) }}">{{ __('Manage') }}</a></td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        </div>
    @endif
</section>
@endsection
