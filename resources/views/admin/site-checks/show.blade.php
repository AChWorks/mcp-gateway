@extends('admin.layout')

@section('title', __('Bulk site check'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('Bulk site check') }}</div>
        <h1>{{ __('Selected-site connection check') }}</h1>
        <p class="muted">
            {{ __('Operation') }} <code class="small-code">{{ $operation->getKey() }}</code>
        </p>
    </div>
    <a class="button button-secondary" href="{{ route('admin.sites.index') }}">{{ __('Back to sites') }}</a>
</div>

@error('bulk_check')
    <div class="alert alert-error" role="alert">{{ $message }}</div>
@enderror

<div class="stats-grid" aria-label="{{ __('Bulk check progress') }}">
    <section class="stat-card">
        <span class="stat-value">{{ $summary['total'] }}</span>
        <span class="stat-label">{{ __('Selected') }}</span>
    </section>
    <section class="stat-card">
        <span class="stat-value">{{ $summary['succeeded'] }}</span>
        <span class="stat-label">{{ __('Succeeded') }}</span>
    </section>
    <section class="stat-card">
        <span class="stat-value">{{ $summary['pending'] + $summary['running'] }}</span>
        <span class="stat-label">{{ __('Remaining') }}</span>
    </section>
</div>

<section class="panel panel-wide">
    <div class="section-heading">
        <div>
            <h2>{{ __('Execution') }}</h2>
            <p class="muted">
                {{ __('Each request claims at most one site. Leaving this page pauses new checks; returning here resumes the durable operation.') }}
            </p>
        </div>

        @if ($summary['pending'] > 0 || $summary['running'] > 0)
            <form method="post" action="{{ route('admin.site-checks.advance', ['operation' => $operation->getKey()]) }}">
                @csrf
                <button class="button button-primary" type="submit">
                    {{ $summary['running'] > 0 ? __('Reconcile / continue') : __('Run next check') }}
                </button>
            </form>
        @else
            <span class="badge badge-success">{{ __('Initial pass complete') }}</span>
        @endif
    </div>

    <p class="muted">
        {{ __('Pending') }}: {{ $summary['pending'] }}
        · {{ __('Running') }}: {{ $summary['running'] }}
        · {{ __('Failed') }}: {{ $summary['failed'] }}
        · {{ __('Access blocked') }}: {{ $summary['authorization_blocked'] }}
        · {{ __('Unavailable') }}: {{ $summary['missing'] }}
        · {{ __('Interrupted') }}: {{ $summary['interrupted'] }}
    </p>

    <div class="table-wrap">
        <table>
            <thead>
            <tr>
                <th scope="col">{{ __('Site') }}</th>
                <th scope="col">{{ __('Status') }}</th>
                <th scope="col">{{ __('Attempts') }}</th>
                <th scope="col">{{ __('Error') }}</th>
                <th scope="col"><span class="sr-only">{{ __('Actions') }}</span></th>
            </tr>
            </thead>
            <tbody>
            @foreach ($targets as $item)
                @php($target = $item['target'])
                <tr>
                    <td>
                        @if ($item['visible'])
                            <strong>{{ $item['display_name'] }}</strong><br>
                            <code class="small-code">{{ $item['site_id'] }}</code>
                        @else
                            <strong>{{ __('Access unavailable') }}</strong><br>
                            <span class="muted">{{ __('The current operator can no longer inspect this target identity.') }}</span>
                        @endif
                    </td>
                    <td><span class="badge badge-{{ $item['status_tone'] }}">{{ $item['status_label'] }}</span></td>
                    <td>{{ $target->attempts }} / {{ $maxAttempts }}</td>
                    <td>
                        @if ($target->error_code !== null)
                            <code>{{ $target->error_code }}</code>
                        @else
                            <span class="muted">—</span>
                        @endif
                    </td>
                    <td class="table-action">
                        @if ($item['retryable'])
                            <form method="post" action="{{ route('admin.site-checks.retry', ['operation' => $operation->getKey(), 'target' => $target->getKey()]) }}">
                                @csrf
                                <button class="button button-secondary" type="submit">{{ __('Retry') }}</button>
                            </form>
                        @else
                            <span class="muted">—</span>
                        @endif
                    </td>
                </tr>
            @endforeach
            </tbody>
        </table>
    </div>
</section>
@endsection
