@extends('admin.layout')

@section('title', __('WordPress Bridge inspection'))

@section('content')
<div class="page-heading">
    <div>
        <div class="eyebrow">{{ __('WordPress read-only operation') }}</div>
        <h1>{{ __('Bridge information') }}</h1>
        <p class="muted">{{ __('Executed through the same Target authorization and connector operation as the AI/MCP entry point.') }}</p>
    </div>
    <div class="filter-actions">
        <a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}" class="button button-secondary">{{ __('Back to Target') }}</a>
    </div>
</div>
<section class="panel panel-wide" aria-labelledby="bridge-inspect-result">
    <h2 id="bridge-inspect-result">{{ __('Target :id', ['id' => $target->display_name]) }}</h2>
    @if ($success)
        <p role="status">{{ __('Read-only Bridge information received.') }}</p>
        <pre class="small-code operation-result-preview">{{ $response }}</pre>
        @if ($truncated)
            <p class="field-help">{{ __('Displayed preview is truncated at 32 KiB; no result bytes are retained in browser session storage.') }}</p>
        @endif
    @else
        <p role="alert">{{ __('Bridge inspection could not complete safely.') }}</p>
        <p class="field-help">{{ $error['code'] ?? __('unknown_error') }} — {{ $error['message'] ?? __('No additional details available.') }}</p>
        @if (! empty($error['diagnostic_reference']))
            <p class="field-help">{{ __('Diagnostic reference') }}: <code>{{ $error['diagnostic_reference'] }}</code></p>
        @endif
    @endif
</section>
@endsection
