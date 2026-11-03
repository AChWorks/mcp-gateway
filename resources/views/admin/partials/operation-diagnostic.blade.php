@php($diagnosticContext = (array) session('diagnostic_context', []))
@php($safeDiagnostic = \App\Support\OperationDiagnostics::safeContext($diagnosticContext))
@php($diagnosticStage = $safeDiagnostic['failure_stage'] ?? session('diagnostic_stage'))
@if (session('diagnostic_code'))
    @if (! ($embedded ?? false))<section class="panel" aria-label="{{ __('Operation diagnostic') }}" role="status">@endif
        <p><strong>{{ __('Diagnostic category') }}:</strong> <code>{{ session('diagnostic_code') }}</code>
            @if ($diagnosticStage) · <strong>{{ __('Failure stage') }}:</strong> <code>{{ $diagnosticStage }}</code>@endif
        </p>
        <p>{{ \App\Support\OperationDiagnostics::summary((string) session('diagnostic_code'), $diagnosticContext) }}</p>
        <p><strong>{{ __('What to check') }}:</strong> {{ \App\Support\OperationDiagnostics::nextStep((string) session('diagnostic_code'), $diagnosticContext) }}</p>
        @if (session('diagnostic_reference'))
            <p><strong>{{ __('Log reference') }}:</strong> <code>{{ session('diagnostic_reference') }}</code></p>
        @endif
    @if (! ($embedded ?? false))</section>@endif
@endif
