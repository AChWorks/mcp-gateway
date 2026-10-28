@extends('admin.layout')

@section('title', __('Continue to external authorization'))

@section('head')
    {{-- A new GET navigation breaks the CSP-restricted POST redirect chain.
         The Admin CSP and no-referrer/no-store headers still apply. --}}
    <meta http-equiv="refresh" content="0;url={{ $destination }}">
@endsection

@section('content')
<section class="panel panel-wide" aria-labelledby="external-authorization-title">
    <h1 id="external-authorization-title">{{ __('Continue to external authorization') }}</h1>
    <p>{{ __('The Gateway is opening the verified authorization provider (:provider) for this Target.', ['provider' => $providerHost]) }}</p>
    <p class="field-help">{{ __('If your browser does not navigate automatically, use the link below. Do not resubmit the connection form.') }}</p>
    <p><a class="button button-primary" href="{{ $destination }}" rel="noreferrer noopener">{{ __('Continue to authorization provider') }}</a></p>
    <p><a href="{{ route('admin.targets.show', ['target' => $target->target_id]) }}">{{ __('Back to Target') }}</a></p>
</section>
@endsection
