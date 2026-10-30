@extends('admin.layout')

@section('title', __('Access unavailable'))
@section('form-page', '1')

@section('content')
<section class="panel panel-wide" aria-labelledby="administration-denied-title">
    <div class="eyebrow">{{ __('403 · Access unavailable') }}</div>
    <h1 id="administration-denied-title">{{ __('This page is not available to your account') }}</h1>
    <p class="reading-width">{{ __('Choose an available section or sign out. Ask an Owner if you need access to this page or action.') }}</p>
    <div class="action-row">
        <a class="button button-primary" href="{{ $recoveryUrl }}">{{ __('Continue to your available administration') }}</a>
        <form method="post" action="{{ route('admin.logout') }}">
            @csrf
            <button class="button button-secondary" type="submit">{{ __('Sign out') }}</button>
        </form>
    </div>
</section>
@endsection
