@extends('admin.layout')

@section('title', __('Administration access'))
@section('form-page', '1')

@section('content')
<section class="panel panel-wide" aria-labelledby="administration-access-title">
    <div class="eyebrow">{{ __('Account access') }}</div>
    <h1 id="administration-access-title">{{ __('No administration sections available') }}</h1>
    <p class="reading-width">{{ __('You are signed in, but your account currently has no available administration section. Ask an Owner to review your role and permissions, or sign out.') }}</p>
    <form method="post" action="{{ route('admin.logout') }}">
        @csrf
        <button class="button button-secondary" type="submit">{{ __('Sign out') }}</button>
    </form>
</section>
@endsection
