<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <title>@yield('title', __('Administration')) · {{ config('app.name') }}</title>
    <link rel="stylesheet" href="{{ asset('css/admin.css') }}">
</head>
<body>
<header class="site-header">
    <div class="shell header-inner">
        <a class="brand" href="{{ auth()->check() ? route('admin.dashboard') : route('login') }}">
            {{ __('MCP Gateway') }}
        </a>

        @auth
            <form method="post" action="{{ route('admin.logout') }}">
                @csrf
                <button class="button button-secondary" type="submit">{{ __('Sign out') }}</button>
            </form>
        @endauth
    </div>
</header>

<main class="shell main-content">
    @yield('content')
</main>
</body>
</html>
