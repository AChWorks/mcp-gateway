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
            <nav class="admin-nav" aria-label="{{ __('Administration') }}">
                @can('dashboard.view')
                    <a @class(['nav-link', 'is-active' => request()->routeIs('admin.dashboard')]) href="{{ route('admin.dashboard') }}">{{ __('Dashboard') }}</a>
                @endcan
                @can('sites.view')
                    <a @class(['nav-link', 'is-active' => request()->routeIs('admin.sites.*')]) href="{{ route('admin.sites.index') }}">{{ __('Sites') }}</a>
                @endcan
                @can('activity.view')
                    <a @class(['nav-link', 'is-active' => request()->routeIs('admin.activity')]) href="{{ route('admin.activity') }}">{{ __('Activity') }}</a>
                @endcan
                @can('connection.view')
                    <a @class(['nav-link', 'is-active' => request()->routeIs('admin.connection')]) href="{{ route('admin.connection') }}">{{ __('Connection') }}</a>
                @endcan
            </nav>

            <form method="post" action="{{ route('admin.logout') }}">
                @csrf
                <button class="button button-secondary" type="submit">{{ __('Sign out') }}</button>
            </form>
        @endauth
    </div>
</header>

<main class="shell main-content">
    @if (session('status'))
        <div class="alert alert-success" role="status">{{ session('status') }}</div>
    @endif

    @if (session('site_connection_status'))
        @if (str_starts_with((string) session('site_connection_status'), 'connected:'))
            <div class="alert alert-success" role="status">{{ __('WordPress authorization completed successfully.') }}</div>
        @else
            <div class="alert alert-error" role="alert">{{ __('WordPress authorization did not complete. Open the site details and retry when ready.') }}</div>
        @endif
    @endif

    @if ($errors->has('site'))
        <div class="alert alert-error" role="alert">{{ $errors->first('site') }}</div>
    @endif

    @yield('content')
</main>
</body>
</html>
