<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" data-turbo="false">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <meta name="turbo-cache-control" content="no-cache">
    <meta name="turbo-prefetch" content="false">
    @guest<meta name="turbo-visit-control" content="reload">@endguest
    <title>@yield('title', __('Administration')) · {{ config('app.name') }}</title>
    @php
        // Fingerprint bytes as well as VERSION: corrected builds of the same
        // release must not retain stale shared styles or behavior.
        $cssDigest = hash_file('sha256', public_path('css/admin.css'));
        $cssFingerprint = is_string($cssDigest) ? substr($cssDigest, 0, 12) : 'unavailable';
        $jsDigest = hash_file('sha256', public_path('js/admin.js'));
        $jsFingerprint = is_string($jsDigest) ? substr($jsDigest, 0, 12) : 'unavailable';
    @endphp
    <link data-turbo-track="reload" rel="stylesheet" href="{{ asset('css/admin.css').'?v='.rawurlencode((string) config('app.release_version', 'dev')).'-'.$cssFingerprint }}">
    <script src="{{ asset('js/admin.js').'?v='.rawurlencode((string) config('app.release_version', 'dev')).'-'.$jsFingerprint }}" data-turbo-track="reload" defer></script>
    @auth
        @foreach (['admin-navigation.js', 'vendor/turbo-8.0.23.js', 'admin-forms.js'] as $adminScript)
            @php($scriptFingerprint = substr((string) hash_file('sha256', public_path('js/'.$adminScript)), 0, 12))
            <script src="{{ asset('js/'.$adminScript).'?v='.rawurlencode((string) config('app.release_version', 'dev')).'-'.$scriptFingerprint }}" data-turbo-track="reload" defer></script>
        @endforeach
    @endauth
    @yield('head')
</head>
<body @class(['admin-app' => auth()->check(), 'auth-page' => ! auth()->check()])
    data-admin-root="{{ route('admin.dashboard') }}"
    data-unsaved-message="{{ __('You have unsaved changes. Leave this page and discard them?') }}"
    data-loading-message="{{ __('Loading page…') }}"
    data-navigation-error-message="{{ __('The page could not be loaded. Use the original link to try again.') }}">
<a class="skip-link" href="#main-content">{{ __('Skip to main content') }}</a>
<div @class(['admin-shell' => auth()->check(), 'guest-shell' => ! auth()->check()])>
    @auth
        <aside class="admin-sidebar" aria-label="{{ __('Gateway administration') }}">
            <div class="sidebar-heading">
                <a class="brand" href="{{ app(\App\Application\Admin\AdminNavigation::class)->landingUrl(auth()->user()) }}">
                    <span class="brand-mark" aria-hidden="true">M</span>
                    <span>{{ __('MCP Gateway') }}<small>{{ __('Administration') }}</small></span>
                </a>
                <button class="nav-toggle" type="button" aria-controls="admin-navigation" aria-expanded="true" data-admin-nav-toggle hidden>
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
                    <span>{{ __('Navigation') }}</span>
                </button>
            </div>
            <div id="admin-navigation" class="sidebar-content" data-admin-navigation>
                @include('admin.partials.navigation')
                <div class="sidebar-account">
                    <span class="sidebar-account-name">{{ auth()->user()?->name }}</span>
                    <span class="sidebar-account-role">{{ __(ucfirst((string) auth()->user()?->role->value)) }}</span>
                    <form method="post" action="{{ route('admin.logout') }}">
                        @csrf
                        <button class="sidebar-sign-out" type="submit">{{ __('Sign out') }}</button>
                    </form>
                </div>
            </div>
        </aside>
    @endauth

    <div @class(['admin-workspace', 'form-workspace' => $__env->hasSection('form-page')])>
        <header class="site-header">
            <div class="shell header-inner">
                @auth
                    <p class="workspace-context"><span>{{ __('Administration') }}</span><span aria-hidden="true">/</span><strong>@yield('title', __('Dashboard'))</strong></p>
                @else
                    <a class="brand" href="{{ route('login') }}">{{ __('MCP Gateway') }}</a>
                @endauth
            </div>
        </header>

        <p id="admin-navigation-status" class="sr-only" role="status" aria-live="polite" aria-atomic="true"></p>
        <main id="main-content" @class(['shell', 'main-content', 'form-page' => $__env->hasSection('form-page')]) tabindex="-1">
            @if (session('status'))
                <div class="alert alert-success" role="status">{{ session('status') }}</div>
            @endif

            @if ($errors->has('site'))
                <div class="alert alert-error" role="alert">{{ $errors->first('site') }}</div>
            @endif

            @if (session('target_connection_failed'))
                <div class="alert alert-error" role="alert">{{ __('Target authorization did not complete. Open your Target and try again.') }}</div>
            @endif
            @if ($errors->has('target'))
                <div class="alert alert-error" role="alert">{{ $errors->first('target') }}</div>
            @endif
            @if (session('diagnostic_code'))
                <section class="panel" aria-label="{{ __('Operation diagnostic') }}" role="status">
                    <p><strong>{{ __('Diagnostic category') }}:</strong>
                        <code>{{ session('diagnostic_code') }}</code>
                        @if (session('diagnostic_stage'))
                            · <strong>{{ __('Failure stage') }}:</strong> <code>{{ session('diagnostic_stage') }}</code>
                        @endif
                    </p>
                    <p>{{ \App\Support\OperationDiagnostics::summary((string) session('diagnostic_code'), (array) session('diagnostic_context', [])) }}</p>
                    <p><strong>{{ __('What to check') }}:</strong> {{ \App\Support\OperationDiagnostics::nextStep((string) session('diagnostic_code'), (array) session('diagnostic_context', [])) }}</p>
                    @if (session('diagnostic_reference'))
                        <p><strong>{{ __('Log reference') }}:</strong> <code>{{ session('diagnostic_reference') }}</code></p>
                    @endif
                </section>
            @endif

            @yield('content')
        </main>
    </div>
</div>
</body>
</html>
