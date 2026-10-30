@php($current = request()->routeIs($activePattern))
<a @class(['nav-link', 'is-active' => $current]) href="{{ route($destination) }}" @if ($current) aria-current="page" @endif>
    <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
        @switch($icon)
            @case('dashboard')
                <path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/>
                @break
            @case('targets')
                <rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6h.01M7 17h.01M11 6h6M11 17h6"/>
                @break
            @case('activity')
                <path d="M2 12h5l3-8 4 16 3-8h5"/>
                @break
            @case('users')
                <circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3M17 5a3 3 0 0 1 0 6M21 21v-3a6 6 0 0 0-4-5"/>
                @break
            @case('groups')
                <path d="M3 7V5a2 2 0 0 1 2-2h5l3 4h6a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>
                @break
            @case('clients')
                <circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-4-4 3-3m-6 0 3-3"/>
                @break
            @case('connection')
                <path d="m10 13 4-4M8 16l-2 2a4 4 0 0 1-6-6l5-5a4 4 0 0 1 6 0M16 8l2-2a4 4 0 0 1 6 6l-5 5a4 4 0 0 1-6 0"/>
                @break
            @case('settings')
                <path d="M4 3v18M12 3v18M20 3v18M1 8h6M9 15h6M17 8h6"/>
                @break
        @endswitch
    </svg>
    <span>{{ $label }}</span>
</a>
