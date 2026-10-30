<nav class="admin-nav" aria-label="{{ __('Administration') }}">
    @foreach (app(\App\Application\Admin\AdminNavigation::class)->sections(auth()->user()) as $section)
        <section class="nav-group" aria-labelledby="nav-{{ $section['id'] }}-title">
            <h2 id="nav-{{ $section['id'] }}-title" class="nav-group-title">{{ $section['label'] }}</h2>
            @foreach ($section['items'] as $item)
                @include('admin.partials.navigation-link', $item)
            @endforeach
        </section>
    @endforeach
</nav>
