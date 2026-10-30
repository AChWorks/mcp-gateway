<nav class="admin-nav" aria-label="{{ __('Administration') }}">
    @canany(['dashboard.view', 'targets.view', 'activity.view'])
        <section class="nav-group" aria-labelledby="nav-workspace-title">
            <h2 id="nav-workspace-title" class="nav-group-title">{{ __('Workspace') }}</h2>
            @can('dashboard.view')
                @include('admin.partials.navigation-link', ['destination' => 'admin.dashboard', 'activePattern' => 'admin.dashboard', 'label' => __('Dashboard'), 'icon' => 'dashboard'])
            @endcan
            @can('targets.view')
                @include('admin.partials.navigation-link', ['destination' => 'admin.targets.index', 'activePattern' => 'admin.targets.*', 'label' => __('Targets'), 'icon' => 'targets'])
            @endcan
            @can('activity.view')
                @include('admin.partials.navigation-link', ['destination' => 'admin.activity', 'activePattern' => 'admin.activity', 'label' => __('Activity'), 'icon' => 'activity'])
            @endcan
        </section>
    @endcanany

    @canany(['users.view', 'users.manage', 'security.manage'])
        <section class="nav-group" aria-labelledby="nav-access-title">
            <h2 id="nav-access-title" class="nav-group-title">{{ __('Access') }}</h2>
            @can('users.view')
                @include('admin.partials.navigation-link', ['destination' => 'admin.users.index', 'activePattern' => 'admin.users.*', 'label' => __('Users'), 'icon' => 'users'])
            @endcan
            @can('users.manage')
                @include('admin.partials.navigation-link', ['destination' => 'admin.target-groups.index', 'activePattern' => 'admin.target-groups.*', 'label' => __('Target groups'), 'icon' => 'groups'])
            @endcan
            @can('security.manage')
                @include('admin.partials.navigation-link', ['destination' => 'admin.oauth-clients.index', 'activePattern' => 'admin.oauth-clients.*', 'label' => __('AI clients'), 'icon' => 'clients'])
            @endcan
        </section>
    @endcanany

    @if (\Illuminate\Support\Facades\Gate::allows('gateway.connection.view') || auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner)
        <section class="nav-group" aria-labelledby="nav-system-title">
            <h2 id="nav-system-title" class="nav-group-title">{{ __('System') }}</h2>
            @can('gateway.connection.view')
                @include('admin.partials.navigation-link', ['destination' => 'admin.connection', 'activePattern' => 'admin.connection', 'label' => __('Connection information'), 'icon' => 'connection'])
            @endcan
            @if (auth()->user()?->role === \App\Domain\Access\GatewayRole::Owner)
                @include('admin.partials.navigation-link', ['destination' => 'admin.operations.index', 'activePattern' => 'admin.operations.*', 'label' => __('Operational settings'), 'icon' => 'settings'])
            @endif
        </section>
    @endif
</nav>
