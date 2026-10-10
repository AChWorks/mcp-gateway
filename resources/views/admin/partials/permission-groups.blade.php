@php
    // Pure presentation grouping: the existing role, Target ACL, and denial engine remain authoritative.
    $permissionSections = [
        'gateway' => [
            'title' => __('Gateway administration'),
            'help' => __('Account, security, activity and Gateway-wide operations. These permissions do not select a Target.'),
            'status' => null,
            'future' => false,
        ],
        'targets' => [
            'title' => __('Shared Target management'),
            'help' => __('Shared registration and lifecycle controls. The badge distinguishes Gateway-wide actions (such as adding a Target) from Target-scoped actions (such as connecting one).'),
            'status' => null,
            'future' => false,
        ],
        'wordpress' => [
            'title' => __('WordPress (WP AI Bridge)'),
            'help' => __('These permissions act only on WordPress Targets. They never grant access to SSH or Agent Targets.'),
            'status' => __('Available'),
            'future' => false,
        ],
        'ssh' => [
            'title' => __('Direct SSH'),
            'help' => __('SSH command execution grants remote OS-account authority, including permitted sudo/root and file access even when SFTP toggles are denied. Only a separately confirmed Owner edit may lift default-denied SSH permissions. SFTP tools are not yet available.'),
            'status' => __('Command available; SFTP pending'),
            'future' => ! ($sshPermissionsEditable ?? false),
        ],
        'agent' => [
            'title' => __('AI Server Agent'),
            'help' => __('Agent integration is paused. These identifiers are reserved and do not enable Agent operations; existing denials are retained.'),
            'status' => __('Paused'),
            'future' => true,
        ],
    ];
    $selectedDenials = is_array($selectedDenials ?? null) ? $selectedDenials : [];
    $connectorGroup = match ($connectorType ?? null) {
        'wp_ai_bridge' => 'wordpress',
        'ssh_direct' => 'ssh',
        'ai_server_agent' => 'agent',
        default => null,
    };
    $visiblePermissions = collect($permissions);
    $preservedOtherDenials = [];
    if ($connectorGroup !== null) {
        $otherConnectorPermission = static fn ($permission): bool => in_array($permission->adminGroup(), ['wordpress', 'ssh', 'agent'], true)
            && $permission->adminGroup() !== $connectorGroup;
        $preservedOtherDenials = $visiblePermissions->filter(static fn ($permission): bool => $otherConnectorPermission($permission)
            && in_array($permission->value, $selectedDenials, true))->values()->all();
        $visiblePermissions = $visiblePermissions->reject($otherConnectorPermission);
    }
    $groupedPermissions = $visiblePermissions->groupBy(static fn ($permission): string => $permission->adminGroup());
@endphp

{{-- A connector-specific Target edit must not erase older, unrelated stored denial keys. --}}
@foreach ($preservedOtherDenials as $permission)
    <input type="hidden" name="denied_permissions[]" value="{{ $permission->value }}">
@endforeach
@if ($preservedOtherDenials !== [])
    <p class="field-help">{{ __('Existing restrictions for other connector types are preserved but have no effect on this Target.') }}</p>
@endif

@foreach ($permissionSections as $group => $section)
    @php($items = $groupedPermissions->get($group, collect()))
    @if ($items->isNotEmpty())
        <section class="permission-category" aria-label="{{ $section['title'] }}">
            <div class="permission-category-heading">
                <h3>{{ $section['title'] }}</h3>
                @if ($section['status'] !== null)
                    <small>{{ $section['status'] }}</small>
                @endif
            </div>
            <p class="field-help">{{ $section['help'] }}</p>

            @if ($section['future'])
                @php($retained = $items->filter(static fn ($permission): bool => in_array($permission->value, $selectedDenials, true)))
                @foreach ($retained as $permission)
                    <input type="hidden" name="denied_permissions[]" value="{{ $permission->value }}">
                @endforeach
                <details class="permission-category-collapsible" @if ($retained->isNotEmpty()) open @endif>
                    <summary>{{ __('Review reserved permission definitions') }}@if ($retained->isNotEmpty()) ({{ __(':count existing denials retained', ['count' => $retained->count()]) }})@endif</summary>
                    <ul class="permission-reserved-list">
                        @foreach ($items as $permission)
                            <li>
                                <strong>{{ $permission->title() }}</strong>
                                <code>{{ $permission->value }}</code>
                                @if (in_array($permission->value, $selectedDenials, true))
                                    <span class="permission-reserved-note">{{ __('Existing denial retained') }}</span>
                                @endif
                            </li>
                        @endforeach
                    </ul>
                </details>
            @else
                <div class="checkbox-grid">
                    @foreach ($items as $permission)
                        @include('admin.partials.permission-option', [
                            'permission' => $permission,
                            'checked' => in_array($permission->value, $selectedDenials, true),
                        ])
                    @endforeach
                </div>
            @endif
        </section>
    @endif
@endforeach
