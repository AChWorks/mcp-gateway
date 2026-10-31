@php
    // Pure presentation grouping: the existing role, Target ACL, and denial engine remain authoritative.
    $sshPermissionContext = in_array($sshPermissionContext ?? null, ['user', 'group', 'target'], true)
        ? $sshPermissionContext : 'user';
    $sshHelp = match ($sshPermissionContext) {
        'group' => __('Live SSH controls. Checked boxes DENY the capability for assigned users on matching Targets. Removing a denial never grants a capability that the user role/global policy lacks.'),
        'target' => __('Live SSH controls for this exact Target. Checked boxes DENY the capability. Unchecking only removes this Target-level restriction; global role/grants, groups and Target reachability still apply.'),
        default => __('Live SSH controls. Checked boxes DENY the capability; unchecked boxes may authorize it only for a separately selected Target and a role that allows SSH. Every SSH command can read/write files and use permitted sudo/root even if the SFTP boxes remain denied.'),
    };
    $sshStatus = match ($sshPermissionContext) {
        'group' => __('Active · deny-only'),
        'target' => __('Active · Target-specific denies'),
        default => __('Active · Owner-confirmed'),
    };
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
            'help' => __('These permissions act only on WordPress Targets. They never grant access to other connector types.'),
            'status' => __('Available'),
            'future' => false,
        ],
        'ssh' => [
            'title' => __('Direct SSH'),
            'help' => $sshHelp,
            'status' => ($sshPermissionsEditable ?? false) ? $sshStatus : __('Requires Owner edit'),
            'future' => ! ($sshPermissionsEditable ?? false),
        ],
    ];
    $selectedDenials = is_array($selectedDenials ?? null) ? $selectedDenials : [];
    $connectorGroup = match ($connectorType ?? null) {
        'wp_ai_bridge' => 'wordpress',
        'ssh_direct' => 'ssh',
        default => null,
    };
    $visiblePermissions = collect($permissions);
    $preservedOtherDenials = [];
    if ($connectorGroup !== null) {
        $otherConnectorPermission = static fn ($permission): bool => in_array($permission->adminGroup(), ['wordpress', 'ssh'], true)
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
                    <summary>{{ __('SSH settings require an authorized Owner editor') }}@if ($retained->isNotEmpty()) ({{ __(':count existing denials retained', ['count' => $retained->count()]) }})@endif</summary>
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
                @if ($group === 'ssh')
                    <p class="permission-safety-hint"><strong>{{ __('Checked = DENY. Unchecked = potentially ALLOW, never beyond role and Target scope.') }}</strong></p>
                @endif
                <div class="checkbox-grid">
                    @foreach ($items as $permission)
                        @include('admin.partials.permission-option', [
                            'permission' => $permission,
                            'checked' => in_array($permission->value, $selectedDenials, true),
                            'displayChoiceStatus' => $displayChoiceStatus ?? false,
                        ])
                    @endforeach
                </div>
            @endif
        </section>
    @endif
@endforeach
