@php
    // Pure presentation grouping: the existing role, Target ACL, and denial engine remain authoritative.
    $sshPermissionContext = in_array($sshPermissionContext ?? null, ['user', 'group', 'target'], true)
        ? $sshPermissionContext : 'user';
    $sshHelp = match ($sshPermissionContext) {
        'group' => __('Live SSH controls. Checked boxes DENY the capability for assigned users on matching Targets. Removing a denial never grants a capability that the user role/global policy lacks.'),
        'target' => __('Live SSH controls for this exact Target. Checked boxes DENY the capability. Unchecking only removes this Target-level restriction; global role/grants, groups and Target reachability still apply.'),
        default => __('SSH is available within Administrator and Operator roles, but starts DENIED for new users. A checked box blocks the tool; an unchecked box can enable it only after an Owner-confirmed Save on explicitly Selected Targets. Existing account choices are loaded from saved global Denies. SSH commands may read/write files and use permitted sudo/root even when SFTP is denied.'),
    };
    $sshStatus = match ($sshPermissionContext) {
        'group' => __('Active · deny-only'),
        'target' => __('Active · Target-specific denies'),
        default => __('Owner-gated · new users default DENY'),
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
    $roleAwareUser = (bool) ($roleAwareUser ?? false);
    $selectedUserRole = $roleAwareUser
        ? ($selectedUserRole ?? \App\Domain\Access\GatewayRole::Operator)
        : null;
    $isRestrictable = static fn ($permission): bool => $selectedUserRole !== \App\Domain\Access\GatewayRole::Owner
        && $selectedUserRole?->allows($permission) === true;
    $rolesAllowingRestriction = static fn ($permission): string => implode(' ', array_map(
        static fn ($role): string => $role->value,
        array_filter(\App\Domain\Access\GatewayRole::cases(),
            static fn ($role): bool => $role !== \App\Domain\Access\GatewayRole::Owner && $role->allows($permission)),
    ));
    $roleEligibleCount = $roleAwareUser ? $visiblePermissions->filter($isRestrictable)->count() : 0;
    $roleUnavailableCount = $visiblePermissions->count() - $roleEligibleCount;
@endphp

{{-- A connector-specific Target edit must not erase older, unrelated stored denial keys. --}}
@foreach ($preservedOtherDenials as $permission)
    <input type="hidden" name="denied_permissions[]" value="{{ $permission->value }}">
@endforeach
@if ($preservedOtherDenials !== [])
    <p class="field-help">{{ __('Existing restrictions for other connector types are preserved but have no effect on this Target.') }}</p>
@endif

@if ($roleAwareUser)
    <div data-user-role-restrictions
        data-role-summary-template="{{ __(':role: :eligible capabilities can be restricted; :unavailable are already excluded by the Role.') }}"
        data-role-owner-summary="{{ __('Owner has no global Deny controls. When enabled, Owner bypasses Target restrictions for recovery.') }}">
        <p class="field-help" role="status" aria-live="polite" data-user-role-summary>{{ $selectedUserRole === \App\Domain\Access\GatewayRole::Owner
            ? __('Owner has no global Deny controls. When enabled, Owner bypasses Target restrictions for recovery.')
            : __(':role: :eligible capabilities can be restricted; :unavailable are already excluded by the Role.', ['role' => \Illuminate\Support\Str::headline($selectedUserRole->value), 'eligible' => $roleEligibleCount, 'unavailable' => $roleUnavailableCount]) }}</p>
@endif

@foreach ($permissionSections as $group => $section)
    @php($items = $groupedPermissions->get($group, collect()))
    @if ($items->isNotEmpty())
        <section class="permission-category" aria-label="{{ $section['title'] }}"
            @if ($roleAwareUser) data-user-role-section @if (! $items->contains($isRestrictable)) hidden @endif @endif>
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
                    <p class="permission-safety-hint"><strong>{{ $roleAwareUser
                        ? __('New users: all three SSH Denies are checked for safety. Existing users: checkboxes reflect saved Denies on a fresh visit. Uncheck only for an intentional Owner-approved SSH grant; Save to apply.')
                        : __('Checked = DENY. Unchecked = potentially ALLOW, never beyond role and Target scope.') }}</strong></p>
                @endif
                <div class="checkbox-grid">
                    @foreach ($items as $permission)
                        @include('admin.partials.permission-option', [
                            'permission' => $permission,
                            'checked' => in_array($permission->value, $selectedDenials, true),
                            'displayChoiceStatus' => $displayChoiceStatus ?? false,
                            'roleAwareUser' => $roleAwareUser,
                            'roleChoiceAllowed' => ! $roleAwareUser || $isRestrictable($permission),
                            'roleChoiceAllowedRoles' => $roleAwareUser ? $rolesAllowingRestriction($permission) : '',
                            'roleChoiceIsSsh' => $roleAwareUser && $group === 'ssh',
                        ])
                    @endforeach
                </div>
            @endif
        </section>
    @endif
@endforeach

@if ($roleAwareUser)
    <div data-user-role-owner-note @if ($selectedUserRole !== \App\Domain\Access\GatewayRole::Owner) hidden @endif>
        <p class="field-help">{{ __('Owner does not need global Deny restrictions. When account access is enabled, Target restrictions are bypassed for recovery.') }}</p>
    </div>
    <details class="permission-category-collapsible" data-user-role-unavailable
        @if ($selectedUserRole === \App\Domain\Access\GatewayRole::Owner) hidden @endif>
        <summary>{{ __('Already unavailable in this Role') }} (<span data-role-unavailable-count>{{ $roleUnavailableCount }}</span>)</summary>
        <p class="field-help">{{ __('These capabilities are excluded by the selected Role. They cannot be enabled or denied here. Choosing another Role may change which restrictions are editable.') }}</p>
        <ul class="permission-reserved-list">
            @foreach ($visiblePermissions as $permission)
                <li data-user-role-unavailable-item data-allowed-roles="{{ $rolesAllowingRestriction($permission) }}"
                    @if ($isRestrictable($permission)) hidden @endif>
                    <strong>{{ $permission->title() }}</strong>
                    <code dir="ltr">{{ $permission->value }}</code>
                </li>
            @endforeach
        </ul>
    </details>
    </div>
@endif
