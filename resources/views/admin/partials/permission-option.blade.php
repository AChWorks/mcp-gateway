@php($permissionId = 'permission-'.str_replace('.', '-', $permission->value))
<label class="checkbox-option permission-option" title="{{ $permission->description() }}"
    @if ($roleAwareUser ?? false)
        data-user-role-choice data-allowed-roles="{{ $roleChoiceAllowedRoles }}"
        @if ($roleChoiceIsSsh ?? false) data-user-role-ssh-choice @endif
        @if (! $roleChoiceAllowed) hidden @endif
    @endif>
    <input
        type="checkbox"
        name="denied_permissions[]"
        value="{{ $permission->value }}"
        aria-label="{{ __('Deny :permission', ['permission' => $permission->title()]) }}"
        aria-describedby="{{ $permissionId }}-scope {{ $permissionId }}-key {{ $permissionId }}-help{{ ($displayChoiceStatus ?? false) ? ' '.$permissionId.'-choice' : '' }}"
        @checked($checked)
        @disabled(($roleAwareUser ?? false) && ! $roleChoiceAllowed)
    >
    <span class="permission-copy">
        <span class="permission-heading">
            <span class="permission-label">{{ __('Deny :permission', ['permission' => $permission->title()]) }}</span>
            <span class="badge badge-neutral permission-scope" id="{{ $permissionId }}-scope">{{ $permission->scopeLabel() }}</span>
        </span>
        <code class="permission-key" id="{{ $permissionId }}-key" dir="ltr">{{ $permission->value }}</code>
        <span class="permission-help" id="{{ $permissionId }}-help">{{ $permission->description() }}</span>
        @if ($displayChoiceStatus ?? false)
            <span class="permission-help permission-choice" id="{{ $permissionId }}-choice">
                <span data-global-deny-choice="denied">{{ __('Current form choice: Deny globally — save to apply changes') }}</span>
                <span data-global-deny-choice="not-denied">{{ __('Current form choice: No global Deny — other restrictions may apply; save to apply changes') }}</span>
            </span>
        @endif
    </span>
</label>
