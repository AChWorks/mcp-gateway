@php($permissionId = 'permission-'.str_replace('.', '-', $permission->value))
<label class="checkbox-option permission-option" title="{{ $permission->description() }}">
    <input
        type="checkbox"
        name="denied_permissions[]"
        value="{{ $permission->value }}"
        aria-label="{{ __('Deny :permission', ['permission' => $permission->title()]) }}"
        aria-describedby="{{ $permissionId }}-scope {{ $permissionId }}-key {{ $permissionId }}-help"
        @checked($checked)
    >
    <span class="permission-copy">
        <span class="permission-heading">
            <span class="permission-label">{{ $permission->title() }}</span>
            <span class="badge badge-neutral permission-scope" id="{{ $permissionId }}-scope">{{ $permission->scopeLabel() }}</span>
        </span>
        <code class="permission-key" id="{{ $permissionId }}-key" dir="ltr">{{ $permission->value }}</code>
        <span class="permission-help" id="{{ $permissionId }}-help">{{ $permission->description() }}</span>
    </span>
</label>
