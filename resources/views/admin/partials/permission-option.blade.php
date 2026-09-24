<label class="checkbox-option permission-option" title="{{ $permission->description() }}">
    <input
        type="checkbox"
        name="denied_permissions[]"
        value="{{ $permission->value }}"
        @checked($checked)
    >
    <span class="permission-copy">
        <span class="permission-heading">
            <span class="permission-label">{{ $permission->title() }}</span>
            <span class="badge badge-neutral permission-scope">{{ $permission->scopeLabel() }}</span>
        </span>
        <code class="permission-key">{{ $permission->value }}</code>
        <span class="permission-help">{{ $permission->description() }}</span>
    </span>
</label>
