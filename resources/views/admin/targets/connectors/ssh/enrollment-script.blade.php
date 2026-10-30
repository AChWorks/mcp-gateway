<script>
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('target-create-form');
    if (!form) return;
    const connector = form.querySelector('#connector_type');
    const method = form.querySelector('#ssh_auth_method');
    const trustedCheckbox = form.querySelector('input[name="ssh_trust_confirmed"]');
    const hostKey = form.querySelector('#ssh_host_key');
    const fingerprint = form.querySelector('#host_fingerprint');
    if (!method || !trustedCheckbox || !hostKey || !fingerprint) return;
    const syncAuthentication = () => {
        const current = method.value;
        form.querySelectorAll('[data-ssh-secret]').forEach(group => {
            const active = group.dataset.sshSecret === current;
            group.hidden = !active;
            group.querySelectorAll('input, textarea').forEach(field => {
                field.disabled = !active || connector.value !== 'ssh_direct';
                field.required = active && field.name !== 'ssh_passphrase';
            });
        });
    };
    method.addEventListener('change', syncAuthentication);
    connector.addEventListener('change', syncAuthentication);
    // If the server endpoint or pasted host key changes, prior user confirmation
    // is no longer meaningful. This is not a substitute for server-side checks.
    ['ssh_host', 'ssh_port', 'ssh_host_key'].forEach(name => {
        form.querySelector('[name="' + name + '"]').addEventListener('input', () => {
            trustedCheckbox.checked = false;
            if (name === 'ssh_host_key') fingerprint.textContent = '';
        });
    });
    form.querySelector('#show_host_fingerprint').addEventListener('click', async () => {
        const parts = hostKey.value.trim().split(/\s+/);
        fingerprint.textContent = '';
        if (parts.length !== 2 || !['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'].includes(parts[0])) {
            fingerprint.textContent = @json(__('Paste one supported public host key with no trailing comment.'));
            return;
        }
        try {
            const decoded = atob(parts[1]);
            const bytes = Uint8Array.from(decoded, c => c.charCodeAt(0));
            const data = new DataView(bytes.buffer);
            const length = data.getUint32(0);
            if (bytes.length < 16 || length !== parts[0].length ||
                new TextDecoder().decode(bytes.subarray(4, 4 + length)) !== parts[0]) {
                throw new Error('invalid public key');
            }
            const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
            fingerprint.textContent = 'SHA256:' + btoa(String.fromCharCode(...digest)).replace(/=+$/, '');
        } catch (_) {
            fingerprint.textContent = @json(__('Cannot preview this key. Check its format or use the trusted server console.'));
        }
    });
    syncAuthentication();
});
</script>
