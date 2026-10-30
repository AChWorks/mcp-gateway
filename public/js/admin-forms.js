(() => {
    'use strict';

    const initialized = new WeakMap();
    function claim(element, name) {
        const names = initialized.get(element) || new Set();
        if (names.has(name)) return false;
        names.add(name);
        initialized.set(element, names);
        return true;
    }

    function initEnrollment(root) {
    const form = root.querySelector('#target-create-form');
    if (!form || !claim(form, 'Enrollment')) return;
    const connector = form.querySelector('#connector_type');
    const shared = form.querySelector('[data-target-shared]');
    const panels = form.querySelectorAll('[data-connector-panel]');
    const actions = form.querySelector('[data-target-actions]');
    const preflight = form.querySelector('#target-endpoint-preflight');
    const staleNotice = form.querySelector('#target-preflight-stale');

    // This is a time-of-check observation, never a future authorization. As
    // soon as the connector or any checked field changes, old success is stale.
    let preflightInvalidated = false;
    let checkedFields = null;
    if (preflight && preflight.dataset.checkedConnector) {
        try {
            checkedFields = JSON.parse(preflight.dataset.checkedFields || '{}');
        } catch (_) {
            preflightInvalidated = true;
        }
    }
    const syncPreflight = () => {
        if (!preflight || !preflight.dataset.checkedConnector) return;
        if (connector.value !== preflight.dataset.checkedConnector) preflightInvalidated = true;
        if (!checkedFields || !Object.entries(checkedFields).every(([name, value]) => {
            const field = Array.from(form.elements).find(el => el.name === name);
            return field && field.value === String(value);
        })) preflightInvalidated = true;
        if (preflightInvalidated) {
            preflight.hidden = true;
            if (staleNotice) staleNotice.hidden = false;
        }
    };
    Object.keys(checkedFields || {}).forEach(name => {
        const field = form.elements.namedItem(name);
        if (field) {
            field.addEventListener('input', syncPreflight);
            field.addEventListener('change', syncPreflight);
        }
    });

    const syncConnector = () => {
        const current = connector.value;
        shared.hidden = !current;
        shared.disabled = !current;
        actions.hidden = !current;
        panels.forEach(panel => {
            const active = panel.dataset.connectorPanel === current;
            panel.hidden = !active;
            panel.disabled = !active;
        });
        syncPreflight();
    };
    connector.addEventListener('change', syncConnector);
    syncConnector();
    }

    function initSshEnrollment(root) {
    const form = root.querySelector('#target-create-form');
    if (!form || !claim(form, 'SshEnrollment')) return;
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
            fingerprint.textContent = fingerprint.dataset.invalidMessage;
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
            fingerprint.textContent = fingerprint.dataset.unavailableMessage;
        }
    });
    syncAuthentication();
    }

    function initSshConfiguration(root) {
    const form = root.querySelector('#ssh-reconfiguration');
    if (!form || !claim(form, 'SshConfiguration')) return;
    const method = form.querySelector('#ssh_edit_auth_method');
    const trust = form.querySelector('input[name="ssh_trust_confirmed"]');
    const sync = () => {
        form.querySelectorAll('[data-edit-ssh-credential]').forEach(group => {
            const active = group.dataset.editSshCredential === method.value;
            group.hidden = !active;
            group.querySelectorAll('input,textarea').forEach(field => field.disabled = !active);
        });
    };
    method.addEventListener('change', sync);
    ['ssh_host','ssh_port','ssh_username','ssh_host_key'].forEach(name => {
        form.querySelector('[name="' + name + '"]').addEventListener('input', () => {
            trust.checked = false;
        });
    });
    sync();
    }

    function initSettings(root) {
    root.querySelectorAll('[data-clear-setting]').forEach(button => {
        const input = root.getElementById(button.dataset.clearSetting);
        if (!input || !claim(button, 'reset')) return;
        button.hidden = false;
        button.addEventListener('click', () => {
            input.value = '';
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.focus();
        });
    });
    }
    function init(root = document) {
        initEnrollment(root);
        initSshEnrollment(root);
        initSshConfiguration(root);
        initSettings(root);
    }
    document.addEventListener('gateway:admin-ready', event => init(event.detail.root));
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => init(), { once: true });
    } else {
        init();
    }
})();
