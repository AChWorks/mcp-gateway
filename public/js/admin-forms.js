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
    const shortcuts = form.querySelector('[data-target-ssh-shortcuts]');
    const sshMode = form.querySelector('#ssh_mode');

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
        if (shortcuts) shortcuts.hidden = current === 'ssh_direct';
        syncPreflight();
    };
    connector.addEventListener('change', syncConnector);
    sshMode?.addEventListener('change', () => {
        // A preflight for Direct/Manual must not remain visibly valid after
        // changing the SSH route, even when the real host/port are unchanged.
        preflightInvalidated = true;
        syncPreflight();
    });
    shortcuts?.querySelectorAll('[data-target-ssh-shortcut]').forEach(link => {
        link.addEventListener('click', event => {
            if (event.defaultPrevented || event.button !== 0 || event.metaKey
                || event.ctrlKey || event.shiftKey || event.altKey || !sshMode) return;
            event.preventDefault();
            connector.value = 'ssh_direct';
            connector.dispatchEvent(new Event('change', { bubbles: true }));
            sshMode.value = link.dataset.targetSshShortcut;
            // The trusted shortcut click intentionally stages this select.
            // A bare script-driven select/change elsewhere must remain inert.
            if (event.isTrusted) sshMode.dataset.adminStagedEdit = 'true';
            sshMode.dispatchEvent(new Event('change', { bubbles: true }));
            form.querySelector('#target_id')?.focus();
        });
    });
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
    const routeMode = form.querySelector('#ssh_mode');
    // Without JS this selector is intentionally inert; mode links render a
    // server-owned POST action. Progressive behavior activates it in-place.
    if (routeMode) routeMode.disabled = false;
    const standardFields = form.querySelector('[data-ssh-standard]');
    const managedFields = form.querySelector('[data-ssh-managed]');
    const manualFields = form.querySelector('[data-ssh-reverse-route]');
    const routeValue = form.querySelector('[data-ssh-route-value]');
    const submit = form.querySelector('[data-target-submit]');
    const preflightAction = form.querySelector('[data-target-preflight]');
    const preflightHelp = form.querySelector('[data-target-preflight-help]');
    const initialSubmitLabel = submit?.textContent || '';
    const managedSubmitLabel = 'Create Pending Setup and installer command';

    const syncRoute = () => {
        const ssh = connector.value === 'ssh_direct';
        const managed = ssh && routeMode?.value === 'managed';
        const manual = ssh && routeMode?.value === 'manual';
        if (manualFields) {
            manualFields.hidden = !manual;
            manualFields.querySelectorAll('input').forEach(field => {
                field.disabled = !manual;
                field.required = manual;
            });
        }
        if (managedFields) {
            managedFields.hidden = !managed;
            managedFields.querySelectorAll('input').forEach(field => {
                field.disabled = !managed;
                field.required = managed;
            });
        }
        if (standardFields) standardFields.hidden = managed;
        if (routeValue) {
            routeValue.disabled = managed || !ssh;
            routeValue.value = manual ? 'reverse' : 'direct';
        }
        if (submit) {
            submit.textContent = managed ? managedSubmitLabel : (submit.dataset.standardLabel || initialSubmitLabel);
            submit.disabled = managed && form.dataset.managedReady !== 'true';
        }
        if (preflightAction) {
            preflightAction.hidden = managed;
            preflightAction.disabled = managed;
        }
        if (preflightHelp) preflightHelp.hidden = managed;
        form.action = managed ? form.dataset.managedAction : form.dataset.standardAction;
    };
    if (submit) {
        submit.dataset.standardLabel = routeMode?.value === 'managed' ? 'Register Target' : initialSubmitLabel;
    }
    routeMode?.addEventListener('change', () => {
        trustedCheckbox.checked = false;
        syncRoute();
        syncAuthentication();
    });
    connector.addEventListener('change', syncRoute);
    syncRoute();
    const syncAuthentication = () => {
        const current = method.value;
        const standard = routeMode?.value !== 'managed' && connector.value === 'ssh_direct';
        method.disabled = !standard;
        form.querySelectorAll('[data-ssh-secret]').forEach(group => {
            const active = group.dataset.sshSecret === current;
            group.hidden = !active;
            group.querySelectorAll('input, textarea').forEach(field => {
                field.disabled = !active || !standard;
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
    const routeMode = form.querySelector('#ssh_edit_route_mode');
    const syncRoute = () => {
        const reverse = routeMode?.value === 'reverse';
        const routeFields = form.querySelector('[data-ssh-reverse-route]');
        if (routeFields) routeFields.hidden = !reverse;
        form.querySelectorAll('[data-ssh-reverse-route] input').forEach(field => {
            field.disabled = !reverse;
            field.required = reverse;
        });
    };
    routeMode?.addEventListener('change', () => {
        trust.checked = false;
        syncRoute();
    });
    syncRoute();
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

    function initUserRoleRestrictions(root) {
    const form = root.querySelector('[data-user-role-form]');
    if (!form || !claim(form, 'UserRoleRestrictions')) return;
    const role = form.querySelector('#role');
    const panel = form.querySelector('[data-user-role-restrictions]');
    if (!role || !panel) return;

    const choices = Array.from(panel.querySelectorAll('[data-user-role-choice]'));
    const sshChoices = choices.filter(choice => choice.hasAttribute('data-user-role-ssh-choice'));
    const unavailable = Array.from(panel.querySelectorAll('[data-user-role-unavailable-item]'));
    const sections = Array.from(panel.querySelectorAll('[data-user-role-section]'));
    const roleStatus = panel.querySelector('[data-user-role-summary]');
    const unavailablePanel = panel.querySelector('[data-user-role-unavailable]');
    const unavailableCount = panel.querySelector('[data-role-unavailable-count]');
    const ownerNote = panel.querySelector('[data-user-role-owner-note]');
    const checkedCount = form.querySelector('[data-user-checked-count]');
    const sshReview = form.querySelector('[data-user-role-ssh-review]');
    const state = form.querySelector('[data-user-permission-state]');

    const permitted = (element, selectedRole) =>
        selectedRole !== 'owner' && (element.dataset.allowedRoles || '').split(' ').includes(selectedRole);
    // Keep user intent separate from automatic deny-default initialization:
    // a temporarily disabled deliberate draft survives Role switching.
    const choiceBaselines = new WeakMap();
    choices.forEach(choice => {
        const checkbox = choice.querySelector('input[name="denied_permissions[]"]');
        choiceBaselines.set(checkbox, checkbox.checked);
    });

    // A Viewer/Owner account has no stored SSH Denies because its Role
    // excludes SSH already. On the FIRST in-form promotion to Operator/Admin,
    // preselect safe SSH Denies instead of suggesting three implicit grants.
    // After entry, keep the actual draft choices across later Role switches.
    let sshChoicesInitialized = sshChoices.some(choice => permitted(choice, role.value));
    const seedNewSshRole = () => {
        if (sshChoicesInitialized) return;
        const newlyEligible = sshChoices.filter(choice => permitted(choice, role.value));
        if (!newlyEligible.length) return;
        newlyEligible.forEach(choice => {
            const checkbox = choice.querySelector('input[name="denied_permissions[]"]');
            checkbox.checked = true;
            // This is a safety default, not an unsaved edit by the user.
            choiceBaselines.set(checkbox, true);
        });
        sshChoicesInitialized = true;
    };

    const sync = (changed) => {
        const current = role.value;
        const owner = current === 'owner';
        let eligible = 0, denied = 0;
        choices.forEach(choice => {
            const allowed = permitted(choice, current);
            const checkbox = choice.querySelector('input[name="denied_permissions[]"]');
            choice.hidden = !allowed;
            checkbox.disabled = !allowed;
            if (allowed) {
                eligible++;
                if (checkbox.checked) denied++;
            }
        });
        unavailable.forEach(item => { item.hidden = owner || permitted(item, current); });
        sections.forEach(section => {
            section.hidden = !Array.from(section.querySelectorAll('[data-user-role-choice]'))
                .some(choice => !choice.hidden);
        });
        const excluded = choices.length - eligible;
        ownerNote.hidden = !owner;
        unavailablePanel.hidden = owner;
        unavailableCount.textContent = String(excluded);
        const roleName = role.selectedOptions[0]?.textContent.trim() || current;
        roleStatus.textContent = owner ? panel.dataset.roleOwnerSummary
            : panel.dataset.roleSummaryTemplate
                .replace(':role', roleName).replace(':eligible', String(eligible))
                .replace(':unavailable', String(excluded));

        if (sshReview) {
            const show = current === 'operator' || current === 'administrator';
            sshReview.hidden = !show;
            sshReview.querySelectorAll('input').forEach(input => { input.disabled = !show; });
        }
        if (changed && state) {
            state.dataset.userPermissionState = 'editing';
            state.textContent = state.dataset.userDraftMessage;
        }
        if (checkedCount) {
            // Failed saves flash submitted input and are NOT persisted. An
            // initializer must never re-label that unsaved draft Saved/Defaults.
            const stateName = state?.dataset.userPermissionState;
            const unsaved = changed || stateName === 'editing' || stateName === 'submitted';
            const template = unsaved ? checkedCount.dataset.pendingTemplate : checkedCount.dataset.statusTemplate;
            checkedCount.textContent = template.replace(':count', String(denied));
        }
    };
    role.addEventListener('change', () => { seedNewSshRole(); sync(true); });
    panel.addEventListener('change', event => {
        if (event.target.matches('input[name="denied_permissions[]"]')) {
            const checkbox = event.target;
            if (checkbox.checked !== choiceBaselines.get(checkbox)) {
                checkbox.dataset.adminStagedEdit = 'true';
            } else {
                delete checkbox.dataset.adminStagedEdit;
            }
            sync(true);
        }
    });
    sync(false);
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
        initUserRoleRestrictions(root);
    }
    document.addEventListener('gateway:admin-ready', event => init(event.detail.root));
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => init(), { once: true });
    } else {
        init();
    }
})();
