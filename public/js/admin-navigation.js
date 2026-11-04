(() => {
    'use strict';

    // This file is loaded before Turbo so the unsaved-history guard owns the
    // first popstate listener. Initial HTML opts out until setup completes.
    function configureTurbo() {
        if (!window.Turbo) return;
        window.Turbo.session.drive = false;
        window.Turbo.config.forms.mode = 'off';
    }

    let navigating = false;
    let allowUnload = false;
    let submittedDirtyForm = null;
    let restoringCancelledHistory = false;
    let currentHistoryIndex = history.state?.turbo?.restorationIndex ?? 0;

    // A bounced input/change event is not evidence of an unsaved edit.
    // Baselines belong to the rendered form instance, including Turbo visits.
    const formBaselines = new WeakMap();
    const presentedFeedback = new WeakSet();

    // Native POSTs deliberately use server redirects, not an AJAX toast queue.
    // Their response can restore the previous scroll position below a message
    // rendered at the top of the page. Bring only new, server-rendered results
    // into view, and never resurrect a consumed flash from browser storage.
    function revealFeedback(root = document) {
        const feedback = root.querySelector('[data-admin-feedback]');
        if (!feedback || presentedFeedback.has(feedback) || feedback.hidden) return;
        if (location.hash && location.hash !== '#' + feedback.id) {
            // Respect an explicit, valid in-document anchor.
            try {
                if (document.getElementById(decodeURIComponent(location.hash.slice(1)))) return;
            } catch { /* An invalid fragment does not suppress operation feedback. */ }
        }
        if (document.hidden) return;
        presentedFeedback.add(feedback);
        requestAnimationFrame(() => {
            if (!feedback.isConnected || feedback.hidden) return;
            feedback.focus({ preventScroll: true });
            feedback.scrollIntoView({ block: 'start', behavior: 'auto' });
        });
    }

    // The URL token has already been claimed by the server. Keep the current
    // history entry (and its Turbo restoration state), but remove the opaque
    // one-time query after document load; a Back visit cannot replay feedback.
    function clearFeedbackUrlToken() {
        const url = new URL(location.href);
        if (!url.searchParams.has('_admin_feedback')) return;
        url.searchParams.delete('_admin_feedback');
        history.replaceState(history.state, '', url.href);
    }

    function failedDraftFields() {
        try {
            const fields = JSON.parse(document.body.dataset.adminDraftFields || '[]');
            return new Set(Array.isArray(fields) ? fields : []);
        } catch { return new Set(); }
    }

    function hasFailedDraft(form) {
        const fields = failedDraftFields();
        return fields.size > 0 && Array.from(form.elements).some(control =>
            control.name && fields.has(control.name)
                && !['hidden', 'button', 'submit', 'reset'].includes((control.type || '').toLowerCase()));
    }

    function editableForm(form) {
        return form instanceof HTMLFormElement && form.method.toLowerCase() !== 'get'
            && form.dataset.adminDirtyGuard !== 'off'
            && Array.from(form.elements).some(control => {
                const type = (control.type || '').toLowerCase();
                return ['INPUT', 'TEXTAREA', 'SELECT'].includes(control.tagName)
                    && !['hidden', 'button', 'submit', 'reset', 'image'].includes(type)
                    && !control.readOnly;
            });
    }

    // Password managers may fill unrelated technical fields after DOMContentLoaded.
    // A field value alone, focus alone, or an arbitrary input/change event alone
    // does not prove an intentional edit. Preserve server-rendered values for
    // technical identities and recognize actual typing/selection/paste.
    const deliberateFields = new WeakSet();
    // A passive later replacement must not override an actual operator value.
    // This also covers a field that the operator edited and then reverted.
    const deliberateValues = new WeakMap();
    const credentialInteractions = new WeakSet();
    const editableInputs = control => control instanceof HTMLInputElement
        || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement;

    function deliberate(event) {
        const control = event.target;
        if (!editableInputs(control) || !control.form) return;
        // Selects have discrete semantic choices, and some browser-driving
        // mechanisms emit a non-trusted change after selecting a real option.
        // Protect that changed choice regardless of event trust; an untouched
        // or reverted selection still compares clean with the baseline.
        // Technical identity and Owner-password inputs continue to require
        // deliberate native interaction rather than a synthetic event.
        if (event.type === 'change' && control instanceof HTMLSelectElement) {
            deliberateFields.add(control);
            deliberateValues.set(control, control.value);
            return;
        }
        if (!event.isTrusted || document.activeElement !== control) return;
        if (event.type === 'paste' || event.type === 'cut' || event.type === 'compositionstart') {
            deliberateFields.add(control);
            return;
        }
        if (event.type === 'beforeinput' || event.type === 'input') {
            const inputType = event.inputType || '';
            // Chrome autofill/password-manager replacement is not typed text.
            // Native typing, paste, deletion, undo/redo and IME are edits.
            if (inputType.startsWith('insertText')
                || inputType.startsWith('insertComposition')
                || inputType.startsWith('insertFromPaste')
                || inputType.startsWith('delete')
                || inputType.startsWith('history')) {
                deliberateFields.add(control);
                if (event.type === 'input') deliberateValues.set(control, control.value);
            }
        } else if (event.type === 'change'
            && (control instanceof HTMLSelectElement
                || control.type === 'checkbox' || control.type === 'radio'
                || control.type === 'file')) {
                deliberateFields.add(control);
                deliberateValues.set(control, control.value);
            }
    }

    ['beforeinput', 'input', 'change', 'paste', 'cut', 'compositionstart'].forEach(type =>
        document.addEventListener(type, deliberate, true));

    // Some shared controls deliberately edit values through JavaScript rather
    // than a native input event. Their real click (not a synthetic input event)
    // is the intent signal; the normal semantic comparator still detects reverts.
    document.addEventListener('pointerdown', event => {
        const control = event.target.closest?.('input[data-admin-requires-intent]');
        if (event.isTrusted && control?.name === 'current_password' && !control.disabled) {
            // Explicit interaction may open the browser's native saved-password
            // chooser; allow that selection, not a silent page-load fill.
            credentialInteractions.add(control);
        }
    }, true);
    document.addEventListener('keydown', event => {
        if (!event.isTrusted || !['Enter', 'ArrowDown', 'ArrowUp', ' '].includes(event.key)) return;
        const control = event.target.closest?.('input[data-admin-requires-intent]');
        if (control?.name === 'current_password' && !control.disabled) {
            credentialInteractions.add(control);
        }
    }, true);

    document.addEventListener('click', event => {
        if (!event.isTrusted) return;
        const clear = event.target.closest('[data-clear-setting]');
        if (clear) {
            const field = document.getElementById(clear.dataset.clearSetting);
            if (field) deliberateFields.add(field);
        }
        const selectPage = event.target.closest('[data-select-page]');
        if (selectPage) {
            selectPage.closest('form')?.querySelectorAll('input[data-selectable][name="selected_ids[]"]')
                .forEach(field => { if (!field.disabled) deliberateFields.add(field); });
        }
    }, true);

    function reconcilePassiveIdentity(form) {
        form.querySelectorAll('[data-admin-manual-entry][data-admin-server-value]').forEach(control => {
            const intended = deliberateValues.has(control)
                ? deliberateValues.get(control) : control.dataset.adminServerValue;
            if (control.value !== intended) control.value = intended;
        });
        form.querySelectorAll('input[name="current_password"][data-admin-requires-intent]')
            .forEach(control => {
                if (!deliberateFields.has(control) && !credentialInteractions.has(control)) {
                    // A password manager may silently write a valid Owner
                    // password on page load. It must not count as reauth.
                    control.value = '';
                }
            });
    }

    function fieldValues(form) {
        const entries = new Map();
        Array.from(form.elements).forEach(control => {
            if (!control.name || !['INPUT', 'SELECT', 'TEXTAREA'].includes(control.tagName)) return;
            const type = (control.type || '').toLowerCase();
            if (['hidden', 'button', 'submit', 'reset', 'image'].includes(type)) return;
            // Owner reauthentication is not a persisted draft. Other new
            // credentials are protected when deliberately entered.
            if (type === 'password' && control.name === 'current_password') return;
            if (control.disabled && control.closest('[data-user-role-choice]')
                && control.dataset.adminStagedEdit !== 'true') return;
            let value;
            if (type === 'checkbox' || type === 'radio') value = control.checked;
            else if (type === 'file') value = Array.from(control.files || [],
                file => [file.name, file.size, file.lastModified]);
            else if (control.tagName === 'SELECT' && control.multiple) {
                value = Array.from(control.selectedOptions, option => option.value);
            } else value = control.value;
            entries.set(control, JSON.stringify([control.name, type, value]));
        });
        return entries;
    }

    function captureBaselines(root = document) {
        root.querySelectorAll('form').forEach(form => {
            if (editableForm(form) && !formBaselines.has(form)) {
                reconcilePassiveIdentity(form);
                formBaselines.set(form, {
                    values: fieldValues(form),
                    failedDraft: hasFailedDraft(form),
                });
                formDirty(form);
            }
        });
    }

    function formDirty(form) {
        if (!editableForm(form)) {
            form?.removeAttribute('data-admin-dirty');
            return false;
        }
        reconcilePassiveIdentity(form);
        if (!formBaselines.has(form)) {
            formBaselines.set(form, {
                values: fieldValues(form),
                failedDraft: hasFailedDraft(form),
            });
        }
        const baseline = formBaselines.get(form);
        const current = fieldValues(form);
        let changed = baseline.failedDraft;
        current.forEach((value, control) => {
            if (deliberateFields.has(control) && value === baseline.values.get(control)) {
                // A fully reverted edit cannot grant future passive autofill
                // authority over a server-authored technical identity field.
                deliberateFields.delete(control);
                deliberateValues.delete(control);
            }
            if ((deliberateFields.has(control) || control.dataset.adminStagedEdit === 'true')
                && baseline.values.get(control) !== value) changed = true;
        });
        if (changed) form.dataset.adminDirty = 'true';
        else form.removeAttribute('data-admin-dirty');
        return changed;
    }

    function dirtyForms(except = null) {
        return Array.from(document.querySelectorAll('form')).some(form =>
            form !== except && formDirty(form));
    }

    function canLeave() {
        return !dirtyForms() || window.confirm(document.body.dataset.unsavedMessage || '');
    }

    function safeDestination(value) {
        if (!document.body.classList.contains('admin-app')) return false;
        const url = new URL(value, location.href);
        if (url.origin !== location.origin || url.username || url.password) return false;
        const root = new URL(document.body.dataset.adminRoot, location.href).pathname.replace(/\/$/, '');
        const mainDestinations = new Set(Array.from(document.querySelectorAll('.admin-nav a[href]'),
            link => new URL(link.href).pathname));
        if (mainDestinations.has(url.pathname)) return true;
        // Target detail/enrollment/configuration are reviewed local GET pages.
        // Never match one-time external authorization, callbacks or transfers.
        if (!mainDestinations.has(root + '/targets')) return false;
        const prefix = root + '/targets/';
        if (!url.pathname.startsWith(prefix)) return false;
        const parts = url.pathname.slice(prefix.length).split('/');
        return (parts.length === 1 && parts[0] !== '')
            || (parts.length === 2 && parts[0] !== '' && parts[1] === 'edit');
    }

    function message(value, busy) {
        const main = document.getElementById('main-content');
        if (main) {
            if (busy) main.setAttribute('aria-busy', 'true');
            else main.removeAttribute('aria-busy');
        }
        const status = document.getElementById('admin-navigation-status');
        if (status) status.textContent = value;
    }

    function enhanceLinks() {
        configureTurbo();
        document.querySelectorAll('.admin-nav a[href], main a[href]').forEach(link => {
            if (link.hasAttribute('download') || link.target
                || link.getAttribute('data-turbo') === 'false'
                || link.getAttribute('href').startsWith('#')) return;
            if (safeDestination(link.href)) link.setAttribute('data-turbo', 'true');
        });
    }

    // Section/skip links stay within this document's history entry. Native
    // fragment entries do not have Turbo indices and can bypass the dirty-form
    // restoration guard. Preserve the current state when updating the fragment.
    document.addEventListener('click', event => {
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey
            || event.shiftKey || event.altKey) return;
        const link = event.target.closest('a[href]');
        if (!link || link.target || link.hasAttribute('download')) return;
        const url = new URL(link.href, location.href);
        if (!url.hash || url.origin !== location.origin || url.pathname !== location.pathname
            || url.search !== location.search) return;
        let destination;
        try { destination = document.getElementById(decodeURIComponent(url.hash.slice(1))); }
        catch { return; }
        if (!destination) return;
        event.preventDefault();
        history.replaceState(history.state, '', url.href);
        destination.scrollIntoView();
        if (!destination.hasAttribute('tabindex')) destination.setAttribute('tabindex', '-1');
        destination.focus({ preventScroll: true });
    });

    document.addEventListener('input', markDirty);
    document.addEventListener('change', markDirty);
    document.addEventListener('focusin', event => {
        const form = event.target.closest?.('form');
        if (form) reconcilePassiveIdentity(form);
    });

    function markDirty(event) {
        const form = event.target.closest('form');
        if (form) formDirty(form);
    }

    document.addEventListener('reset', event => {
        const form = event.target;
        if (form instanceof HTMLFormElement) requestAnimationFrame(() => formDirty(form));
    });

    // Native validation runs before submit. A successfully submitted form
    // does not block its own navigation; unrelated unsaved forms still do.
    document.addEventListener('submit', event => {
        if (!event.defaultPrevented && event.target instanceof HTMLFormElement) {
            const form = event.target;
            reconcilePassiveIdentity(form);
            const passiveOwnerCredential = Array.from(form.querySelectorAll(
                'input[name="current_password"][data-admin-requires-intent]')).find(
                control => !control.disabled && control.value !== '' && !deliberateFields.has(control)
                    && !credentialInteractions.has(control));
            if (passiveOwnerCredential) {
                event.preventDefault();
                passiveOwnerCredential.value = '';
                passiveOwnerCredential.focus();
                passiveOwnerCredential.reportValidity();
                return;
            }
            submittedDirtyForm = formDirty(form) ? form : null;
            if (submittedDirtyForm) submittedDirtyForm.removeAttribute('data-admin-dirty');
        }
    });

    window.addEventListener('beforeunload', event => {
        if (!allowUnload && dirtyForms(submittedDirtyForm)) {
            // A cancelled native departure (including a one-shot download)
            // must restore this form's guard along with other drafts.
            // Recompute the submitted form explicitly: dirtyForms() short
            // circuits at another draft and must not leave its flag cleared.
            if (submittedDirtyForm?.isConnected) formDirty(submittedDirtyForm);
            submittedDirtyForm = null;
            dirtyForms();
            event.preventDefault();
            event.returnValue = '';
        } else {
            submittedDirtyForm = null;
        }
    });

    document.addEventListener('turbo:before-prefetch', event => event.preventDefault());

    document.addEventListener('turbo:before-visit', event => {
        if (!safeDestination(event.detail.url) || !canLeave()) {
            event.preventDefault();
            return;
        }
        allowUnload = true;
    });

    // Turbo's before-visit deliberately excludes Back/Forward. Keep cancelled
    // same-document history traversal at the original entry, without rendering
    // a different URL or allowing Turbo to consume the cancelled popstate.
    window.addEventListener('popstate', event => {
        const next = event.state?.turbo?.restorationIndex;
        if (restoringCancelledHistory) {
            restoringCancelledHistory = false;
            event.stopImmediatePropagation();
            return;
        }
        if (Number.isInteger(next) && next !== currentHistoryIndex && dirtyForms() && !canLeave()) {
            event.stopImmediatePropagation();
            restoringCancelledHistory = true;
            history.go(currentHistoryIndex - next);
        } else {
            allowUnload = true;
        }
    }, true);

    document.addEventListener('turbo:visit', () => {
        navigating = true;
        message(document.body.dataset.loadingMessage || '', true);
    });

    document.addEventListener('turbo:load', () => {
        window.GatewayAdmin?.init(document);
        captureBaselines();
        enhanceLinks();
        currentHistoryIndex = history.state?.turbo?.restorationIndex ?? currentHistoryIndex;
        allowUnload = false;
        submittedDirtyForm = null;
        if (navigating) {
            const heading = document.querySelector('main h1, h1');
            const destination = heading || document.getElementById('main-content');
            if (destination) {
                destination.setAttribute('tabindex', '-1');
                destination.focus({ preventScroll: true });
            }
            message(document.title, false);
        }
        navigating = false;
        revealFeedback();
        clearFeedbackUrlToken();
    });

    document.addEventListener('turbo:fetch-request-error', () => {
        message(document.body.dataset.navigationErrorMessage || '', false);
    });

    // Browser back/forward caches are independent of Turbo snapshots. Recheck
    // the server session/grants before presenting a restored privileged page.
    window.addEventListener('pageshow', event => {
        if (event.persisted && document.body.classList.contains('admin-app')) {
            allowUnload = true;
            location.reload();
        }
    });

    document.addEventListener('gateway:admin-ready', () => {
        captureBaselines();
        enhanceLinks();
        revealFeedback();
        clearFeedbackUrlToken();
    });
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) revealFeedback();
    });
    document.addEventListener('DOMContentLoaded', () => {
        captureBaselines();
        revealFeedback();
        clearFeedbackUrlToken();
    }, { once: true });
    if (document.readyState !== 'loading') {
        captureBaselines();
        enhanceLinks();
        revealFeedback();
        clearFeedbackUrlToken();
    }
})();
