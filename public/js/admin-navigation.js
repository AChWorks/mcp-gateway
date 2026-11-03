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

    function formValues(form) {
        return JSON.stringify(Array.from(form.elements).flatMap(control => {
            if (!control.name || !['INPUT', 'SELECT', 'TEXTAREA'].includes(control.tagName)) return [];
            const type = (control.type || '').toLowerCase();
            // Session/auth tokens, optimistic revision hashes, and generated
            // hidden metadata are not human-editable form content.
            if (['hidden', 'button', 'submit', 'reset', 'image'].includes(type)) return [];
            // The existing Owner's current password confirms a later POST;
            // it is not persistent form content. Browser password managers
            // may fill it after the baseline without an operator edit.
            // Keep new passwords and SSH credentials protected as real drafts.
            if (type === 'password' && control.name === 'current_password') return [];
            // Out-of-Role Deny choices cannot be submitted. Ignore automatic
            // SSH safe-default seeding after a Role is reverted, but preserve
            // deliberate edits staged while the permission was available.
            if (control.disabled && control.closest('[data-user-role-choice]')
                && control.dataset.adminStagedEdit !== 'true') return [];
            let value;
            if (type === 'checkbox' || type === 'radio') value = control.checked;
            else if (type === 'file') value = Array.from(control.files || [],
                file => [file.name, file.size, file.lastModified]);
            else if (control.tagName === 'SELECT' && control.multiple) {
                value = Array.from(control.selectedOptions, option => option.value);
            } else value = control.value;
            return [[control.name, type, value]];
        }));
    }

    function captureBaselines(root = document) {
        root.querySelectorAll('form').forEach(form => {
            if (editableForm(form) && !formBaselines.has(form)) {
                formBaselines.set(form, {
                    values: formValues(form),
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
        if (!formBaselines.has(form)) {
            formBaselines.set(form, {
                values: formValues(form),
                failedDraft: hasFailedDraft(form),
            });
        }
        const baseline = formBaselines.get(form);
        const changed = baseline.failedDraft || formValues(form) !== baseline.values;
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
            submittedDirtyForm = formDirty(event.target) ? event.target : null;
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
