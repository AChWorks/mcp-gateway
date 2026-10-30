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
    let restoringCancelledHistory = false;
    let currentHistoryIndex = history.state?.turbo?.restorationIndex ?? 0;

    function dirtyForms() {
        return document.querySelector('form[data-admin-dirty="true"]') !== null;
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
        if (form && form.method.toLowerCase() !== 'get') form.dataset.adminDirty = 'true';
    }

    // Native validation runs before submit. Never intercept or replay the form.
    document.addEventListener('submit', event => {
        if (!event.defaultPrevented) {
            event.target.removeAttribute('data-admin-dirty');
            allowUnload = true;
        }
    });

    window.addEventListener('beforeunload', event => {
        if (!allowUnload && dirtyForms()) {
            event.preventDefault();
            event.returnValue = '';
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
        enhanceLinks();
        currentHistoryIndex = history.state?.turbo?.restorationIndex ?? currentHistoryIndex;
        allowUnload = false;
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

    document.addEventListener('gateway:admin-ready', enhanceLinks);
    if (document.readyState !== 'loading') enhanceLinks();
})();
