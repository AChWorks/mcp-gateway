(() => {
    'use strict';

    let activeNavigation = null;

    function initializeNavigation(root) {
        const toggle = root.querySelector('[data-admin-nav-toggle]');
        const navigation = toggle && document.getElementById(toggle.getAttribute('aria-controls'));

        if (!toggle || !navigation || typeof window.matchMedia !== 'function') {
            if (activeNavigation && !activeNavigation.toggle.isConnected) {
                activeNavigation.destroy();
                activeNavigation = null;
            }
            return;
        }
        if (activeNavigation && activeNavigation.toggle === toggle) {
            return;
        }

        if (activeNavigation) {
            activeNavigation.destroy();
        }

        const narrow = window.matchMedia('(max-width: 64rem)');

        function setExpanded(expanded, restoreFocus = false) {
            const visible = !narrow.matches || expanded;
            navigation.hidden = !visible;
            toggle.setAttribute('aria-expanded', String(visible));
            if (restoreFocus && narrow.matches) {
                toggle.focus();
            }
        }

        function syncViewport() {
            const focusWillBeHidden = narrow.matches && navigation.contains(document.activeElement);
            setExpanded(!narrow.matches, focusWillBeHidden);
        }

        function onToggle() {
            setExpanded(toggle.getAttribute('aria-expanded') !== 'true');
        }

        function onEscape(event) {
            if (event.key === 'Escape' && narrow.matches && !navigation.hidden) {
                setExpanded(false, true);
                event.preventDefault();
            }
        }

        toggle.hidden = false;
        toggle.addEventListener('click', onToggle);
        document.addEventListener('keydown', onEscape);
        narrow.addEventListener('change', syncViewport);
        syncViewport();

        activeNavigation = {
            toggle,
            destroy() {
                toggle.removeEventListener('click', onToggle);
                document.removeEventListener('keydown', onEscape);
                narrow.removeEventListener('change', syncViewport);
                navigation.hidden = false;
                toggle.hidden = true;
            },
        };
    }

    function init(root = document) {
        initializeNavigation(root);
        document.dispatchEvent(new CustomEvent('gateway:admin-ready', { detail: { root } }));
    }

    // Native links/forms remain authoritative. This hook also lets an explicit
    // future navigation adapter initialize a newly server-rendered shell.
    window.GatewayAdmin = Object.assign(window.GatewayAdmin || {}, { init });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => init(), { once: true });
    } else {
        init();
    }
})();
