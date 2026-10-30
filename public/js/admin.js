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

    const selectionForms = new WeakSet();

    function initializeSelections(root) {
        const forms = Array.from(root.querySelectorAll('[data-access-selection]'));
        if (root instanceof HTMLElement && root.matches('[data-access-selection]')) {
            forms.unshift(root);
        }
        forms.forEach((form) => {
            if (selectionForms.has(form)) {
                return;
            }
            selectionForms.add(form);
            const counter = form.querySelector('[data-selection-count]');
            const intent = form.querySelector('[name="intent"]');
            const shownIntent = form.querySelector('[name="shown_intent"]');
            const checkboxes = () => Array.from(form.querySelectorAll('input[name="selected_ids[]"]'));
            const update = () => {
                if (!counter) {
                    return;
                }
                const sameIntent = !intent || !shownIntent || intent.value === shownIntent.value;
                const savedElsewhere = sameIntent ? Number(form.dataset.offPageCount || 0) : 0;
                const count = savedElsewhere + checkboxes().filter((input) => input.checked).length;
                counter.textContent = (form.dataset.selectionCountLabel || ':count selected').replace(':count', String(count));
                counter.classList.toggle('field-error', count > 100);
                form.querySelectorAll('button[name="action"][value="review"]')
                    .forEach((review) => { review.disabled = count === 0 || count > 100; });
            };
            form.addEventListener('change', update);
            const selectPage = form.querySelector('[data-select-page]');
            if (selectPage) {
                selectPage.addEventListener('click', (event) => {
                    event.preventDefault();
                    checkboxes().filter((input) => input.hasAttribute('data-selectable') && !input.disabled)
                        .forEach((input) => { input.checked = true; });
                    // The native POST remains authoritative and saves these choices.
                    form.dispatchEvent(new Event('change', { bubbles: true }));
                });
            }
            update();
        });
    }

    function init(root = document) {
        initializeNavigation(root);
        initializeSelections(root);
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
