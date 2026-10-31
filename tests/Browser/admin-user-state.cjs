'use strict';

// Native User account round trips use the retained, doubly guarded loopback fixture.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const base = process.env.GATEWAY_BROWSER_BASE_URL;
if (!/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(base || '')) throw new Error('A local browser fixture is required.');
const ownerPassword = 'Group-Browser-Password!234';
const sshDenials = ['ssh.command.run', 'ssh.file.read', 'ssh.file.write'];
const checks = page => page.locator('input[type="checkbox"][name="denied_permissions[]"]');
const checked = page => checks(page).evaluateAll(nodes => nodes.filter(node => node.checked).map(node => node.value).sort());

async function expand(page) {
    const disclosure = page.locator('details.permission-category-collapsible').first();
    if (await disclosure.getAttribute('open') === null) await disclosure.locator(':scope > summary').click();
}
async function setDenials(page, values) {
    await expand(page);
    for (const input of await checks(page).all()) {
        if (await input.isEnabled()) await input.uncheck();
    }
    for (const value of values) {
        const input = page.locator('input[name="denied_permissions[]"][value="' + value + '"]');
        assert.ok(await input.isEnabled(), 'Cannot Deny a role-ineligible capability: ' + value);
        await input.check();
    }
}
async function post(page, name) {
    const pending = page.waitForResponse(response => response.request().method() === 'POST'
        && new URL(response.url()).origin === base
        && new URL(response.url()).pathname.startsWith('/admin/users'));
    await page.getByRole('button', { name, exact: true }).click();
    const response = await pending;
    assert.equal(response.status(), 302, 'User submission must retain native POST/redirect/GET.');
    assert.ok(response.request().isNavigationRequest());
    assert.ok(new URLSearchParams(response.request().postData()).get('_token'));
    await page.waitForLoadState('networkidle');
}
async function reopen(page, name) {
    await page.getByRole('link', { name: 'Back to users', exact: true }).click();
    await page.getByRole('link', { name: 'Manage ' + name, exact: true }).click();
    await page.getByRole('heading', { name, exact: true }).waitFor();
}
async function assertGlobalDenyChoice(page, key, denied) {
    const checkbox = page.locator('input[name="denied_permissions[]"][value="' + key + '"]');
    const choice = checkbox.locator('..').locator('.permission-choice');
    assert.equal(await checkbox.isChecked(), denied);
    assert.equal(await choice.locator('[data-global-deny-choice="denied"]').isVisible(), denied);
    assert.equal(await choice.locator('[data-global-deny-choice="not-denied"]').isVisible(), !denied);
}
async function state(page, expected) {
    assert.equal(await page.locator('#role').inputValue(), expected.role);
    assert.equal(await page.locator('#target_scope_mode').inputValue(), expected.scope);
    assert.equal(await page.locator('#access_enabled').isChecked(), expected.enabled);
    assert.equal(await page.locator('#ai_access_enabled').isChecked(), expected.ai);
    assert.deepEqual(await checked(page), [...expected.denials].sort());
}
async function assertRestrictionSummary(page, status, count) {
    const counter = page.locator('#user-permission-restrictions > summary [data-user-checked-count]');
    assert.equal(await counter.innerText(), status + ': ' + count + ' checked',
        'Restriction counter must truthfully reflect persisted/default/unsaved draft state');
}

async function run(browser, javaScriptEnabled) {
    const suffix = javaScriptEnabled ? 'JS' : 'native';
    const context = await browser.newContext({ javaScriptEnabled,
        viewport: { width: javaScriptEnabled ? 1440 : 390, height: 1000 }, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const errors = [], external = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (new URL(request.url()).origin !== base) external.push(request.url()); });
    // Discarding an unsaved error draft is deliberate in the fresh-GET no-mutation check.
    page.on('dialog', dialog => dialog.accept());
    try {
        assert.equal((await page.goto(base + '/__browser__/group-workflows/owner')).status(), 200);
        await page.goto(base + '/admin/users/create');
        await assertRestrictionSummary(page, 'Defaults', 3);
        const name = 'Browser saved user ' + suffix;
        const email = 'browser-saved-user-' + suffix.toLowerCase() + '@example.test';
        const saved = [...sshDenials, 'activity.view', 'targets.view'];
        await page.locator('#name').fill(name);
        await page.locator('#email').fill(email);
        await page.locator('#password').fill('User-Browser-Password!234');
        await page.locator('#password_confirmation').fill('User-Browser-Password!234');
        await page.locator('#role').selectOption('operator');
        await page.locator('#target_scope_mode').selectOption('selected');
        await page.locator('#access_enabled').check();
        await page.locator('#ai_access_enabled').check();

        // Rejected Create with nonzero Deny draft: JavaScript must never
        // relabel flashed Unsaved input as Defaults.
        await setDenials(page, saved);
        await page.locator('#current_password').fill('Wrong-Owner-Password!234');
        await post(page, 'Create user');
        assert.equal(await page.locator('[data-user-save-failed]').count(), 1);
        assert.equal(await page.locator('#current_password-error').count(), 1);
        await assertRestrictionSummary(page, 'Unsaved', saved.length);

        // Ordinary validation rejection with explicitly empty Deny draft.
        // Password inputs are intentionally NOT flashed after a failed POST.
        await setDenials(page, []);
        await page.locator('#password').fill('User-Browser-Password!234');
        await page.locator('#password_confirmation').fill('Mismatched-User-Password!234');
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Create user');
        assert.equal(await page.locator('[data-user-save-failed]').count(), 1);
        assert.equal(await page.locator('#password-error').count(), 1);
        await assertRestrictionSummary(page, 'Unsaved', 0);
        await page.goto(base + '/admin/users');
        assert.equal(await page.getByRole('link', { name: 'Manage ' + name, exact: true }).count(), 0,
            'Rejected Create must not persist an account');
        await page.goto(base + '/admin/users/create');
        await assertRestrictionSummary(page, 'Defaults', 3);

        // A subsequent successful Create must use only the fresh form.
        await page.locator('#name').fill(name);
        await page.locator('#email').fill(email);
        await page.locator('#password').fill('User-Browser-Password!234');
        await page.locator('#password_confirmation').fill('User-Browser-Password!234');
        await page.locator('#role').selectOption('operator');
        await page.locator('#target_scope_mode').selectOption('selected');
        await page.locator('#access_enabled').check();
        await page.locator('#ai_access_enabled').check();
        await setDenials(page, saved);
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Create user');
        await page.getByRole('heading', { name, exact: true }).waitFor();
        const editUrl = page.url();
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });
        await assertRestrictionSummary(page, 'Saved', saved.length);
        await reopen(page, name);
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });
        await assertRestrictionSummary(page, 'Saved', saved.length);

        // GET Role preview is not persisted even with JavaScript enabled.
        await page.goto(editUrl + '?preview_role=administrator');
        assert.equal(await page.locator('#role').inputValue(), 'administrator');
        await assertRestrictionSummary(page, 'Unsaved', saved.length);
        await page.goto(editUrl);
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });
        await assertRestrictionSummary(page, 'Saved', saved.length);
        // An unavailable role capability is not offered as a checkbox and
        // cannot enter a normal form submission. The original server guard
        // still rejects crafted ineligible requests in PHP feature tests.
        const userManage = page.locator('input[name="denied_permissions[]"][value="users.manage"]');
        const targetCreate = page.locator('input[name="denied_permissions[]"][value="targets.create"]');
        const sshCommand = page.locator('input[name="denied_permissions[]"][value="ssh.command.run"]');
        assert.ok(await userManage.isDisabled(), 'Operator cannot edit users.manage Deny');
        assert.equal(await userManage.locator('..').getAttribute('hidden'), '');
        assert.equal(await page.locator('[data-user-role-unavailable-item] code')
            .filter({ hasText: /^users\.manage$/ }).count(), 1);

        if (javaScriptEnabled) {
            await page.locator('#role').selectOption('administrator');
            assert.ok(await targetCreate.isEnabled(), 'Administrator can Deny targets.create');
            assert.ok(await userManage.isDisabled(), 'Administrator still cannot manage users');
            assert.equal(await page.locator('[data-user-permission-state="editing"]').count(), 1);
            await targetCreate.check();
            await page.locator('#role').selectOption('operator');
            assert.ok(await targetCreate.isDisabled());
            assert.ok(await targetCreate.isChecked(), 'Temporary draft returns when original Role is selected');
            const submitted = await page.locator('form[data-user-role-form]').evaluate(form =>
                new FormData(form).getAll('denied_permissions[]'));
            assert.ok(!submitted.includes('targets.create'), 'Role-ineligible Deny is never submitted');
            await page.locator('#role').selectOption('administrator');
            assert.ok(await targetCreate.isChecked(), 'Allowed draft restored when switching Role back');
            await targetCreate.uncheck();
            await page.locator('#role').selectOption('viewer');
            assert.ok(await sshCommand.isDisabled(), 'Viewer cannot edit SSH Deny');
            await page.locator('#role').selectOption('owner');
            assert.ok(await targetCreate.isDisabled(), 'Owner cannot set global Deny');
            assert.equal(await page.locator('[data-user-role-owner-note]').isVisible(), true);
            assert.equal(await page.locator('[data-user-role-unavailable]').isVisible(), false);
            assert.deepEqual(await page.locator('form[data-user-role-form]').evaluate(form =>
                new FormData(form).getAll('denied_permissions[]')), [],
                'Owner does not submit inapplicable Deny choices');
            await page.locator('#role').selectOption('operator');
            assert.ok(await sshCommand.isEnabled(), 'Operator can edit SSH Deny');
            assert.ok(await userManage.isDisabled());
            assert.deepEqual(await checked(page), [...saved].sort(), 'Role round trip retains unsaved checkbox state');
        }

        // The changed two-section permission presentation and its long
        // identifiers must reflow without horizontal document overflow.
        const roleViewport = page.viewportSize();
        for (const width of [360, 390, 768, 1366]) {
            for (const theme of ['light', 'dark']) {
                await page.setViewportSize({ width, height: 950 });
                await page.emulateMedia({ colorScheme: theme });
                const layout = await page.evaluate(() => {
                    const panel = document.querySelector('[data-user-role-restrictions]');
                    const region = panel.getBoundingClientRect();
                    return {
                        document: document.documentElement.scrollWidth,
                        viewport: document.documentElement.clientWidth,
                        panel: { x: region.x, right: region.right, width: region.width },
                        rowCount: [...panel.querySelectorAll('[data-user-role-choice]')]
                            .filter(el => !el.hidden && getComputedStyle(el).display !== 'none').length,
                    };
                });
                assert.ok(layout.document <= layout.viewport,
                    'Permission UI creates no overflow at ' + width + ' ' + theme);
                assert.ok(layout.panel.width > 170 && layout.panel.x >= -1
                    && layout.panel.right <= width + 2,
                    'Permission UI fits viewport at ' + width + ' ' + theme);
                assert.ok(layout.rowCount > 0, 'Role-capable controls remain visible');
            }
        }
        await page.setViewportSize(roleViewport);
        await page.emulateMedia({ colorScheme: 'light' });

        // Unchecking a saved SSH Deny without the explicit confirmation also
        // returns a draft; a later list -> Account visit must show only saved
        // restrictions, never an apparent temporary grant.
        await page.locator('input[name="denied_permissions[]"][value="ssh.file.read"]').uncheck();
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Save user access');
        assert.equal(await page.locator('[data-user-save-failed]').count(), 1);
        assert.deepEqual(await checked(page), saved.filter(value => value !== 'ssh.file.read').sort());
        await assertRestrictionSummary(page, 'Unsaved', saved.length - 1);
        const originalViewport = page.viewportSize();
        for (const width of [390, 768, 1366]) {
            for (const theme of ['light', 'dark']) {
                await page.setViewportSize({ width, height: 950 });
                await page.emulateMedia({ colorScheme: theme });
                const geometry = await page.evaluate(() => ({
                    viewport: document.documentElement.clientWidth,
                    document: document.documentElement.scrollWidth,
                    alert: document.querySelector('[data-user-save-failed]').getBoundingClientRect().toJSON(),
                }));
                assert.ok(geometry.document <= geometry.viewport, 'No overflow at ' + width + ' ' + theme);
                assert.ok(geometry.alert.width > 180 && geometry.alert.x >= -1,
                    'Account save banner stays in flow at ' + width + ' ' + theme);
            }
        }
        await page.setViewportSize(originalViewport);
        await page.emulateMedia({ colorScheme: 'light' });
        await reopen(page, name);
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });
        await page.locator('input[name="denied_permissions[]"][value="activity.view"]').uncheck();
        await assertGlobalDenyChoice(page, 'activity.view', false);
        await page.locator('input[name="denied_permissions[]"][value="activity.view"]').check();
        await assertGlobalDenyChoice(page, 'activity.view', true);

        // A failed password confirmation must display the empty draft, never saved/default Deny checks.
        await setDenials(page, []);
        await assertGlobalDenyChoice(page, 'activity.view', false);
        await page.locator('#access_enabled').uncheck();
        await page.locator('#ai_access_enabled').uncheck();
        await page.locator('#current_password').fill('Wrong-Owner-Password!234');
        await post(page, 'Save user access');
        assert.equal(await page.locator('#current_password-error').count(), 1);
        await state(page, { role: 'operator', scope: 'selected', enabled: false, ai: false, denials: [] });
        assert.equal(await page.locator('[data-user-permission-state="submitted"]').count(), 1);
        await assertRestrictionSummary(page, 'Unsaved', 0);
        await assertGlobalDenyChoice(page, 'activity.view', false);
        await page.goto(editUrl);
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });
        assert.equal(await page.locator('[data-user-permission-state="saved"]').count(), 1);
        await assertRestrictionSummary(page, 'Saved', saved.length);
        await assertGlobalDenyChoice(page, 'activity.view', true);
        assert.notEqual(await page.locator('#user-permission-restrictions').getAttribute('open'), null);

        // Server validation is reached through valid native inputs with a mismatched password pair.
        await setDenials(page, []);
        await page.locator('#password').fill('Changed-User-Password!234');
        await page.locator('#password_confirmation').fill('Mismatched-User-Password!234');
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Save user access');
        assert.equal(await page.locator('#password-error').count(), 1);
        assert.deepEqual(await checked(page), []);
        await assertGlobalDenyChoice(page, 'activity.view', false);
        assert.equal(await page.locator('[data-user-permission-state="submitted"]').count(), 1);
        await assertRestrictionSummary(page, 'Unsaved', 0);
        await assertGlobalDenyChoice(page, 'activity.view', false);
        await page.goto(editUrl);
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });

        // Positive flag/role/scope changes survive a real save and list → Account navigation.
        await page.locator('#role').selectOption('administrator');
        await page.locator('#target_scope_mode').selectOption('all');
        await page.locator('#access_enabled').uncheck();
        await page.locator('#ai_access_enabled').uncheck();
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Save user access');
        await reopen(page, name);
        await state(page, { role: 'administrator', scope: 'all', enabled: false, ai: false, denials: saved });

        // An intentionally empty SAVED set requires the existing explicit Owner SSH review.
        await page.locator('#role').selectOption('operator');
        await page.locator('#target_scope_mode').selectOption('selected');
        await setDenials(page, []);
        await page.locator('#confirm_ssh_permission_changes').check();
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Save user access');
        await reopen(page, name);
        await state(page, { role: 'operator', scope: 'selected', enabled: false, ai: false, denials: [] });
        await assertRestrictionSummary(page, 'Saved', 0);
        assert.equal(await page.locator('[data-user-permission-state="saved"]').count(), 1);
        await assertGlobalDenyChoice(page, 'activity.view', false);
        if (!javaScriptEnabled) {
            // A GET-only Role preview is the native fallback for a Role
            // transition: it changes just the displayed form, never storage.
            await page.goto(editUrl);
            await page.locator('noscript a[href*="preview_role=administrator"]').click();
            await page.waitForLoadState('networkidle');
            assert.equal(await page.locator('#role').inputValue(), 'administrator');
            assert.ok(await page.locator('input[value="targets.create"][name="denied_permissions[]"]').isEnabled());
            const previewViewport = page.viewportSize();
            await page.setViewportSize({ width: 360, height: 850 });
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth
                <= document.documentElement.clientWidth), 'Native Role preview fits 360px');
            await page.setViewportSize(previewViewport);
            assert.equal(await page.locator('[data-user-permission-state="editing"]').count(), 1);
            await assertRestrictionSummary(page, 'Unsaved', 0);
            await page.locator('#confirm_ssh_permission_changes').check();
            await page.locator('#current_password').fill(ownerPassword);
            await post(page, 'Save user access');
            await reopen(page, name);
            await state(page, { role: 'administrator', scope: 'selected', enabled: false, ai: false, denials: [] });
        }
        assert.deepEqual(errors, []);
        assert.deepEqual(external, []);
        console.log('PASS: User create/save/list/reopen, role/scope/access/AI flags, exact saved Deny state, role-aware choices, visible Saved/Unsaved/Defaults on rejected Create/Edit, native Role preview, rejected SSH, no-mutation recovery and Owner-confirmed empty saved restrictions; ' + suffix);
    } finally { await context.close(); }
}
(async () => {
    const browser = await chromium.launch({ headless: true });
    try { await run(browser, true); await run(browser, false); }
    finally { await browser.close(); }
})().catch(error => {
    console.error('FAIL: User saved-state browser regression:', error.stack || error.message);
    process.exitCode = 1;
});
