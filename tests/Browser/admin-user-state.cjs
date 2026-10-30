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
    for (const input of await checks(page).all()) await input.uncheck();
    for (const value of values) await page.locator('input[name="denied_permissions[]"][value="' + value + '"]').check();
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
async function state(page, expected) {
    assert.equal(await page.locator('#role').inputValue(), expected.role);
    assert.equal(await page.locator('#target_scope_mode').inputValue(), expected.scope);
    assert.equal(await page.locator('#access_enabled').isChecked(), expected.enabled);
    assert.equal(await page.locator('#ai_access_enabled').isChecked(), expected.ai);
    assert.deepEqual(await checked(page), [...expected.denials].sort());
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
        const name = 'Browser saved user ' + suffix;
        const email = 'browser-saved-user-' + suffix.toLowerCase() + '@example.test';
        await page.locator('#name').fill(name);
        await page.locator('#email').fill(email);
        await page.locator('#password').fill('User-Browser-Password!234');
        await page.locator('#password_confirmation').fill('User-Browser-Password!234');
        await page.locator('#role').selectOption('operator');
        await page.locator('#target_scope_mode').selectOption('selected');
        await page.locator('#access_enabled').check();
        await page.locator('#ai_access_enabled').check();
        const saved = [...sshDenials, 'activity.view', 'targets.view'];
        await setDenials(page, saved);
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Create user');
        await page.getByRole('heading', { name, exact: true }).waitFor();
        const editUrl = page.url();
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });
        await reopen(page, name);
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });

        // A failed password confirmation must display the empty draft, never saved/default Deny checks.
        await setDenials(page, []);
        await page.locator('#access_enabled').uncheck();
        await page.locator('#ai_access_enabled').uncheck();
        await page.locator('#current_password').fill('Wrong-Owner-Password!234');
        await post(page, 'Save user access');
        assert.equal(await page.locator('#current_password-error').count(), 1);
        await state(page, { role: 'operator', scope: 'selected', enabled: false, ai: false, denials: [] });
        assert.equal(await page.locator('[data-user-permission-state="submitted"]').count(), 1);
        await page.goto(editUrl);
        await state(page, { role: 'operator', scope: 'selected', enabled: true, ai: true, denials: saved });
        assert.equal(await page.locator('[data-user-permission-state="saved"]').count(), 1);
        assert.notEqual(await page.locator('#user-permission-restrictions').getAttribute('open'), null);

        // Server validation is reached through valid native inputs with a mismatched password pair.
        await setDenials(page, []);
        await page.locator('#password').fill('Changed-User-Password!234');
        await page.locator('#password_confirmation').fill('Mismatched-User-Password!234');
        await page.locator('#current_password').fill(ownerPassword);
        await post(page, 'Save user access');
        assert.equal(await page.locator('#password-error').count(), 1);
        assert.deepEqual(await checked(page), []);
        assert.equal(await page.locator('[data-user-permission-state="submitted"]').count(), 1);
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
        assert.equal(await page.locator('[data-user-permission-state="saved"]').count(), 1);
        assert.deepEqual(errors, []);
        assert.deepEqual(external, []);
        console.log('PASS: User create/save/list/reopen, role/scope/access/AI flags, exact saved Deny state, empty error drafts, no-mutation recovery and Owner-confirmed empty saved restrictions; ' + suffix);
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
