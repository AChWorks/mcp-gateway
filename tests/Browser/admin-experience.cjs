'use strict';

// Real Laravel routes + real CSS/JS in the explicitly guarded loopback fixture.
// No production accounts, real downstream request, payload or credential logging.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const base = process.env.GATEWAY_BROWSER_BASE_URL;
if (!/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(base || '')) {
    throw new Error('A local-only GATEWAY_BROWSER_BASE_URL is required.');
}
const pass = (name) => console.log('PASS: ' + name);

async function create(browser, options = {}) {
    const context = await browser.newContext({
        viewport: { width: options.width || 1440, height: 900 },
        javaScriptEnabled: options.javaScriptEnabled !== false,
        colorScheme: options.dark ? 'dark' : 'light',
        reducedMotion: 'reduce',
    });
    const page = await context.newPage();
    const errors = [];
    const external = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {
        if (new URL(request.url()).origin !== base) external.push(new URL(request.url()).origin);
    });
    return { context, page, errors, external };
}

async function enter(page, role = 'owner') {
    const response = await page.goto(base + '/__browser__/experience/' + role);
    assert.equal(response.status(), 200, 'Synthetic fixture entry failed: '+response.status()+' '+new URL(page.url()).pathname+' '+(await page.locator('body').innerText()).slice(0,160));
    await page.getByRole('heading', { name: 'Gateway overview', exact: true }).waitFor({ timeout: 5000 });
    if (await page.evaluate(() => typeof window.GatewayAdmin !== 'undefined')) {
        await page.waitForFunction(() => typeof window.Turbo !== 'undefined');
    }
}

async function nav(page, name, heading) {
    if (await page.locator('[data-admin-nav-toggle]').isVisible()
        && await page.locator('[data-admin-nav-toggle]').getAttribute('aria-expanded') === 'false') {
        await page.locator('[data-admin-nav-toggle]').click();
    }
    await page.locator('.admin-nav').getByRole('link', { name, exact: true }).click();
    await page.getByRole('heading', { name: heading, exact: true }).waitFor();
}

async function matrix(browser) {
    const run = await create(browser);
    try {
        await enter(run.page);
        const assets = await run.page.locator('script[src],link[rel="stylesheet"]').evaluateAll(elements =>
            elements.map(element => element.src || element.href));
        for (const url of assets) {
            const response = await run.page.request.get(url);
            assert.equal(response.status(), 200, 'A real local asset failed to load.');
            assert.match(response.headers()['content-type'], /javascript|css/);
        }
        assert.equal(await run.page.locator('meta[name="turbo-cache-control"]').getAttribute('content'), 'no-cache');
        assert.equal(await run.page.locator('meta[name="turbo-prefetch"]').getAttribute('content'), 'false');
        assert.equal(await run.page.evaluate(() => Turbo.config.forms.mode), 'off');
        assert.equal(await run.page.evaluate(() => Turbo.session.drive), false);
        assert.equal(await run.page.locator('#needs-review-title').count(), 1);
        assert.equal(await run.page.locator('[aria-labelledby="needs-review-title"] tbody tr').count(), 5);
        assert.deepEqual(await run.page.locator('.stat-label').allTextContents(),
            ['Visible Targets', 'Recorded connected', 'Needs review', 'Paused']);
        const rowCount = await run.page.locator('[aria-labelledby="needs-review-title"] tbody').innerText();
        assert.ok(!rowCount.includes('UI pending authorization'));
        assert.ok(!rowCount.includes('UI SSH build host'));

        let renders = 0;
        for (const width of [360, 768, 1440]) {
            for (const colorScheme of ['light', 'dark']) {
                await run.page.setViewportSize({ width, height: 900 });
                await run.page.emulateMedia({ colorScheme, reducedMotion: 'reduce' });
                for (const path of ['/admin', '/admin/targets', '/admin/targets/create?connector_type=ssh_direct',
                    '/admin/oauth-clients', '/admin/operations']) {
                    await run.page.goto(base + path);
                    await run.page.locator('#main-content h1').waitFor();
                    if (await run.page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) console.log('OVERFLOW', JSON.stringify(await run.page.evaluate(() => [...document.querySelectorAll('body *')].map(e=>({tag:e.tagName,cls:e.className,right:Math.round(e.getBoundingClientRect().right),width:Math.round(e.getBoundingClientRect().width)})).filter(e=>e.right>innerWidth+1).slice(0,12))));
                    assert.equal(await run.page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
                        false, 'Page overflow at ' + width + ' ' + path);
                    assert.equal(await run.page.locator('.admin-nav [aria-current="page"]').count(), 1);
                    renders++;
                }
            }
        }
        assert.deepEqual(run.errors, []);
        assert.deepEqual(run.external, []);
        pass(renders + ' real styled Admin viewport/theme renders; local assets; scoped summary and five-row review bound');
    } finally {
        await run.context.close();
    }
}

async function navigation(browser) {
    const run = await create(browser);
    const page = run.page;
    try {
        await enter(page);
        await page.evaluate(() => window.__adminExperienceSentinel = 'same-document');
        await nav(page, 'Targets', 'Gateway Targets');
        assert.equal(await page.evaluate(() => window.__adminExperienceSentinel), 'same-document');
        assert.match(await page.title(), /Targets/);
        assert.equal(await page.locator('.admin-nav [aria-current="page"]').innerText(), 'Targets');
        assert.equal(await page.evaluate(() => document.activeElement.tagName), 'H1');
        await nav(page, 'Operational settings', 'Operational settings');
        const input = page.locator('input[name="values[wp_response_kib]"]');
        await input.fill('80');
        let dialogs = 0;
        const dismiss = async dialog => { dialogs++; await dialog.dismiss(); };
        page.on('dialog', dismiss);
        await page.locator('.admin-nav').getByRole('link', { name: 'Dashboard', exact: true }).click();
        assert.equal(dialogs, 1);
        assert.match(page.url(), /\/admin\/operations$/);
        assert.equal(await input.inputValue(), '80');

        // Back/Forward are popstate restoration, not before-visit events.
        await page.evaluate(() => history.back());
        await page.waitForTimeout(100);
        assert.equal(dialogs, 2);
        assert.match(page.url(), /\/admin\/operations$/);
        assert.equal(await input.inputValue(), '80');
        page.off('dialog', dismiss);
        const accept = async dialog => { dialogs++; await dialog.accept(); };
        page.on('dialog', accept);
        await page.evaluate(() => history.back());
        await page.getByRole('heading', { name: 'Gateway Targets', exact: true }).waitFor();
        page.off('dialog', accept);
        await page.goForward();
        await page.getByRole('heading', { name: 'Operational settings', exact: true }).waitFor();
        assert.equal(await input.inputValue(), '', 'A discarded edit was restored from a snapshot.');

        // Repeat shell readiness must not accumulate per-control handlers.
        await page.evaluate(() => {
            for (let i = 0; i < 5; i++) GatewayAdmin.init(document);
            const field = document.querySelector('input[name="values[wp_response_kib]"]');
            window.__resetInputs = 0;
            field.addEventListener('input', () => window.__resetInputs++);
            field.value = '90';
        });
        await page.locator('[data-clear-setting]').first().click();
        assert.equal(await input.inputValue(), '');
        assert.equal(await page.evaluate(() => window.__resetInputs), 1);
        page.on('dialog', async dialog => dialog.accept());
        await nav(page, 'Dashboard', 'Gateway overview');
        await page.getByRole('link', { name: 'Add Target', exact: true }).click();
        await page.getByRole('heading', { name: 'Add Target', exact: true }).waitFor();
        await page.locator('#connector_type').selectOption('ssh_direct');
        await page.locator('#ssh_auth_method').selectOption('private_key');
        assert.equal(await page.locator('#ssh_password').isDisabled(), true);
        assert.equal(await page.locator('#ssh_private_key').isDisabled(), false);
        await page.locator('#ssh_auth_method').selectOption('password');
        assert.equal(await page.locator('#ssh_password').isDisabled(), false);
        assert.equal(await page.locator('#ssh_private_key').isDisabled(), true);
        await page.locator('#ssh_host_key').fill('invalid fixture key');
        await page.locator('#show_host_fingerprint').click();
        assert.match(await page.locator('#host_fingerprint').innerText(), /Paste one supported public host key/);
        await page.locator('#connector_type').selectOption('wp_ai_bridge');
        assert.equal(await page.locator('#ssh_password').isDisabled(), true);

        await page.goto(base + '/admin/targets/ui-ssh-connected/edit');
        await page.locator('#ssh_edit_auth_method').selectOption('private_key');
        assert.equal(await page.locator('#ssh_edit_password').isDisabled(), true);
        assert.equal(await page.locator('#ssh_edit_private_key').isDisabled(), false);
        assert.deepEqual(run.errors, []);
        pass('GET-only enhanced navigation preserves URL/title/current link/focus; unsaved link and Back cancellation; repeat-safe form widgets');
    } finally {
        await run.context.close();
    }
}

async function mobileAndNative(browser) {
    for (const javaScriptEnabled of [true, false]) {
        const run = await create(browser, { width: 360, javaScriptEnabled, dark: true });
        try {
            await enter(run.page);
            if (javaScriptEnabled) {
                await run.page.keyboard.press('Tab');
                assert.equal(await run.page.evaluate(() => document.activeElement.className), 'skip-link');
                await run.page.keyboard.press('Enter');
                assert.equal(await run.page.evaluate(() => document.activeElement.id), 'main-content');
                const toggle = run.page.locator('[data-admin-nav-toggle]');
                await toggle.click();
                assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
                await run.page.keyboard.press('Escape');
                assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
                assert.equal(await toggle.evaluate(element => element === document.activeElement), true);
            } else {
                assert.equal(await run.page.locator('#admin-navigation').isVisible(), true);
            }
            await nav(run.page, 'Targets', 'Gateway Targets');
            assert.equal(await run.page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
            pass('360px dark keyboard/disclosure and native navigation with JavaScript ' + (javaScriptEnabled ? 'on' : 'off'));
        } finally {
            await run.context.close();
        }
    }
}

async function nativeFormsAndScope(browser) {
    const run = await create(browser);
    const page = run.page;
    try {
        await enter(page);
        await nav(page, 'Operational settings', 'Operational settings');
        const posts = [];
        page.on('request', request => {
            if (new URL(request.url()).pathname === '/admin/operations' && request.method() === 'PUT') {
                posts.push(request.resourceType());
            }
            if (new URL(request.url()).pathname === '/admin/operations' && request.method() === 'POST') {
                posts.push(request.resourceType());
            }
        });
        await page.locator('input[name="values[wp_response_kib]"]').fill('80');
        await page.locator('input[name="current_password"]').fill('isolated-browser-password');
        await page.getByRole('button', { name: 'Save operational settings', exact: true }).click();
        await page.waitForLoadState('domcontentloaded');
        await page.getByRole('heading', { name: 'Operational settings', exact: true }).waitFor();
        assert.deepEqual(posts, ['document'], 'Settings submission was intercepted or replayed.');
        assert.equal(await page.locator('input[name="values[wp_response_kib]"]').inputValue(), '80');

        // A denied CSRF request cannot expire a legitimate test session.
        const denied = await page.request.post(base + '/__browser__/experience-expire');
        assert.equal(denied.status(), 419);
        await page.request.get(base + '/__browser__/experience/viewer');
        await nav(page, 'Targets', 'Gateway Targets');
        assert.equal(await page.locator('.admin-nav').getByRole('link', { name: 'Operational settings', exact: true }).count(), 0);
        assert.equal(await page.locator('.admin-nav').getByRole('link', { name: 'Users', exact: true }).count(), 0);
        assert.equal(await page.locator('main').getByText('UI SSH build host', { exact: true }).count(), 0);
        assert.equal(await page.locator('main').getByText('UI Editorial WordPress', { exact: true }).count(), 1);
        const token = await page.locator('form[action$="/admin/logout"] input[name="_token"]').inputValue();
        const expired = await page.request.post(base + '/__browser__/experience-expire', { form: { _token: token } });
        assert.equal(expired.status(), 204);
        await nav(page, 'Dashboard', 'Sign in');
        assert.match(page.url(), /\/admin\/login$/);
        assert.equal(await page.locator('.admin-sidebar').count(), 0);
        assert.deepEqual(run.errors, []);
        pass('native one-shot settings save; CSRF rejection; fresh scoped navigation; expired session returns to native login');
    } finally {
        await run.context.close();
    }
}

(async () => {
    const browser = await chromium.launch({ headless: true });
    try {
        await matrix(browser);
        await navigation(browser);
        await mobileAndNative(browser);
        await nativeFormsAndScope(browser);
    } finally {
        await browser.close();
    }
})().catch(error => {
    console.error('FAIL: Admin experience regression:', error.stack || error.message);
    process.exitCode = 1;
});
