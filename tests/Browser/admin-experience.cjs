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
                    if (await run.page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) console.log('OVERFLOW', JSON.stringify(await run.page.evaluate(() => [...document.querySelectorAll('.admin-shell,.admin-workspace,main,.panel,.table-wrap')].map(e=>({tag:e.tagName,cls:e.className,right:Math.round(e.getBoundingClientRect().right),width:Math.round(e.getBoundingClientRect().width),scroll:e.scrollWidth,overflow:getComputedStyle(e).overflowX,min:getComputedStyle(e).minWidth,cols:getComputedStyle(e).gridTemplateColumns})))));;
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
        let speculativeRequests = 0;
        page.on('request', request => {
            if (new URL(request.url()).pathname.includes('/external-authorization/')) speculativeRequests++;
        });
        await page.evaluate(() => {
            const link = document.createElement('a');
            link.id = 'fixture-no-prefetch';
            link.href = '/admin/targets/ui-wp-connected/external-authorization/' + '0'.repeat(32);
            link.textContent = 'Synthetic one-use path';
            document.querySelector('main').appendChild(link);
        });
        await page.locator('#fixture-no-prefetch').hover();
        await page.waitForTimeout(250);
        assert.equal(speculativeRequests, 0, 'Hover prefetched a stateful handoff path.');
        await page.locator('#fixture-no-prefetch').evaluate(element => element.remove());
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
        await page.locator('.target-help-details').filter({ has: page.locator('#show_host_fingerprint') }).locator('summary').click();
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

        await page.locator('input[name="values[wp_response_kib]"]').fill('999999999');
        await page.locator('input[name="current_password"]').fill('isolated-browser-password');
        await page.locator('form[action$="/admin/operations"]').evaluate(form => form.noValidate = true);
        await page.getByRole('button', { name: 'Save operational settings', exact: true }).click();
        await page.locator('input[name="values[wp_response_kib]"][aria-invalid="true"]').waitFor();
        assert.equal(await page.locator('input[name="values[wp_response_kib]"]').inputValue(), '999999999');
        assert.equal(await page.locator('input[name="current_password"]').inputValue(), '', 'The password was restored after invalid input.');
        assert.deepEqual(posts, ['document', 'document']);

        // A denied CSRF request cannot expire a legitimate test session.
        const denied = await page.request.post(base + '/__browser__/experience-expire');
        assert.equal(denied.status(), 419);
        await page.request.get(base + '/__browser__/experience/viewer');
        await nav(page, 'Targets', 'Gateway Targets');
        assert.equal(await page.locator('.admin-nav').getByRole('link', { name: 'Operational settings', exact: true }).count(), 0);
        assert.equal(await page.locator('.admin-nav').getByRole('link', { name: 'Users', exact: true }).count(), 0);
        assert.equal(await page.locator('main').getByText('UI SSH build host', { exact: true }).count(), 0);
        assert.equal(await page.locator('main').getByText('UI Editorial WordPress', { exact: true }).count(), 1);
        const forbidden = await page.goto(base + '/admin/operations');
        assert.equal(forbidden.status(), 403);
        await enter(page, 'viewer');
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

async function assertReflow(page, scenario) {
    const dimensions = await page.evaluate(() => ({
        viewport: innerWidth, document: document.documentElement.scrollWidth,
    }));
    assert.ok(dimensions.document <= dimensions.viewport,
        scenario + ' widened the page: ' + JSON.stringify(dimensions));
}

async function adaptation(browser) {
    const run = await create(browser, { width: 320 });
    const page = run.page;
    try {
        await enter(page);
        // This is 320 CSS pixels, independent of device scale or a phone preset.
        assert.equal(await page.evaluate(() => innerWidth), 320);
        for (const path of ['/admin', '/admin/targets',
            '/admin/targets/create?connector_type=ssh_direct', '/admin/operations']) {
            await page.goto(base + path);
            await page.locator('#main-content h1').waitFor();
            await assertReflow(page, '320 CSS px ' + path);
        }

        await page.setViewportSize({ width: 1280, height: 900 });
        const field = page.locator('input[name="values[wp_response_kib]"]');
        const original = await field.evaluate(element => parseFloat(getComputedStyle(element).fontSize));
        const rootSize = await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize));
        // A text-size fixture, not device scaling or a claim of browser zoom.
        await page.addStyleTag({ content: 'html { font-size: ' + rootSize * 2 + 'px !important; }' });
        await page.waitForFunction(expected => parseFloat(getComputedStyle(
            document.querySelector('input[name="values[wp_response_kib]"]')).fontSize) === expected,
        original * 2, { timeout: 2000 });
        const enlarged = await field.evaluate(element => parseFloat(getComputedStyle(element).fontSize));
        assert.equal(enlarged, original * 2, 'Form text did not resize to 200%.');
        await assertReflow(page, '200% text settings');
        assert.equal(await field.isVisible(), true);
        assert.equal(await page.getByRole('button', { name: 'Save operational settings', exact: true }).isVisible(), true);
        assert.equal(await page.locator('label[for="setting_wp_response_kib"]').count(), 1);

        await page.setViewportSize({ width: 320, height: 900 });
        await page.goto(base + '/admin/targets');
        // Change only fixture content/direction in an actual rendered inventory.
        // No translated application or second implementation is introduced.
        const longName = 'درگاه تحریریه — WordPress / محیط آزمایش ' + 'LongConnectorName'.repeat(12);
        await page.locator('.target-display-name').first().evaluate((element, text) => {
            document.documentElement.dir = 'rtl';
            element.textContent = text;
        }, longName);
        assert.equal(await page.locator('.target-display-name').first().innerText(), longName);
        await assertReflow(page, 'RTL mixed-script long Target name');
        const identity = await page.locator('.target-cell-identity').first().evaluate(element => {
            const name = element.querySelector('.target-display-name').getBoundingClientRect();
            const cell = element.getBoundingClientRect();
            return { direction: getComputedStyle(element).direction,
                contained: name.left >= cell.left - 1 && name.right <= cell.right + 1 };
        });
        assert.equal(identity.direction, 'rtl');
        assert.equal(identity.contained, true, 'Long mixed-script name escaped its inventory cell.');

        await page.goto(base + '/admin');
        await page.evaluate(() => { document.documentElement.dir = 'rtl'; });
        const technicalId = 'ui-error-1:connector/v2?scope=read-only';
        await page.locator('[aria-labelledby="needs-review-title"] bdi code').first()
            .evaluate((element, text) => { element.textContent = text; }, technicalId);
        const isolation = await page.locator('[aria-labelledby="needs-review-title"] bdi').first()
            .evaluate(element => ({ direction: getComputedStyle(element).direction,
                bidi: getComputedStyle(element).unicodeBidi, text: element.textContent }));
        assert.equal(isolation.direction, 'ltr');
        assert.equal(isolation.bidi, 'isolate');
        assert.equal(isolation.text, technicalId);
        await assertReflow(page, 'RTL Dashboard with isolated technical identifier');
        assert.deepEqual(run.errors, []);
        assert.deepEqual(run.external, []);
        pass('320 CSS px reflow; measured 200% form text; RTL mixed-script long names and isolated technical IDs');
    } finally {
        await run.context.close();
    }
}

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

async function deadline(promise, label) {
    let timer;
    try {
        return await Promise.race([promise, new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('Timed out waiting for ' + label)), 5000);
        })]);
    } finally { clearTimeout(timer); }
}

async function enhancedTargetsReady(page) {
    await page.waitForFunction(() => document.querySelector('.admin-nav a[href$="/targets"]')?.getAttribute('data-turbo') === 'true');
}

async function resilience(browser) {
    const run = await create(browser);
    const page = run.page;
    let release = () => {};
    try {
        await enter(page);
        await enhancedTargetsReady(page);
        await page.evaluate(() => { window.__resilienceDocument = 'original'; });
        const held = deferred();
        release = held.resolve;
        await page.route(base + '/admin/targets', async route => {
            await held.promise;
            await route.continue();
        });
        const started = page.waitForRequest(base + '/admin/targets');
        await page.locator('.admin-nav').getByRole('link', { name: 'Targets', exact: true }).click();
        await started;
        await page.waitForFunction(() => document.getElementById('main-content').getAttribute('aria-busy') === 'true');
        const status = page.locator('#admin-navigation-status');
        assert.equal(await status.getAttribute('role'), 'status');
        assert.equal(await status.getAttribute('aria-live'), 'polite');
        assert.equal(await status.innerText(), await page.locator('body').getAttribute('data-loading-message'));
        assert.equal(await page.getByRole('heading', { name: 'Gateway overview', exact: true }).isVisible(), true);
        held.resolve();
        await page.getByRole('heading', { name: 'Gateway Targets', exact: true }).waitFor();
        assert.equal(await page.locator('#main-content').getAttribute('aria-busy'), null);
        assert.equal(await status.innerText(), await page.title());
        assert.equal(await page.evaluate(() => window.__resilienceDocument), 'original');
        await page.unroute(base + '/admin/targets');
        pass('held enhanced GET retains current content and exposes live loading/busy state');

        await nav(page, 'Dashboard', 'Gateway overview');
        await enhancedTargetsReady(page);
        const oldResponse = deferred();
        const responseReady = deferred();
        const delivered = deferred();
        release = oldResponse.resolve;
        await page.route(base + '/admin/targets', async route => {
            // Fetch real Laravel HTML, then hold only its delivery to the browser.
            const response = await route.fetch();
            responseReady.resolve({ status: response.status(), navigation: route.request().isNavigationRequest() });
            await oldResponse.promise;
            try { await route.fulfill({ response }); } finally { delivered.resolve(); }
        });
        await page.locator('.admin-nav').getByRole('link', { name: 'Targets', exact: true }).click();
        const delayedResponse = await deadline(responseReady.promise, 'delayed Laravel response');
        assert.equal(delayedResponse.status, 200);
        assert.equal(delayedResponse.navigation, false, 'Stale response case must hold an enhanced GET.');
        await nav(page, 'Activity', 'Operator activity view');
        await page.waitForFunction(() => document.getElementById('admin-navigation-status').textContent === document.title);
        const latestTitle = await page.title();
        oldResponse.resolve();
        await deadline(delivered.promise, 'delivery of delayed response');
        await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
        assert.match(page.url(), /\/admin\/activity$/);
        assert.equal(await page.title(), latestTitle);
        assert.equal(await page.locator('#admin-navigation-status').innerText(), latestTitle);
        assert.equal(await page.evaluate(() => window.__resilienceDocument), 'original');
        assert.equal(await page.locator('.admin-nav [aria-current="page"]').innerText(), 'Activity');
        assert.equal(await page.getByRole('heading', { name: 'Operator activity view', exact: true }).isVisible(), true);
        assert.equal(await page.locator('#main-content').getAttribute('aria-busy'), null);
        await page.unroute(base + '/admin/targets');
        await enhancedTargetsReady(page);

        assert.deepEqual(run.errors, []);
        assert.deepEqual(run.external, []);
        pass('enhanced GET live loading state; delayed older HTML cannot overwrite latest destination');
    } finally {
        release();
        await run.context.close();
    }
}

async function networkFailure(browser) {
    const run = await create(browser);
    const page = run.page;
    try {
        await enter(page);
        await enhancedTargetsReady(page);
        await page.evaluate(() => { window.__beforeFailureDocument = true; });
        const errorStates = [];
        const mutations = [];
        page.on('request', request => { if (request.method() !== 'GET') mutations.push(request.method()); });
        await page.exposeFunction('__recordNavigationError', state => { errorStates.push(state); });
        await page.evaluate(() => {
            // Passive observation after the product handler; never cancel Turbo's
            // event or replace its error behavior with fixture markup.
            document.addEventListener('turbo:fetch-request-error', () => {
                const status = document.getElementById('admin-navigation-status');
                window.__recordNavigationError({ text: status.textContent,
                    expected: document.body.dataset.navigationErrorMessage,
                    role: status.getAttribute('role'), live: status.getAttribute('aria-live'),
                    busy: document.getElementById('main-content').getAttribute('aria-busy') });
            });
        });
        let failures = 0;
        let nativeFallbacks = 0;
        await page.route(base + '/admin/targets', async route => {
            if (route.request().resourceType() === 'document') {
                nativeFallbacks++;
                await route.continue();
            } else {
                failures++;
                await route.abort('failed');
            }
        });
        const fallback = page.waitForRequest(request => request.url() === base + '/admin/targets'
            && request.resourceType() === 'document' && request.isNavigationRequest());
        await page.locator('.admin-nav').getByRole('link', { name: 'Targets', exact: true }).click();
        await fallback;
        await page.getByRole('heading', { name: 'Gateway Targets', exact: true }).waitFor();
        assert.equal(failures, 1, 'Only the enhanced GET must be aborted.');
        assert.equal(nativeFallbacks, 1, 'Failed enhanced GET must fall back to one real native GET.');
        assert.match(page.url(), /\/admin\/targets$/);
        assert.match(await page.title(), /Targets/);
        assert.equal(await page.locator('.admin-nav [aria-current="page"]').innerText(), 'Targets');
        assert.equal(await page.evaluate(() => window.__beforeFailureDocument), undefined);
        assert.equal(await page.locator('#main-content').getAttribute('aria-busy'), null);
        assert.equal(errorStates.length, 1, 'The product did not expose its navigation error state.');
        assert.equal(errorStates[0].text, errorStates[0].expected);
        assert.ok(errorStates[0].text.length > 0);
        assert.equal(errorStates[0].role, 'status');
        assert.equal(errorStates[0].live, 'polite');
        assert.equal(errorStates[0].busy, null);
        assert.deepEqual(mutations, [], 'A read failure must not replay any mutation.');
        // Pinned Turbo rethrows this one injected network failure after announcing
        // and initiating native fallback. Unexpected page errors still fail.
        assert.deepEqual(run.errors, ['Failed to fetch']);
        assert.deepEqual(run.external, []);
        pass('failed enhanced GET announces error, clears busy state and performs one real native GET with fresh shell');
    } finally {
        await run.context.close();
    }
}

(async () => {
    const browser = await chromium.launch({ headless: true });
    try {
        const group = process.env.GATEWAY_UI_TEST_GROUP || 'all';
        assert.ok(['all', 'matrix', 'navigation', 'mobile', 'forms', 'adaptation', 'resilience'].includes(group), 'Unknown UI test group.');
        if (group === 'all' || group === 'matrix') await matrix(browser);
        if (group === 'all' || group === 'navigation') await navigation(browser);
        if (group === 'all' || group === 'mobile') await mobileAndNative(browser);
        if (group === 'all' || group === 'forms') await nativeFormsAndScope(browser);
        if (group === 'all' || group === 'adaptation') await adaptation(browser);
        if (group === 'all' || group === 'resilience') {
            await resilience(browser);
            await networkFailure(browser);
        }
    } finally {
        await browser.close();
    }
})().catch(error => {
    console.error('FAIL: Admin experience regression:', error.stack || error.message);
    process.exitCode = 1;
});
