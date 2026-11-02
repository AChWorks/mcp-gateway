'use strict';

// Real Chromium against guarded disposable Laravel+SQLite browser fixture.
// No live SSH, host changes, enrollment secrets or privileged commands.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const base = process.env.GATEWAY_BROWSER_BASE_URL;
if (!/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(base || '')) {
    throw new Error('Disposable loopback browser fixture required.');
}

(async () => {
    const browser = await chromium.launch({ headless: true });
    try {
        for (const width of [375, 768, 1440]) {
            for (const dark of [false, true]) {
                const context = await browser.newContext({
                    viewport: { width, height: 900 },
                    colorScheme: dark ? 'dark' : 'light',
                    reducedMotion: 'reduce',
                });
                const page = await context.newPage();
                const failures = [];
                page.on('pageerror', e => failures.push(e.message));
                await page.goto(base + '/__browser__/experience/owner');
                await page.goto(base + '/admin/settings/reverse-ssh');
                await page.getByRole('heading', { name: 'Gateway host readiness' }).waitFor();
                assert.equal(await page.getByRole('heading', { name: 'Configure Reverse SSH' }).count(), 1);
                assert.equal(await page.getByText('Remote Target reachability', { exact: true }).count(), 1);
                assert.equal(await page.locator('input[name="current_password"]').count(), 2);
                await page.goto(base + '/__browser__/managed-reverse-pending');
                await page.getByRole('heading', { name: 'Retry Pending Setup without deleting this Target' }).waitFor();
                const reissue = page.locator('form[action$="/reverse-ssh/reissue"]');
                assert.equal(await reissue.count(), 1);
                assert.equal(await reissue.locator('input[name="confirm_target_id"]').count(), 1);
                assert.equal(await reissue.locator('input[name="current_password"]').count(), 1);
                for (const dir of ['ltr', 'rtl']) {
                    await page.evaluate(value => document.documentElement.setAttribute('dir', value), dir);
                    const geometry = await page.evaluate(() => {
                        const root = document.documentElement;
                        const panel = document.querySelector('#main-content');
                        const f = document.querySelector('form[action$="/reverse-ssh/reissue"]');
                        const submit = f.querySelector('button[type="submit"]');
                        const field = f.querySelector('input[name="confirm_target_id"]');
                        const box = element => {
                            const r = element.getBoundingClientRect();
                            return { left: r.left, right: r.right, top: r.top, bottom: r.bottom };
                        };
                        return {
                            overflow: root.scrollWidth - root.clientWidth,
                            panel: box(panel), form: box(f), submit: box(submit), field: box(field),
                        };
                    });
                    assert.ok(geometry.overflow < 2, 'Document overflow at ' + JSON.stringify({width, dir, geometry}));
                    assert.ok(geometry.form.left >= geometry.panel.left - 2
                        && geometry.form.right <= geometry.panel.right + 2,
                        'Recovery form escaped shared canvas ' + JSON.stringify({width, dir, geometry}));
                    assert.ok(geometry.submit.left >= geometry.form.left - 2
                        && geometry.submit.right <= geometry.form.right + 2,
                        'Recovery action escaped form ' + JSON.stringify({width, dir, geometry}));
                }
                assert.deepEqual(failures, [], 'Client-side runtime errors on managed Reverse UI');
                await context.close();
            }
        }

        const context = await browser.newContext({ viewport: { width: 375, height: 900 }, javaScriptEnabled: false });
        const page = await context.newPage();
        await page.goto(base + '/__browser__/experience/owner');
        await page.goto(base + '/__browser__/managed-reverse-pending');
        const form = page.locator('form[action$="/reverse-ssh/reissue"]');
        await form.locator('[name="confirm_target_id"]').fill('ui-managed-pending');
        await form.locator('[name="current_password"]').fill('wrong-password');
        await form.getByRole('button', { name: 'Reissue one-use install command' }).click();
        await page.getByRole('alert').filter({ hasText: 'Managed Reverse SSH action was not completed' }).waitFor();
        assert.equal(await page.getByRole('button', { name: 'Reissue one-use install command' }).count(), 1,
            'Wrong password must not remove the Owner recovery path.');
        await page.goto(base + '/__browser__/experience/viewer');
        const denied = await page.goto(base + '/admin/settings/reverse-ssh');
        assert.equal(denied.status(), 403, 'Non-owner must not view Reverse SSH control settings.');
        console.log('PASS: real Chromium responsive/dark/RTL recovery forms, no-JS wrong-password denial and non-owner 403.');
        await context.close();
    } finally {
        await browser.close();
    }
})().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
