'use strict';

// Actual native Laravel grouping/access tasks in the explicitly guarded loopback fixture.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { mkdirSync } = require('node:fs');
const { join } = require('node:path');
const base = process.env.GATEWAY_BROWSER_BASE_URL;
if (!/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(base || '')) throw new Error('A local-only browser fixture is required.');
const password = 'Group-Browser-Password!234';
const artifactDirectory = process.env.GATEWAY_GROUP_BROWSER_ARTIFACT_DIR;
if (artifactDirectory) mkdirSync(artifactDirectory, { recursive: true });
const pass = name => console.log('PASS: ' + name);
const groupPath = id => '/admin/target-groups/' + id;
const userPath = id => '/admin/users/' + id;
const selected = page => page.locator('input[name="selected_ids[]"]');
const counter = page => page.locator('[data-selection-count]');
const row = (page, name) => page.locator('.access-selection-table tbody tr').filter({
    has: page.getByText(name, { exact: true }),
});
async function create(browser, options = {}) {
    const context = await browser.newContext({
        viewport: { width: options.width || 1440, height: 1000 },
        javaScriptEnabled: options.javaScriptEnabled !== false,
        colorScheme: options.dark ? 'dark' : 'light', reducedMotion: 'reduce',
    });
    const page = await context.newPage();
    const errors = [], external = [], posts = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {
        if (new URL(request.url()).origin !== base) external.push(new URL(request.url()).origin);
        if (request.method() === 'POST') {
            const fields = new URLSearchParams(request.postData());
            posts.push({
                path: new URL(request.url()).pathname, csrf: Boolean(fields.get('_token')),
                native: request.isNavigationRequest() && request.resourceType() === 'document',
            });
        }
    });
    return { context, page, errors, external, posts };
}
async function enter(page, role = 'owner') {
    const response = await page.goto(base + '/__browser__/group-workflows/' + role);
    assert.equal(response.status(), 200);
    return response.json();
}
async function post(page, button) {
    const response = page.waitForResponse(r => r.request().method() === 'POST'
        && new URL(r.url()).origin === base);
    await button.click();
    const result = await response;
    assert.equal(result.status(), 302, 'A native operation did not use POST/redirect/GET.');
    await page.waitForLoadState('networkidle');
    return result;
}
async function filter(page, search, membership) {
    await page.getByLabel('Search', { exact: true }).fill(search);
    if (membership) await page.getByLabel('Show', { exact: true }).selectOption(membership);
    await post(page, page.getByRole('button', { name: 'Search and filter', exact: true }));
}
async function choose(page, name) {
    const checkbox = page.getByRole('checkbox', { name: 'Select ' + name, exact: true });
    await checkbox.check();
    return checkbox.inputValue();
}
async function ids(page) {
    return page.locator('input[name="page_ids[]"]').evaluateAll(inputs => inputs.map(input => input.value).sort());
}
async function review(page) {
    await post(page, page.getByRole('button', { name: 'Review selection', exact: true }));
    await page.locator('#access-review-title').waitFor();
}
async function apply(page, ssh = false) {
    await page.getByLabel('Your current password', { exact: true }).fill(password);
    if (ssh) await page.locator('#confirm_ssh_changes').check();
    await post(page, page.getByRole('button', { name: 'Apply reviewed changes', exact: true }));
    await page.getByRole('status').filter({ hasText: 'Changes saved:' }).waitFor();
}
async function sectionSpacing(page, probeFormStack = false) {
    const spacing = await page.evaluate((probe) => {
        const form = document.querySelector('[data-access-selection]');
        if (!form) return null;
        const heading = form.parentElement.querySelector(':scope > .section-heading');
        const next = heading.nextElementSibling;
        const alert = next && next.classList.contains('alert') ? next : null;
        const root = getComputedStyle(document.documentElement);
        const raw = root.getPropertyValue('--ui-panel-stack-gap').trim();
        const expected = parseFloat(raw) * (raw.endsWith('rem') ? parseFloat(root.fontSize) : 1);
        const gaps = [
            (alert || form).getBoundingClientRect().top - heading.getBoundingClientRect().bottom,
        ];
        if (alert) gaps.push(form.getBoundingClientRect().top - alert.getBoundingClientRect().bottom);
        if (probe) {
            const existed = form.classList.contains('form-stack');
            form.classList.add('form-stack');
            gaps.push(form.getBoundingClientRect().top - (alert || heading).getBoundingClientRect().bottom);
            if (!existed) form.classList.remove('form-stack');
        }
        return { expected, gaps };
    }, probeFormStack);
    if (spacing) for (const gap of spacing.gaps) {
        assert.ok(Math.abs(gap - spacing.expected) <= 1,
            'Collection heading/form spacing must be exactly one shared token: ' + JSON.stringify(spacing));
    }
    return spacing;
}
async function capture(page, name, fullPage = false) {
    await sectionSpacing(page);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false,
        'Grouping page overflow: ' + name);
    if (artifactDirectory) {
        await page.mouse.move(1, 1);
        await page.screenshot({ path: join(artifactDirectory, name + '.png'), fullPage });
    }
}
// These are bounded layout exercises, not translations or assistive-technology certification.
// Reload actual server HTML between cases; display-only mutations never enter a submitted form.
async function layoutAdaptation(page, name) {
    const url = page.url();
    const viewport = page.viewportSize();
    for (const variant of ['320px', '200pct-text', 'synthetic-persian-latin-rtl']) {
        await page.setViewportSize({ width: variant === '320px' ? 320 : variant === '200pct-text' ? 768 : 390, height: 1000 });
        await page.emulateMedia({ colorScheme: variant.includes('rtl') ? 'dark' : 'light' });
        await page.goto(url);
        const metrics = await page.evaluate((scenario) => {
            const root = document.documentElement;
            const before = parseFloat(getComputedStyle(root).fontSize);
            if (scenario === '200pct-text') root.style.setProperty('font-size', (before * 2) + 'px', 'important');
            if (scenario.includes('rtl')) {
                root.dir = 'rtl'; root.lang = 'fa';
                const label = 'گروه دسترسی آزمایشی برای مدیریت چند تارگت — Connector-' + 'long-identifier-'.repeat(8);
                document.querySelector('#main-content h1').textContent = label;
                document.querySelectorAll('.access-item-identity strong').forEach((node) => { node.textContent = label; });
            }
            return { scenario, width: innerWidth, before, after: parseFloat(getComputedStyle(root).fontSize), direction: root.dir || 'ltr' };
        }, variant);
        if (variant === '200pct-text') assert.equal(metrics.after, metrics.before * 2);
        if (variant.includes('rtl')) assert.equal(metrics.direction, 'rtl');
        await capture(page, name + '-' + variant, true);
        metrics.spacing = await sectionSpacing(page);
        console.log('LAYOUT ONLY: ' + name + ' ' + JSON.stringify(metrics));
    }
    await page.setViewportSize(viewport);
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto(url);
}
function finish(run) {
    assert.deepEqual(run.errors, []);
    assert.deepEqual(run.external, []);
    for (const request of run.posts) {
        assert.equal(request.csrf, true, 'A grouping POST omitted CSRF.');
        assert.equal(request.native, true, 'A grouping mutation stopped being a native document POST.');
        assert.match(request.path, /^\/admin\/(?:target-groups$|access-changes\/(?:group-targets|group-users|user-groups|user-targets)\/[A-Za-z0-9]+\/(?:selection|apply)$)/,
            'Grouping dispatched an unexpected action.');
    }
}

async function groupTasks(browser) {
    const run = await create(browser);
    const page = run.page;
    try {
        const fixture = await enter(page);
        await page.goto(base + '/admin/target-groups');
        await page.getByRole('link', { name: 'Add target group', exact: true }).click();
        await page.getByRole('heading', { name: 'Add target group', exact: true }).waitFor();
        assert.equal(await page.locator('details').first().getAttribute('open'), null);
        const name = 'Browser-created workflow group';
        await page.getByLabel('Group name', { exact: true }).fill(name);
        await page.getByLabel('Your current password', { exact: true }).fill(password);
        await post(page, page.getByRole('button', { name: 'Create target group', exact: true }));
        assert.match(new URL(page.url()).pathname, /^\/admin\/target-groups\/[A-Za-z0-9]+\/targets$/);
        const groupId = new URL(page.url()).pathname.split('/')[3];
        await page.getByRole('heading', { name, exact: true }).waitFor();
        assert.equal(await page.locator('#access-members-title').innerText(), 'Targets');
        assert.equal(await page.locator('.admin-nav [aria-current="page"]').innerText(), 'Target groups');
        assert.equal(await page.locator('[aria-label="Group sections"] [aria-current="page"]').innerText(), 'Targets');
        assert.match(await page.title(), /Targets/);
        await page.locator('[aria-label="Group sections"]').getByRole('link', { name: 'Users', exact: true }).click();
        await page.waitForURL(base + groupPath(groupId) + '/users');
        assert.equal(await page.locator('#access-members-title').innerText(), 'Users');
        await page.goBack();
        await page.waitForURL(base + groupPath(groupId) + '/targets');
        assert.equal(await page.locator('#access-members-title').innerText(), 'Targets');
        assert.equal(await page.locator('.access-selection-table tbody tr').count(), 0);

        await page.getByRole('link', { name: 'Add Targets', exact: true }).click();
        await filter(page, 'Group fixture Target ');
        assert.equal(await selected(page).count(), 50);
        await page.evaluate(() => {
            const form = document.querySelector('[data-access-selection]');
            window.__groupSelectionEvents = 0;
            form.addEventListener('change', () => window.__groupSelectionEvents++);
            GatewayAdmin.init(document); GatewayAdmin.init(document); GatewayAdmin.init(document);
        });
        const beforeSelectPage = run.posts.length;
        await page.getByRole('button', { name: 'Select this page', exact: true }).click();
        assert.equal(await page.locator('input[name="selected_ids[]"]:checked').count(), 50);
        assert.equal(await counter(page).innerText(), '50 selected');
        assert.equal(await page.evaluate(() => window.__groupSelectionEvents), 1, 'Repeated initialization duplicated the selection action.');
        assert.equal(run.posts.length, beforeSelectPage, 'Progressive Select page unexpectedly submitted.');
        await post(page, page.getByRole('button', { name: 'Clear selection', exact: true }));
        assert.equal(await counter(page).innerText(), '0 selected');

        const chosen = [await choose(page, fixture.targets[0].label), await choose(page, fixture.targets[1].label)];
        assert.equal(await counter(page).innerText(), '2 selected');
        await post(page, page.getByRole('button', { name: 'Next', exact: true }));
        assert.equal(await selected(page).count(), 5);
        assert.equal(await counter(page).innerText(), '2 selected');
        chosen.push(await choose(page, fixture.targets[50].label));
        await filter(page, 'definitely-no-group-fixture-match');
        assert.equal(await selected(page).count(), 0);
        assert.equal(await counter(page).innerText(), '3 selected');
        await page.getByText('No items match these filters. Your saved selection is kept.', { exact: true }).waitFor();
        await post(page, page.getByRole('button', { name: 'View selected', exact: true }));
        assert.equal(await page.getByLabel('Search', { exact: true }).inputValue(), '',
            'View selected must reveal the basket independently of the old no-match filter.');
        assert.deepEqual(await ids(page), [...chosen].sort());
        assert.equal(await page.locator('input[name="intent"]').inputValue(), 'add');
        await filter(page, 'Group fixture Target', 'all');
        assert.equal(await page.locator('input[name="intent"]').inputValue(), 'add', 'All view changed the explicit Add operation.');
        assert.equal(await counter(page).innerText(), '3 selected');
        await filter(page, 'old-filter-does-not-match', 'selected');
        assert.equal(await page.locator('input[name="intent"]').inputValue(), 'add', 'Selected view changed Add into Remove.');
        assert.equal(await page.getByLabel('Search', { exact: true }).inputValue(), '');
        assert.deepEqual(await ids(page), [...chosen].sort());
        await filter(page, fixture.targets[0].label, 'selected');
        assert.deepEqual(await ids(page), [chosen[0]], 'Searching within Selected should refine that basket.');
        assert.equal(await counter(page).innerText(), '3 selected');
        await post(page, page.getByRole('button', { name: 'View selected', exact: true }));
        assert.deepEqual(await ids(page), [...chosen].sort());
        await review(page);
        assert.equal(await page.locator('main tbody tr').count(), 3);
        assert.equal(await page.locator('#confirm_ssh_changes').count(), 0, 'WP-only membership asked for SSH review.');
        assert.equal(await page.locator('.admin-nav [aria-current="page"]').innerText(), 'Target groups');
        await capture(page, 'group-review-desktop-light');

        const reviewUrl = page.url();
        const reviewId = await page.locator('input[name="review_id"]').inputValue();
        await page.getByLabel('Your current password', { exact: true }).fill('wrong-fixture-password');
        await post(page, page.getByRole('button', { name: 'Apply reviewed changes', exact: true }));
        assert.equal(page.url(), reviewUrl);
        assert.equal(await page.locator('input[name="review_id"]').inputValue(), reviewId);
        await page.locator('#current_password-error').waitFor();
        assert.equal(await page.getByLabel('Your current password', { exact: true }).inputValue(), '');
        const inspect = await run.context.newPage();
        await inspect.goto(base + groupPath(groupId) + '/targets');
        assert.equal(await inspect.locator('.access-selection-table tbody tr').count(), 0, 'Wrong password wrote memberships.');
        await inspect.close();
        await apply(page);
        await page.reload();
        assert.deepEqual(await ids(page), [...chosen].sort(), 'Only the three reviewed identities may become members.');

        await choose(page, fixture.targets[0].label);
        await review(page);
        await apply(page);
        await page.reload();
        assert.deepEqual(await ids(page), chosen.slice(1).sort(), 'Removing one selected member changed an unselected membership.');

        await page.locator('[aria-label="Group sections"]').getByRole('link', { name: 'Users', exact: true }).click();
        await page.getByRole('link', { name: 'Add users', exact: true }).click();
        await filter(page, fixture.users.other.label);
        await choose(page, fixture.users.other.label);
        await review(page);
        assert.equal(await page.locator('#confirm_ssh_changes').count(), 0);
        await apply(page);
        assert.deepEqual(await ids(page), [fixture.users.other.id]);

        await page.goto(base + userPath(fixture.users.member.id) + '/edit');
        await page.locator('[aria-label="User access sections"]').getByRole('link', { name: 'Groups', exact: true }).click();
        await page.getByRole('link', { name: 'Assign groups', exact: true }).click();
        await filter(page, 'Browser fixture');
        await choose(page, fixture.groups.native.label);
        await choose(page, fixture.groups.denial.label);
        await review(page);
        assert.equal(await page.locator('#confirm_ssh_changes').count(), 1, 'SSH-denial group lost its applicable review.');
        assert.equal(await page.locator('#confirm_ssh_changes').isChecked(), false);
        assert.match(await page.locator('label[for="confirm_ssh_changes"]').innerText(), /memberships/i);
        const sshReviewId = await page.locator('input[name="review_id"]').inputValue();
        await page.getByLabel('Your current password', { exact: true }).fill(password);
        await post(page, page.getByRole('button', { name: 'Apply reviewed changes', exact: true }));
        assert.equal(await page.locator('input[name="review_id"]').inputValue(), sshReviewId);
        await page.locator('#confirm_ssh_changes-error').waitFor();
        await apply(page, true);
        assert.deepEqual(await ids(page), [fixture.groups.native.id, fixture.groups.denial.id].sort());

        await page.locator('[aria-label="User access sections"]').getByRole('link', { name: 'Targets', exact: true }).click();
        await page.getByRole('link', { name: 'Add Targets', exact: true }).click();
        await filter(page, 'Group fixture Target 01');
        await choose(page, fixture.targets[10].label);
        await choose(page, fixture.targets[11].label);
        await review(page);
        assert.equal(await page.locator('#confirm_ssh_changes').count(), 0);
        await apply(page);
        for (const target of [fixture.targets[10], fixture.targets[11]]) {
            await row(page, target.label).getByText('Direct rule', { exact: true }).waitFor();
        }
        await row(page, fixture.special.blocked.label).getByText('Explicitly blocked', { exact: true }).waitFor();
        await page.getByRole('link', { name: 'Add Targets', exact: true }).click();
        await filter(page, fixture.special.blocked.label);
        await choose(page, fixture.special.blocked.label);
        await review(page);
        assert.equal(await page.getByRole('button', { name: 'Apply reviewed changes', exact: true }).isDisabled(), true);
        await page.getByText('An explicit direct Deny must be reviewed in the individual Target editor.', { exact: true }).waitFor();
        const exactEditor = base + userPath(fixture.users.member.id) + '/targets/group-browser-blocked/edit';
        const blockedEditorLink = page.getByRole('link', { name: 'Open individual Target rules', exact: true });
        assert.equal(await blockedEditorLink.getAttribute('href'), exactEditor);
        await blockedEditorLink.click();
        await page.waitForURL(exactEditor);
        assert.equal(await page.locator('.page-heading code').innerText(), 'group-browser-blocked');
        assert.equal(await page.getByLabel('Explicit scope rule', { exact: true }).inputValue(), 'deny');
        // Individual ACL editors intentionally use native full navigation outside Turbo's finite allowlist.
        assert.equal(await page.locator('.admin-nav [aria-current="page"]').innerText(), 'Users');
        await page.getByRole('link', { name: 'Back to target access', exact: true }).click();
        await page.waitForURL(base + userPath(fixture.users.member.id) + '/targets');
        await row(page, fixture.special.blocked.label).getByText('Deny', { exact: true }).waitFor();

        await page.getByRole('link', { name: 'Add Targets', exact: true }).click();
        await post(page, page.getByRole('button', { name: 'Clear selection', exact: true }));
        await filter(page, fixture.special.ssh.label);
        await choose(page, fixture.special.ssh.label);
        await review(page);
        assert.equal(await page.locator('#confirm_ssh_changes').count(), 1);
        assert.equal(await page.locator('#confirm_ssh_changes').isChecked(), false);
        const directSshCopy = await page.locator('label[for="confirm_ssh_changes"]').innerText();
        assert.match(directSshCopy, /direct Target scope changes/i);
        assert.match(directSshCopy, /Allow or Deny/);
        assert.match(directSshCopy, /Inherit/);
        assert.doesNotMatch(directSshCopy, /memberships/i);
        await capture(page, 'direct-ssh-review-1440-light', true);
        await page.setViewportSize({ width: 390, height: 1000 });
        await page.emulateMedia({ colorScheme: 'dark' });
        await capture(page, 'direct-ssh-review-390-dark', true);
        await layoutAdaptation(page, 'direct-ssh-review-layout');

        let renders = 0;
        for (const width of [390, 768, 1440]) for (const theme of ['light', 'dark']) {
            await page.setViewportSize({ width, height: 1000 });
            await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
            for (const [label, route] of [
                ['group-members', groupPath(groupId) + '/targets'],
                ['group-picker', groupPath(groupId) + '/targets?membership=available&intent=add&search=Group%20fixture%20Target'],
                ['group-users', groupPath(groupId) + '/users'],
                ['user-groups', userPath(fixture.users.member.id) + '/groups'],
                ['user-targets', userPath(fixture.users.member.id) + '/targets'],
            ]) {
                await page.goto(base + route);
                await page.locator('#main-content h1').waitFor();
                assert.equal(await page.locator('.admin-nav [aria-current="page"]').count(), 1);
                await capture(page, label + '-' + width + '-' + theme);
                renders++;
            }
        }
        await layoutAdaptation(page, 'user-targets-collection-layout');
        finish(run);
        pass('group creation/member-first navigation; explicit cross-page/search basket; native exact review/apply and removal; password/SSH review recovery; user-centric access; '+renders+' viewport/theme renders');
    } finally { await run.context.close(); }
}

async function nativeAndDenied(browser) {
    const run = await create(browser, { width: 390, dark: true, javaScriptEnabled: false });
    const page = run.page;
    try {
        const fixture = await enter(page);
        await page.goto(base + groupPath(fixture.groups.native.id) + '/targets');
        await page.getByRole('link', { name: 'Add Targets', exact: true }).click();
        await filter(page, 'Group fixture Target ');
        assert.equal(await page.evaluate(() => typeof window.GatewayAdmin), 'undefined');
        await post(page, page.getByRole('button', { name: 'Select this page', exact: true }));
        assert.equal(await counter(page).innerText(), 'Saved selection: 50');
        await post(page, page.getByRole('button', { name: 'Next', exact: true }));
        assert.equal(await selected(page).count(), 5);
        assert.equal(await counter(page).innerText(), 'Saved selection: 50');
        await post(page, page.getByRole('button', { name: 'Clear selection', exact: true }));
        assert.equal(await counter(page).innerText(), 'Saved selection: 0');
        await post(page, page.getByRole('button', { name: 'Review selection', exact: true }));
        await page.getByText('Select at least one item to review.', { exact: true }).waitFor();
        console.log('LAYOUT: native feedback with form-stack probe ' + JSON.stringify(await sectionSpacing(page, true)));
        await capture(page, 'empty-selection-error-mobile-dark');
        await page.getByRole('link', { name: 'View current members', exact: true }).click();
        await page.getByRole('link', { name: 'Add Targets', exact: true }).click();
        await filter(page, 'Group fixture Target ');
        const chosen = [await choose(page, fixture.targets[3].label), await choose(page, fixture.targets[4].label)];
        await review(page);
        assert.equal(await page.locator('main tbody tr').count(), 2);
        assert.equal(await page.locator('#confirm_ssh_changes').count(), 0);
        await apply(page);
        await page.reload();
        assert.deepEqual(await ids(page), [...chosen, fixture.special.native.id].sort());
        finish(run);
        pass('no-JavaScript native Select page/paging/clear/review/apply; only explicit choices saved and existing member retained');
    } finally { await run.context.close(); }

    const denied = await create(browser, { width: 390, dark: true });
    try {
        const fixture = await enter(denied.page, 'operator');
        const response = await denied.page.goto(base + groupPath(fixture.groups.native.id) + '/targets');
        assert.equal(response.status(), 403);
        assert.equal(await denied.page.locator('.access-selection-table').count(), 0);
        assert.equal(await denied.page.locator('.admin-nav').getByRole('link', { name: 'Target groups', exact: true }).count(), 0);
        await capture(denied.page, 'operator-forbidden-mobile-dark');
        finish(denied);
        pass('Operator remains forbidden from group access administration; shared section/form/alert gaps and distinct direct-SSH review copy');
    } finally { await denied.context.close(); }
}

(async () => {
    const browser = await chromium.launch({ headless: true });
    try {
        await groupTasks(browser);
        await nativeAndDenied(browser);
    } finally { await browser.close(); }
})().catch(error => {
    console.error('FAIL: Admin group workflow regression:', error.stack || error.message);
    process.exitCode = 1;
});
