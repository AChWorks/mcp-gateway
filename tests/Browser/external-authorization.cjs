'use strict';

// Run only with the disposable loopback fixture in
// bin/check-admin-external-authorization-browser.sh.
// Do not log provider URLs: they contain transient OAuth state.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');

const base = process.env.GATEWAY_BROWSER_BASE_URL;
if (!/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(base || '')) {
  throw new Error('A local-only GATEWAY_BROWSER_BASE_URL is required.');
}

const providerHost = 'provider.browser.test';
const adminCsp = "form-action 'self'";

async function fixture(browser, { javaScriptEnabled = true, width = 1280, dark = false } = {}) {
  const context = await browser.newContext({
    javaScriptEnabled,
    colorScheme: dark ? 'dark' : 'light',
    reducedMotion: dark ? 'reduce' : 'no-preference',
    viewport: { width, height: 800 },
  });
  const page = await context.newPage();
  const responses = [];
  const errors = [];
  let providerHits = 0;

  await page.route('https://provider.browser.test/**', async (route) => {
    providerHits++;
    assert.equal(route.request().method(), 'GET');
    assert.equal(new URL(route.request().url()).pathname, '/wp-ai-bridge/oauth/authorize');
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><html><body><h1>Local consent fixture</h1></body></html>',
    });
  });

  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (url.origin !== base) return;
    if (url.pathname.endsWith('/connect') || url.pathname.includes('/external-authorization/')) {
      const headers = response.headers();
      responses.push({
        method: response.request().method(),
        status: response.status(),
        path: url.pathname,
        csp: headers['content-security-policy'],
        referrer: headers['referrer-policy'],
        cache: headers['cache-control'],
        redirect: headers.location,
      });
    }
  });

  return {
    context,
    page,
    responses,
    errors,
    providerHits: () => providerHits,
  };
}

async function checkAuthorization(browser, options) {
  const run = await fixture(browser, options);
  try {
    await run.page.goto(base + '/__browser__/enter', { waitUntil: 'domcontentloaded' });
    assert.equal(new URL(run.page.url()).pathname, '/admin/targets/browser-wp');
    const button = run.page.getByRole('button', { name: /Authorize WordPress|Restart WordPress authorization/ });
    assert.equal(await button.count(), 1);
    await button.click();
    await run.page.waitForURL((url) => url.hostname === providerHost, { timeout: 15000, waitUntil: 'domcontentloaded' });
    assert.equal(await run.page.locator('h1').innerText(), 'Local consent fixture');
    assert.equal(run.providerHits(), 1, 'The external provider must be reached exactly once.');

    const submitted = run.responses.filter((res) => res.path.endsWith('/connect'));
    const handoffs = run.responses.filter((res) => res.path.includes('/external-authorization/'));
    assert.equal(submitted.length, 1, 'The Admin POST may not be replayed.');
    assert.equal(handoffs.length, 1, 'The transition must use an internal GET.');
    assert.equal(submitted[0].method, 'POST');
    assert.equal(submitted[0].status, 303);
    assert.ok(submitted[0].redirect.startsWith(base + '/admin/targets/browser-wp/external-authorization/'));
    assert.ok(!submitted[0].redirect.includes('state='), 'Never put OAuth state in the internal URL.');
    assert.equal(handoffs[0].method, 'GET');
    assert.equal(handoffs[0].status, 200);
    for (const response of [submitted[0], handoffs[0]]) {
      assert.ok(response.csp.includes(adminCsp), 'Admin CSP was weakened.');
      assert.ok(response.csp.includes("frame-ancestors 'none'"));
      assert.equal(response.referrer, 'no-referrer');
      assert.ok(response.cache.includes('no-store'));
    }
    assert.ok(!run.errors.some((message) => /content security policy/i.test(message)),
      'The authorized navigation was blocked by CSP.');

    console.log('PASS: actual Admin POST -> 303 -> protected GET -> one external provider navigation;'
      + ' JavaScript ' + (options.javaScriptEnabled ? 'on' : 'off') + ', viewport ' + options.width);
  } finally {
    await run.context.close();
  }
}

async function checkOrdinaryFormRestriction(browser) {
  const run = await fixture(browser);
  try {
    await run.page.goto(base + '/__browser__/enter', { waitUntil: 'domcontentloaded' });
    await run.page.evaluate(() => {
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = 'https://provider.browser.test/untrusted';
      document.body.appendChild(form);
      form.submit();
    });
    await run.page.waitForTimeout(600);
    assert.equal(run.providerHits(), 0, 'An unrelated Admin POST must remain blocked.');
    assert.equal(new URL(run.page.url()).origin, base);
    assert.ok(run.errors.some((message) => message.includes(adminCsp)),
      'Expected Chromium CSP rejection of an untrusted direct form submit.');
    console.log('PASS: ordinary cross-origin Admin forms remain blocked by CSP.');
  } finally {
    await run.context.close();
  }
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    await checkAuthorization(browser, { javaScriptEnabled: true, width: 1280 });
    await checkAuthorization(browser, { javaScriptEnabled: false, width: 375, dark: true });
    await checkOrdinaryFormRestriction(browser);
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error('FAIL: browser authorization regression:', error.message);
  process.exitCode = 1;
});
