'use strict';

/* Optional development-only browser test. No production VPN/authentication data.
 * Prerequisites: Node.js >=18, Python 3, a separately installed Playwright dev
 * dependency, and compatible Chromium. This test installs/downloads nothing.
 * From the repository root: node ci/admin_browser_smoke.js
 * Optional environment:
 *   VPN_ADMIN_CHROMIUM_EXECUTABLE=/path/to/chromium
 *   VPN_ADMIN_BROWSER_PYTHON=/path/to/python3
 *   VPN_ADMIN_BROWSER_ARTIFACTS=/local/screenshot/directory
 *   VPN_ADMIN_FIXTURE_PORT=0  (default: an available loopback port)
 * CI currently syntax-checks this file; full browser execution needs a separately
 * reviewed/pinned browser-tooling setup. Never deploy admin_browser_fixture.py.
 */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');

const root = path.resolve(__dirname, '..');
const artifactDirectory = process.env.VPN_ADMIN_BROWSER_ARTIFACTS || path.join(os.tmpdir(), 'vpn-admin-browser');
const controlToken = randomBytes(24).toString('hex');
const port = process.env.VPN_ADMIN_FIXTURE_PORT || '0';
assert.match(port, /^\d{1,5}$/);
assert(Number(port) <= 65535);

function startFixture() {
  const child = spawn(process.env.VPN_ADMIN_BROWSER_PYTHON || 'python3',
    ['-I', '-B', path.join(root, 'ci', 'admin_browser_fixture.py'), '--port', port], {
      cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH || '/usr/bin:/bin', LC_ALL: 'C', VPN_ADMIN_FIXTURE_CONTROL_TOKEN: controlToken }
    });
  return child;
}

function fixtureAddress(child) {
  return new Promise((resolve, reject) => {
    const lines = readline.createInterface({ input: child.stdout });
    const timer = setTimeout(() => reject(new Error('Synthetic browser fixture startup timed out.')), 10000);
    lines.once('line', (line) => {
      clearTimeout(timer);
      try {
        const report = JSON.parse(line);
        assert.equal(report.fixture, 'synthetic');
        assert(Number.isInteger(report.port) && report.port > 0 && report.port <= 65535);
        resolve(`http://127.0.0.1:${report.port}`);
      } catch {
        reject(new Error('Synthetic browser fixture startup response was invalid.'));
      }
    });
    child.once('error', () => { clearTimeout(timer); reject(new Error('Synthetic browser fixture could not start.')); });
    child.once('exit', () => { clearTimeout(timer); reject(new Error('Synthetic browser fixture exited.')); });
  });
}

async function stopFixture(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => {
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    child.once('close', () => { clearTimeout(timer); resolve(); });
    child.kill('SIGTERM');
  });
}

async function main() {
  fs.mkdirSync(artifactDirectory, { recursive: true, mode: 0o700 });
  const fixture = startFixture();
  // Discard fixture diagnostics rather than accidentally forwarding future data.
  fixture.stderr.resume();
  let browser;
  try {
    const origin = await fixtureAddress(fixture);
    const control = async (values) => {
      const response = await fetch(`${origin}/__fixture/control`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Fixture-Control': controlToken },
        body: JSON.stringify(values), signal: AbortSignal.timeout(5000)
      });
      assert.equal(response.status, 200);
    };
    const launch = { headless: true, args: ['--no-sandbox'] };
    if (process.env.VPN_ADMIN_CHROMIUM_EXECUTABLE) launch.executablePath = process.env.VPN_ADMIN_CHROMIUM_EXECUTABLE;
    else if (fs.existsSync('/usr/bin/chromium')) launch.executablePath = '/usr/bin/chromium';
    browser = await chromium.launch(launch);
    const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
    await context.route('**/*', (route) => {
      const url = new URL(route.request().url());
      return url.origin === origin ? route.continue() : route.abort();
    });
    const page = await context.newPage();
    const errors = [];
    const requests = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => requests.push(request.url()));
    const screenshot = (name) => page.screenshot({ path: path.join(artifactDirectory, name), fullPage: true });
    await page.goto(origin);
    await page.locator('#login-view').waitFor({ state: 'visible' });
    await screenshot('login-synthetic.png');
    await page.locator('#admin-password').fill('fixture-only');
    await page.locator('#login-button').click();
    await page.locator('#console-view').waitFor({ state: 'visible' });
    await page.waitForFunction(() => document.querySelector('#dns-value').textContent === 'Responding');
    assert.equal(await page.locator('#grant-value').textContent(), '1');
    assert.equal(await page.locator('#device-list .badge').first().textContent(), 'Forwarding');
    assert.equal(await page.locator('#admin-password').inputValue(), '');
    await page.waitForFunction(() => document.querySelector('#history-rows').children.length === 2);
    assert.match(await page.locator('#history-status').textContent(), /Collector reporting/);
    assert.match(await page.locator('#history-rows').textContent(), /example.com/);
    assert.match(await page.locator('#history-rows').textContent(), /203.0.113.7/);
    await page.locator('#history-search').fill('example.com');
    await page.locator('#history-form button').click();
    await page.waitForFunction(() => document.querySelector('#history-status').textContent.includes('Collector reporting'));
    assert(requests.some((url) => url.includes('/api/history?') && url.includes('search=example.com')));
    await screenshot('overview-synthetic.png');

    await control({ expires_ms: null });
    await page.locator('#refresh-button').click();
    await page.waitForFunction(() => document.querySelector('#grant-value').textContent === '—');
    assert.equal(await page.locator('#device-list .badge').first().textContent(), 'Enabled');
    await control({ expires_ms: 0 });
    await page.locator('#refresh-button').click();
    await page.waitForTimeout(100);
    assert.equal(await page.locator('#grant-value').textContent(), '—');
    await control({ expires_ms: 1000 });
    await page.locator('#refresh-button').click();
    await page.waitForFunction(() => document.querySelector('#grant-value').textContent === '1');
    await page.waitForFunction(() => document.querySelector('#grant-value').textContent === '—', {}, { timeout: 2500 });
    assert.equal(await page.locator('#device-list .badge').first().textContent(), 'Enabled');
    await control({ expires_ms: 15000 });
    await page.locator('#refresh-button').click();
    await page.waitForFunction(() => document.querySelector('#grant-value').textContent === '1');

    await control({ stale: true });
    await page.locator('#refresh-button').click();
    await page.waitForFunction(() => document.querySelector('#vpn-value').textContent === 'Unknown');
    assert.equal(await page.locator('#grant-value').textContent(), '—');
    assert.equal(await page.locator('#device-list .badge').first().textContent(), 'Unknown');
    await control({ stale: false });
    await page.locator('#refresh-button').click();
    await page.waitForFunction(() => document.querySelector('#vpn-value').textContent === 'Active');
    await control({ logout_failure: true });
    await page.locator('#logout-button').click();
    await page.waitForFunction(() => document.querySelector('#status-message').textContent.includes('Sign-out could not be confirmed'));
    await page.locator('#refresh-button').click();
    await page.waitForTimeout(100);
    assert((await page.locator('#status-message').textContent()).includes('Sign-out could not be confirmed'));
    await control({ logout_failure: false });
    await page.locator('#logout-button').click();
    await page.locator('#login-view').waitFor({ state: 'visible' });

    await page.setViewportSize({ width: 390, height: 844 });
    await screenshot('login-mobile-synthetic.png');
    await page.locator('#admin-password').fill('fixture-only');
    await page.locator('#login-button').click();
    await page.locator('#console-view').waitFor({ state: 'visible' });
    await page.waitForFunction(() => document.querySelector('#vpn-value').textContent === 'Active');
    await screenshot('overview-mobile-synthetic.png');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false);
    assert.deepEqual(errors, []);
    assert(requests.every((value) => new URL(value).origin === origin));
    console.log('PASS: real Chromium login/status/DNS/forwarding, stale observations, null/expired grants and between-poll expiry, CSRF logout/retry, mobile layout and no script errors. All API data is SYNTHETIC; no live VPN was tested.');
    console.log(`Synthetic screenshots: ${artifactDirectory}`);
  } finally {
    if (browser) await browser.close();
    await stopFixture(fixture);
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
