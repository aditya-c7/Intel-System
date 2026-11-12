import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import puppeteer from 'puppeteer-core';

/**
 * Browser-level regression test for the one-shot speed-test lifecycle.
 * Requires a built dashboard (npm run build) and a system Chromium.
 * It runs against a local Worker; it never touches production.
 */

const state = await mkdtemp(join(tmpdir(), 'intel-browser-'));
const port = 18791;
const base = `http://127.0.0.1:${port}`;
const speedTestRequests = [];
let child;
let logs = '';
let browser;

function chromiumPath() {
  const candidates = [
    process.env.CHROMIUM_PATH,
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
  ].filter(Boolean);
  return candidates.find(candidate => existsSync(candidate));
}

async function startWorker() {
  logs = '';
  child = spawn('npx', [
    '--yes', 'wrangler@4.161.0', 'dev', '--ip', '127.0.0.1', '--port', String(port),
    '--inspector-port', '0', '--persist-to', state,
    '--var', 'VISITOR_HMAC_SECRET:local-browser-test-secret-with-more-than-32-chars',
    '--var', 'SPEED_TEST_COOLDOWN_SECONDS:0',
  ], {
    detached: true,
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', chunk => { logs += chunk; });
  child.stderr.on('data', chunk => { logs += chunk; });
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) throw new Error(logs);
    try {
      const response = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(2000) });
      if (response.status === 200) return;
    } catch {}
    await delay(500);
  }
  throw new Error(`Worker startup timed out:\n${logs}`);
}

async function stopWorker() {
  if (!child) return;
  const processToStop = child;
  child = undefined;
  try { process.kill(-processToStop.pid, 'SIGTERM'); } catch {}
  await delay(1000);
  try { process.kill(-processToStop.pid, 'SIGKILL'); } catch {}
}

const countPath = path => speedTestRequests.filter(url => url.includes(path)).length;

async function waitForPanel(page) {
  await page.waitForFunction(
    () => [...document.querySelectorAll('button')].some(button => /speed test|run again/i.test(button.textContent || '')),
    { timeout: 30000 }
  );
}

async function clickByText(page, pattern) {
  const clicked = await page.evaluate(matcher => {
    const regex = new RegExp(matcher, 'i');
    const button = [...document.querySelectorAll('button')].find(candidate => regex.test(candidate.textContent || ''));
    if (!button) return false;
    button.click();
    return true;
  }, pattern);
  assert.ok(clicked, `button matching ${pattern} must exist`);
}

const executablePath = chromiumPath();
if (!executablePath) {
  console.log('Skipping browser lifecycle checks: no system Chromium found (set CHROMIUM_PATH).');
  process.exit(0);
}

try {
  await startWorker();
  browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });
  const page = await browser.newPage();
  page.on('request', request => {
    const url = request.url();
    if (/\/(download|upload)(\?|$)/.test(url) || /speed-test\/(init|complete)/.test(url)) {
      speedTestRequests.push(url);
    }
  });

  // 1. Idle mount: no bandwidth-test traffic before an explicit Start.
  await page.goto(base, { waitUntil: 'networkidle2', timeout: 60000 });
  await waitForPanel(page);
  await delay(2000);
  assert.equal(countPath('/speed-test/init'), 0, 'mount must not initialize a speed test');
  assert.equal(countPath('/download'), 0, 'mount must not download test payloads');
  assert.equal(countPath('/upload'), 0, 'mount must not upload test payloads');

  // 2. One click runs exactly one download phase and one upload phase, then stops.
  await clickByText(page, '^start speed test$');
  await page.waitForFunction(
    () => [...document.querySelectorAll('button')].some(button => /run again/i.test(button.textContent || '')),
    { timeout: 60000 }
  );
  assert.equal(countPath('/speed-test/init'), 1, 'one click must start exactly one run');
  assert.ok(countPath('/download') > 0, 'the run must perform download transfers');
  assert.ok(countPath('/upload') > 0, 'the run must perform upload transfers');
  await delay(1500);
  assert.equal(countPath('/speed-test/complete'), 1, 'the completed run must be finalized once');
  const kinds = speedTestRequests.map(url =>
    url.includes('/speed-test/init') ? 'init'
      : url.includes('/speed-test/complete') ? 'complete'
      : url.includes('/upload') ? 'upload'
      : url.includes('/download') ? 'download'
      : 'other'
  );
  const firstIndex = kinds.indexOf('init');
  const uploadIndex = kinds.indexOf('upload');
  const completeIndex = kinds.indexOf('complete');
  console.log(
    `[trace] sequence: init@${firstIndex}, ${kinds.filter(kind => kind === 'download').length} downloads, ` +
    `upload@${uploadIndex}, complete@${completeIndex}; total requests=${kinds.length}`
  );

  // 3. No automatic repeat, even with a zero cooldown and an idle tab.
  const initsAfterRun = countPath('/speed-test/init');
  await delay(12000);
  assert.equal(countPath('/speed-test/init'), initsAfterRun, 'the test must never restart automatically');

  // 4. Reload restores the result without starting a new run.
  await page.reload({ waitUntil: 'networkidle2' });
  await waitForPanel(page);
  await delay(2000);
  assert.equal(countPath('/speed-test/init'), initsAfterRun, 'restoring results must not start a run');

  // 5. A fast double click starts only one run.
  await page.evaluate(() => {
    const button = [...document.querySelectorAll('button')].find(candidate => /run again|start speed test/i.test(candidate.textContent || ''));
    button?.click();
    button?.click();
  });
  await delay(1500);
  assert.equal(countPath('/speed-test/init'), initsAfterRun + 1, 'a double click must start only one run');
  await page.waitForFunction(
    () => [...document.querySelectorAll('button')].some(button => /run again/i.test(button.textContent || '')),
    { timeout: 60000 }
  );

  // 6. Cancel aborts in-flight transfers and leaves an explicit cancelled state.
  const downloadsBeforeCancel = countPath('/download');
  await clickByText(page, '^run again$');
  await page.waitForFunction(
    () => [...document.querySelectorAll('button')].some(button => /cancel test/i.test(button.textContent || '')),
    { timeout: 15000 }
  );
  await clickByText(page, '^cancel test$');
  await delay(500);
  const downloadsAtCancel = countPath('/download');
  await delay(2500);
  assert.ok(countPath('/download') - downloadsAtCancel <= 2, 'cancel must stop further download requests');
  assert.ok(downloadsBeforeCancel >= 0);
  const cancelledText = await page.evaluate(() => document.body.innerText);
  assert.match(cancelledText, /cancelled/i, 'the UI must show a cancelled state instead of a fake result');

  // 7. Two same-origin tabs share RTT polling through a leader lease; closing the leader
  //    tab lets the mirror tab take over within the 12s lease window.
  const pingCounts = new Map();
  const watchPings = (target, id) => {
    pingCounts.set(id, 0);
    target.on('request', request => {
      if (request.url().includes('/api/network/ping')) {
        pingCounts.set(id, (pingCounts.get(id) || 0) + 1);
      }
    });
  };
  watchPings(page, 'a');
  const startMonitor = () => page.evaluate(() => {
    const button = [...document.querySelectorAll('button')].find(candidate =>
      /start live rtt monitoring/i.test(candidate.getAttribute('title') || '')
    );
    button?.click();
  });
  await startMonitor();
  const mirrorPage = await browser.newPage();
  watchPings(mirrorPage, 'b');
  await mirrorPage.goto(base, { waitUntil: 'networkidle2', timeout: 60000 });
  await mirrorPage.evaluate(() => {
    const button = [...document.querySelectorAll('button')].find(candidate =>
      /start live rtt monitoring/i.test(candidate.getAttribute('title') || '')
    );
    button?.click();
  });
  await delay(8000);
  const aPings = pingCounts.get('a') || 0;
  const bPings = pingCounts.get('b') || 0;
  assert.ok(aPings + bPings > 0, 'at least one tab must probe RTT');
  assert.ok(aPings === 0 || bPings === 0, 'only the leader tab may probe RTT');
  const leaderIsA = aPings > 0;
  const follower = leaderIsA ? mirrorPage : page;
  const leader = leaderIsA ? page : mirrorPage;
  const followerId = leaderIsA ? 'b' : 'a';
  await leader.close();
  const followerBefore = pingCounts.get(followerId) || 0;
  await delay(15000);
  const followerAfter = pingCounts.get(followerId) || 0;
  assert.ok(
    followerAfter > followerBefore,
    'the mirror tab must take over polling after the leader closes'
  );
  const followerText = await follower.evaluate(() => document.body.innerText);
  assert.match(followerText, /Probing this tab/i, 'the surviving tab must become the leader');

  console.log('Browser lifecycle checks passed: idle -> one run -> no repeat, restore, double click, cancel, tab leader handover.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  if (browser) await browser.close().catch(() => {});
  await stopWorker();
  await rm(state, { recursive: true, force: true });
}
