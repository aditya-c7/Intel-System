import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import puppeteer from 'puppeteer-core';

/**
 * Browser-level regression test for the Network Stability panel's RTT monitoring.
 * Requires a built dashboard (npm run build) and a system Chromium.
 * It runs against a local Worker; it never touches production.
 */

const state = await mkdtemp(join(tmpdir(), 'intel-browser-'));
const port = 18791;
const base = `http://127.0.0.1:${port}`;
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

async function waitForPanel(page) {
  await page.waitForFunction(
    () => [...document.querySelectorAll('button')].some(button =>
      /live rtt monitoring/i.test(button.getAttribute('title') || '')
    ),
    { timeout: 30000 }
  );
}

const executablePath = chromiumPath();
if (!executablePath) {
  console.log('Skipping browser panel checks: no system Chromium found (set CHROMIUM_PATH).');
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

  // Two same-origin tabs share RTT polling through a leader lease; closing the leader tab
  // lets the mirror tab take over within the 12s lease window.
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
  await page.goto(base, { waitUntil: 'networkidle2', timeout: 60000 });
  await waitForPanel(page);
  const mirrorPage = await browser.newPage();
  watchPings(mirrorPage, 'b');
  await mirrorPage.goto(base, { waitUntil: 'networkidle2', timeout: 60000 });
  await waitForPanel(mirrorPage);
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

  console.log('Browser panel checks passed: RTT polling and tab leader handover.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  if (browser) await browser.close().catch(() => {});
  await stopWorker();
  await rm(state, { recursive: true, force: true });
}
