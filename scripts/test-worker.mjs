import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const state = await mkdtemp(join(tmpdir(), 'intel-worker-'));
const port = 18789;
const base = `http://127.0.0.1:${port}`;
let child;
let logs = '';
async function request(path, init = {}) {
  return fetch(base + path, { ...init, signal: AbortSignal.timeout(10000) });
}
async function start() {
  logs = '';
  child = spawn('npx', ['--yes', 'wrangler@4.161.0', 'dev', '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', '0', '--persist-to', state, '--var', 'VISITOR_HMAC_SECRET:local-test-only-secret-with-more-than-32-characters'], {
    detached: true,
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', chunk => { logs += chunk; });
  child.stderr.on('data', chunk => { logs += chunk; });
  let launchError;
  child.on('error', error => { launchError = error; });
  for (let i = 0; i < 120; i++) {
    if (launchError) throw launchError;
    if (child.exitCode !== null) throw new Error(logs);
    try {
      const response = await request('/api/health');
      if (response.status === 200 && (await response.json()).status === 'ok') return;
    } catch {}
    await delay(500);
  }
  throw new Error(`Worker startup timed out:\n${logs}`);
}
async function stop() {
  if (!child) return;
  const processToStop = child;
  child = undefined;
  try { process.kill(-processToStop.pid, 'SIGTERM'); } catch {}
  await delay(1000);
  try { process.kill(-processToStop.pid, 'SIGKILL'); } catch {}
}
const post = (path, body) => request(path, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});
try {
  await start();
  const missing = await request('/api/not-found', { headers: { 'Sec-Fetch-Mode': 'navigate' } });
  assert.equal(missing.status, 404);
  assert.match(missing.headers.get('content-type'), /application\/json/);
  await missing.text();
  const head = await request('/api/network/ping', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  const created = await post('/api/visitor/identify', { pageLoadId: 'worker-regression' });
  assert.equal(created.status, 200);
  const identity = await created.json();
  assert.match(identity.visitorId, /^vid_/);
  const forbidden = await request(`/api/visitor/history/${identity.visitorId}`);
  assert.equal(forbidden.status, 403);
  await forbidden.text();
  const initialized = await post('/api/network/speed-test/init', {});
  assert.equal(initialized.status, 200);
  const { token } = await initialized.json();
  assert.match(token, /^st_/);
  const download = await request(`/api/network/download?token=${encodeURIComponent(token)}&bytes=65536`);
  assert.equal(download.status, 200);
  assert.equal((await download.arrayBuffer()).byteLength, 65536);
  const upload = await request(`/api/network/upload?token=${encodeURIComponent(token)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: Buffer.alloc(65536, 7),
  });
  assert.equal(upload.status, 200);
  assert.equal((await upload.json()).receivedBytes, 65536);
  for (const path of ['/', '/dashboard/deep-link']) {
    const page = await request(path, { headers: { 'Sec-Fetch-Mode': 'navigate' } });
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    await page.text();
  }
  await stop();
  await start();
  const history = await request(`/api/visitor/history/${identity.visitorId}`, {
    headers: { 'X-Visitor-Token': identity.visitorToken },
  });
  assert.equal(history.status, 200);
  assert.equal((await history.json()).visits.length, 1);
  console.log('Workers routing, identity/auth, binary transfers, SPA and restart persistence checks passed.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  await stop();
  await rm(state, { recursive: true, force: true });
}
