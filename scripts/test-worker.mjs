import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const state = await mkdtemp(join(tmpdir(), 'intel-worker-'));
const port = 18789;
const base = `http://127.0.0.1:${port}`;
const secret = 'local-test-only-secret-with-more-than-32-characters';
let child;
let logs = '';

async function request(path, init = {}) {
  return fetch(base + path, { ...init, signal: AbortSignal.timeout(30000) });
}
async function start() {
  logs = '';
  const args = [
    '--yes', 'wrangler@4.161.0', 'dev', '--ip', '127.0.0.1', '--port', String(port),
    '--inspector-port', '0', '--persist-to', state, '--var', `VISITOR_HMAC_SECRET:${secret}`,
  ];
  const options = {
    detached: true,
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    stdio: ['ignore', 'pipe', 'pipe'],
  };
  if (process.platform === 'win32') {
    // Windows needs a shell to launch npx.cmd. Pass the whole command as one
    // string (no separate args) so Node does not emit DEP0190, which warns
    // when args are combined with shell:true. Linux keeps the plain spawn.
    child = spawn(['npx.cmd', ...args].join(' '), { ...options, shell: true });
  } else {
    child = spawn('npx', args, options);
  }
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
  if (process.platform === 'win32') {
    // Negative-PID process-group signals are POSIX-only and are a no-op on
    // Windows. Kill the whole process tree (cmd -> npx -> wrangler -> workerd)
    // instead, otherwise stale workers keep port 18789 and its file handles.
    try { spawnSync('taskkill', ['/PID', String(processToStop.pid), '/T', '/F'], { stdio: 'ignore' }); } catch {}
    await delay(1000);
    return;
  }
  try { process.kill(-processToStop.pid, 'SIGTERM'); } catch {}
  await delay(1000);
  try { process.kill(-processToStop.pid, 'SIGKILL'); } catch {}
}
const post = (path, body) => request(path, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

try {
  // ---------------------------------------------------------------- phase A: live behaviour
  await start();

  const missing = await request('/api/not-found', { headers: { 'Sec-Fetch-Mode': 'navigate' } });
  assert.equal(missing.status, 404);
  assert.match(missing.headers.get('content-type'), /application\/json/);
  await missing.text();

  const head = await request('/api/network/ping', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');

  const ping = await request('/api/network/ping');
  assert.equal(ping.status, 200);
  assert.equal((await ping.json()).ok, true);

  const created = await post('/api/visitor/identify', { pageLoadId: 'worker-regression' });
  assert.equal(created.status, 200);
  const identity = await created.json();
  assert.match(identity.visitorId, /^vid_/);
  const forbidden = await request(`/api/visitor/history/${identity.visitorId}`);
  assert.equal(forbidden.status, 403);
  await forbidden.text();

  for (const path of ['/', '/dashboard/deep-link']) {
    const page = await request(path, { headers: { 'Sec-Fetch-Mode': 'navigate' } });
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    await page.text();
  }

  // ------------------------------------------------- phase B: restart persistence
  await stop();
  await start();
  assert.equal((await request('/api/health')).status, 200);
  assert.equal((await request('/api/network/ping')).status, 200);
  const history = await request(`/api/visitor/history/${identity.visitorId}`, {
    headers: { 'X-Visitor-Token': identity.visitorToken },
  });
  assert.equal(history.status, 200);
  assert.equal((await history.json()).visits.length, 1);
  // Identity keeps working after a Worker restart without losing the recorded history above.
  assert.equal((await post('/api/visitor/identify', { pageLoadId: 'restart-check' })).status, 200);

  console.log('Workers routing, identity/auth, SPA fallback and restart persistence checks passed.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  await stop();
  // On Windows, Miniflare can briefly keep a handle open on its cache object
  // (miniflare-CacheObject), so rm may fail with EBUSY/EPERM right after stop().
  // Retry a few times, then make one final best-effort pass that never fails
  // the test suite. CI runs on Linux and is unaffected.
  const removeState = () => rm(state, { recursive: true, force: true });
  let cleaned = false;
  for (let attempt = 0; attempt < 5 && !cleaned; attempt++) {
    try {
      await removeState();
      cleaned = true;
    } catch (error) {
      if (error?.code !== 'EBUSY' && error?.code !== 'EPERM') throw error;
      await delay(500);
    }
  }
  if (!cleaned) {
    try {
      await removeState();
    } catch (error) {
      console.warn(`Warning: could not fully clean up test state at ${state}: ${error?.message || error}`);
    }
  }
}
