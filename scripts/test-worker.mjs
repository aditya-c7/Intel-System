import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const state = await mkdtemp(join(tmpdir(), 'intel-worker-'));
const port = 18789;
const base = `http://127.0.0.1:${port}`;
const secret = 'local-test-only-secret-with-more-than-32-characters';
const CHUNK = 256 * 1024;
const DOWNLOAD_BUDGET = 16 * 1024 * 1024;
const UPLOAD_BUDGET = 8 * 1024 * 1024;
let child;
let logs = '';

async function request(path, init = {}) {
  return fetch(base + path, { ...init, signal: AbortSignal.timeout(30000) });
}
async function start(vars = {}) {
  logs = '';
  const args = [
    '--yes', 'wrangler@4.161.0', 'dev', '--ip', '127.0.0.1', '--port', String(port),
    '--inspector-port', '0', '--persist-to', state, '--var', `VISITOR_HMAC_SECRET:${secret}`,
  ];
  for (const [name, value] of Object.entries(vars)) args.push('--var', `${name}:${value}`);
  child = spawn('npx', args, {
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
function signToken(issuedAtMs, runId) {
  const payload = runId ? `${issuedAtMs}:${runId}` : String(issuedAtMs);
  const hmac = createHmac('sha256', secret).update(payload).digest('hex');
  return runId ? `st_${issuedAtMs}_${runId}_${hmac}` : `st_${issuedAtMs}_${hmac}`;
}
async function expectRejection(response, status, code, { retry = true } = {}) {
  assert.equal(response.status, status);
  if (retry) assert.ok(Number(response.headers.get('retry-after')) >= 1, 'Retry-After must be present');
  const body = await response.json();
  assert.equal(body.ok, false);
  assert.equal(body.code, code);
  return body;
}

try {
  // ---------------------------------------------------------------- phase A: live behaviour
  await start({ SPEED_TEST_COOLDOWN_SECONDS: '0' });

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
  const init = await initialized.json();
  assert.match(init.token, /^st_\d{10,17}_r_[0-9a-f]{32}_[0-9a-f]{64}$/);
  assert.equal(init.policy.maxDownloadBytes, DOWNLOAD_BUDGET);
  assert.equal(init.policy.maxUploadBytes, UPLOAD_BUDGET);
  assert.equal(init.policy.downloadPhaseMs, 8000);
  assert.equal(init.policy.uploadPhaseMs, 6000);
  assert.equal(init.policy.concurrentStreams, 2);
  assert.equal(init.policy.maxRequestBytes, CHUNK);
  assert.ok(init.policy.maxRequestsPerRun >= 1);
  assert.equal(init.cooldownSeconds, 0);
  const token = init.token;
  const downloadUrl = `/api/network/download?token=${encodeURIComponent(token)}&bytes=${CHUNK}`;

  // Per-request cap: a 10 MiB request must be cut to the 256 KiB policy maximum.
  const oversizedRequest = await request(`/api/network/download?token=${encodeURIComponent(token)}&bytes=${10 * 1024 * 1024}`);
  assert.equal(oversizedRequest.status, 200);
  assert.equal((await oversizedRequest.arrayBuffer()).byteLength, CHUNK);

  const tampered = `${token.slice(0, -2)}00`;
  await expectRejection(await request(`/api/network/download?token=${encodeURIComponent(tampered)}`), 403, 'UNAUTHORIZED');
  await expectRejection(await request('/api/network/download'), 403, 'UNAUTHORIZED');
  await expectRejection(
    await request(`/api/network/download?token=${encodeURIComponent(signToken(Date.now() - 10 * 60 * 1000, 'r_000000000000000000'))}`),
    403, 'UNAUTHORIZED'
  );
  await expectRejection(
    await request(`/api/network/download?token=${encodeURIComponent(signToken(Date.now() + 10 * 60 * 1000, 'r_000000000000000000'))}`),
    403, 'UNAUTHORIZED'
  );
  // Validly signed but never admitted by the control plane: no ledger row is created.
  await expectRejection(
    await request(`/api/network/download?token=${encodeURIComponent(signToken(Date.now(), 'r_000000000000000000'))}`),
    403, 'RUN_UNKNOWN'
  );

  // Two parallel streams are allowed; extra simultaneous attempts may only be denied with 429
  // (slot leases are released as soon as a response body closes, so the exact overlap is racy).
  const parallel = await Promise.all([downloadUrl, downloadUrl, downloadUrl, downloadUrl].map(url => request(url)));
  const parallelOk = parallel.filter(response => response.status === 200);
  const parallelDenied = parallel.filter(response => response.status === 429);
  assert.ok(parallelOk.length >= 2, 'two concurrent streams must be admitted');
  let downloadedBytes = CHUNK; // the oversized request above already consumed one chunk
  for (const response of parallel) {
    if (response.status === 200) downloadedBytes += (await response.arrayBuffer()).byteLength;
    else await expectRejection(response, 429, 'CONCURRENT_STREAMS');
  }

  // Upload validation: media type, missing authorization and the per-request byte cap.
  await expectRejection(await request('/api/network/upload', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  }), 403, 'UNAUTHORIZED');
  await expectRejection(await request(`/api/network/upload?token=${encodeURIComponent(token)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  }), 415, 'UNSUPPORTED_MEDIA_TYPE');
  await expectRejection(await request(`/api/network/upload?token=${encodeURIComponent(token)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: Buffer.alloc(CHUNK + 4096, 7),
  }), 413, 'UPLOAD_LIMIT_EXCEEDED', { retry: false });

  const upload = await request(`/api/network/upload?token=${encodeURIComponent(token)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: Buffer.alloc(CHUNK, 7),
  });
  assert.equal(upload.status, 200);
  assert.equal((await upload.json()).receivedBytes, CHUNK);

  // Exhaust the download budget one authorized chunk at a time; the last byte past it is denied.
  let downloadDenied = false;
  for (let i = 0; i < 100 && !downloadDenied; i++) {
    const response = await request(downloadUrl);
    if (response.status === 200) {
      const bytes = (await response.arrayBuffer()).byteLength;
      assert.equal(bytes, CHUNK);
      downloadedBytes += bytes;
      assert.ok(downloadedBytes <= DOWNLOAD_BUDGET, 'aggregate download must never exceed the run budget');
    } else {
      await expectRejection(response, 429, 'BUDGET_EXHAUSTED');
      downloadDenied = true;
    }
  }
  assert.ok(downloadDenied, 'download budget exhaustion must be reported as a normal phase endpoint');
  assert.equal(downloadedBytes, DOWNLOAD_BUDGET);

  // Exhaust the upload budget; unused per-request reservations must not inflate the total.
  let uploadedBytes = CHUNK;
  let uploadDenied = false;
  for (let i = 0; i < 60 && !uploadDenied; i++) {
    const response = await request(`/api/network/upload?token=${encodeURIComponent(token)}`, {
      method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: Buffer.alloc(CHUNK, 7),
    });
    if (response.status === 200) {
      const reported = await response.json();
      uploadedBytes += reported.receivedBytes;
      assert.ok(uploadedBytes <= UPLOAD_BUDGET, 'aggregate upload must never exceed the run budget');
    } else {
      await expectRejection(response, 429, 'BUDGET_EXHAUSTED');
      uploadDenied = true;
    }
  }
  assert.ok(uploadDenied, 'upload budget exhaustion must be reported as a normal phase endpoint');

  // Completion invalidates further transfers for the run and does not refund served bytes.
  const completed = await post('/api/network/speed-test/complete', { token });
  assert.equal(completed.status, 200);
  await expectRejection(await request(downloadUrl), 409, 'RUN_COMPLETED');
  await expectRejection(await request(`/api/network/upload?token=${encodeURIComponent(token)}`, {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: Buffer.alloc(1024, 7),
  }), 409, 'RUN_COMPLETED');

  // A fresh explicit run still needs a fresh init; the old token cannot be replayed for it.
  const second = await post('/api/network/speed-test/init', {});
  assert.equal(second.status, 200);
  const secondInit = await second.json();
  assert.notEqual(secondInit.token, token);
  await expectRejection(await request(downloadUrl), 409, 'RUN_COMPLETED');
  const secondDownload = await request(`/api/network/download?token=${encodeURIComponent(secondInit.token)}&bytes=${CHUNK}`);
  assert.equal(secondDownload.status, 200);
  await secondDownload.arrayBuffer();

  for (const path of ['/', '/dashboard/deep-link']) {
    const page = await request(path, { headers: { 'Sec-Fetch-Mode': 'navigate' } });
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    await page.text();
  }

  // ------------------------------------------------- phase B: restart persistence + cooldown
  await stop();
  await start();
  await expectRejection(await post('/api/network/speed-test/init', {}), 429, 'COOLDOWN');
  // Lightweight identity/health keep working while bandwidth tests are cooling down.
  assert.equal((await request('/api/health')).status, 200);
  assert.equal((await request('/api/network/ping')).status, 200);
  // The admitted run ledger survived the restart: a freshly signed token for the same run ID is
  // still accepted, so durable counters are not reset by a Worker restart.
  const resumedRunId = /^st_\d+_(.+)_[0-9a-f]{64}$/.exec(secondInit.token)?.[1];
  assert.ok(resumedRunId, 'run ID must be recoverable from the issued token');
  const resumed = await request(`/api/network/download?token=${encodeURIComponent(signToken(Date.now(), resumedRunId))}&bytes=${CHUNK}`);
  assert.equal(resumed.status, 200);
  await resumed.arrayBuffer();
  const history = await request(`/api/visitor/history/${identity.visitorId}`, {
    headers: { 'X-Visitor-Token': identity.visitorToken },
  });
  assert.equal(history.status, 200);
  assert.equal((await history.json()).visits.length, 1);
  // Identity keeps working during cooldown without affecting the recorded history above.
  assert.equal((await post('/api/visitor/identify', { pageLoadId: 'cooldown-check' })).status, 200);

  // ------------------------------------------------------------ phase C: runtime kill switch
  await stop();
  await start({ SPEED_TEST_DISABLED: '1', SPEED_TEST_COOLDOWN_SECONDS: '0' });
  await expectRejection(await post('/api/network/speed-test/init', {}), 503, 'SPEED_TEST_DISABLED');
  const blocked = await request(`/api/network/download?token=${encodeURIComponent(secondInit.token)}`);
  assert.equal(blocked.status, 503);
  assert.equal((await blocked.json()).code, 'SPEED_TEST_DISABLED');
  assert.ok(Number(blocked.headers.get('retry-after')) >= 1);
  // Kill switch must not break identity, health, ping or static routing.
  assert.equal((await request('/api/health')).status, 200);
  assert.equal((await request('/api/network/ping')).status, 200);
  assert.equal((await post('/api/visitor/identify', { pageLoadId: 'kill-switch-check' })).status, 200);
  const pageDuringKillSwitch = await request('/', { headers: { 'Sec-Fetch-Mode': 'navigate' } });
  assert.equal(pageDuringKillSwitch.status, 200);
  await pageDuringKillSwitch.text();

  // ------------------------------------------- phase D: per-visitor and shared-IP admission caps
  await stop();
  await rm(state, { recursive: true, force: true });
  await start({ SPEED_TEST_COOLDOWN_SECONDS: '0', SPEED_TEST_VISITOR_RUNS_PER_HOUR: '1' });
  assert.equal((await post('/api/network/speed-test/init', {})).status, 200);
  await expectRejection(await post('/api/network/speed-test/init', {}), 429, 'VISITOR_LIMIT');

  await stop();
  await rm(state, { recursive: true, force: true });
  await start({
    SPEED_TEST_COOLDOWN_SECONDS: '0',
    SPEED_TEST_VISITOR_RUNS_PER_HOUR: '60',
    SPEED_TEST_IP_RUNS_PER_HOUR: '1',
  });
  assert.equal((await post('/api/network/speed-test/init', {})).status, 200);
  await expectRejection(await post('/api/network/speed-test/init', {}), 429, 'IP_LIMIT');

  // ------------------------------------------------------- phase E: site-wide UTC-day budget
  await stop();
  await rm(state, { recursive: true, force: true });
  await start({ SPEED_TEST_COOLDOWN_SECONDS: '0', SPEED_TEST_DAILY_BUDGET_MIB: '24' });
  assert.equal((await post('/api/network/speed-test/init', {})).status, 200);
  await expectRejection(await post('/api/network/speed-test/init', {}), 429, 'DAILY_BUDGET');

  console.log('Workers routing, identity/auth, durable quotas, budget enforcement, token validation, kill switch, admission caps and restart persistence checks passed.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  await stop();
  await rm(state, { recursive: true, force: true });
}
