import { createServer } from 'node:http';
import { handleAsNodeRequest } from 'cloudflare:node';
import { DurableObject } from 'cloudflare:workers';
import app, {
  initializeDatabaseSchema,
  withDatabase,
  verifySpeedTestToken,
  effectiveSpeedTestPolicy,
  speedTestDisabled,
  hashQuotaKey,
  signSpeedTransferGrant,
  signSpeedAdmission,
} from '../server.ts';

// Workers' node:http adapter uses this as a routing key, not a public TCP port.
const API_PORT = 3000;
createServer(app).listen(API_PORT);

const INTERNAL_SPEED_HEADERS = ['x-intel-speed-admission', 'x-intel-speed-grant'];
const SPEED_STORE_NAME = 'speed-test-control-v1';
const SPEED_RUN_GRACE_MS = 60 * 1000;
const SPEED_SLOT_LEASE_MS = 15 * 1000;
const SPEED_STORE_ALARM_MS = 10 * 60 * 1000;
const SPEED_LIMIT_MESSAGES = {
  COOLDOWN: 'A speed test ran recently. Wait for the cooldown to finish.',
  VISITOR_LIMIT: 'Hourly run limit reached for this visitor.',
  IP_LIMIT: 'Hourly run limit reached for this shared network.',
  DAILY_BUDGET: 'Daily speed-test transfer budget exhausted. Try again after 00:00 UTC.',
  CONCURRENT_STREAMS: 'Concurrent stream limit reached for this run.',
  BUDGET_EXHAUSTED: 'Run transfer budget exhausted.',
  RUN_REQUEST_LIMIT: 'Run request limit reached.',
  RUN_UNKNOWN: 'This speed-test run is unknown or expired.',
  RUN_COMPLETED: 'This speed-test run is already finished.',
};

function utcDay(nowMs) {
  return new Date(nowMs).toISOString().slice(0, 10);
}

function apiResponse(response) {
  const result = new Response(response.body, response);
  result.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, no-transform');
  result.headers.set('Permissions-Policy', 'compute-pressure=*');
  result.headers.set('X-Content-Type-Options', 'nosniff');
  return result;
}

function speedRejection(status, code, retryAfterSeconds, message) {
  const retry = Math.max(1, Math.ceil(Number(retryAfterSeconds) || 1));
  return Response.json(
    {
      ok: false,
      code,
      error: message || SPEED_LIMIT_MESSAGES[code] || 'Speed test request rejected.',
      retryAfterSeconds: retry,
    },
    { status, headers: { 'Cache-Control': 'no-store', 'Retry-After': String(retry) } }
  );
}

function stripInternalHeaders(request) {
  const forwarded = new Request(request);
  for (const name of INTERNAL_SPEED_HEADERS) forwarded.headers.delete(name);
  return forwarded;
}

function clientIp(request) {
  // Platform-established address only. Forwarding headers are not trusted here.
  return (request.headers.get('CF-Connecting-IP') || '').trim();
}

function visitorKey(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = /(?:^|;\s*)intel_http_vid=([^;]+)/.exec(cookie);
  if (match) return decodeURIComponent(match[1]);
  return clientIp(request) || 'anon';
}

function tokenFromRequest(request, url) {
  return (
    url.searchParams.get('token') ||
    request.headers.get('x-speed-test-token') ||
    request.headers.get('x-speedtest-token') ||
    ''
  );
}

function requestedChunkBytes(request, url, policy) {
  const headerValue = Number(request.headers.get('x-speedtest-bytes'));
  const queryValue = Number.parseInt(url.searchParams.get('bytes') || '', 10);
  const requested = Number.isFinite(headerValue) && headerValue > 0 ? headerValue : queryValue;
  if (!Number.isFinite(requested) || requested <= 0) return policy.maxRequestBytes;
  return Math.max(
    policy.minRequestBytes,
    Math.min(policy.maxRequestBytes, Math.floor(requested))
  );
}

function storeStub(env) {
  return env.SPEED_TEST_STORE.get(env.SPEED_TEST_STORE.idFromName(SPEED_STORE_NAME));
}

async function callStore(env, path, payload) {
  const response = await storeStub(env).fetch(`https://speed-test-store.internal${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Speed-test control plane error ${response.status}`);
  return response.json();
}

function releaseStore(env, payload) {
  return callStore(env, '/release', payload).catch(() => {});
}

/**
 * Durable speed-test control plane: admission windows, per-run byte reservations, stream slots
 * and the site-wide UTC-day budget. Payload bytes never pass through this object; only small
 * counters are stored. Must be deployed as a single named instance.
 */
export class SpeedTestStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS speed_day (
      day TEXT PRIMARY KEY,
      reserved INTEGER NOT NULL DEFAULT 0
    )`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS speed_admit (
      kind TEXT NOT NULL,
      key TEXT NOT NULL,
      ts INTEGER NOT NULL
    )`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS speed_admit_lookup ON speed_admit (kind, key, ts)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS speed_run (
      run_id TEXT PRIMARY KEY,
      downloaded INTEGER NOT NULL DEFAULT 0,
      uploaded INTEGER NOT NULL DEFAULT 0,
      requests INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL,
      completed INTEGER NOT NULL DEFAULT 0
    )`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS speed_slot (
      slot_id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      phase TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`);
  }

  purge(nowMs) {
    this.sql.exec('DELETE FROM speed_slot WHERE expires_at < ?', nowMs);
    this.sql.exec('DELETE FROM speed_run WHERE expires_at < ?', nowMs);
    this.sql.exec('DELETE FROM speed_admit WHERE ts < ?', nowMs - 60 * 60 * 1000);
    const yesterday = utcDay(nowMs - 24 * 60 * 60 * 1000);
    this.sql.exec('DELETE FROM speed_day WHERE day < ?', yesterday);
  }

  countRows() {
    return this.sql
      .exec(
        `SELECT (SELECT COUNT(*) FROM speed_run) +
                (SELECT COUNT(*) FROM speed_admit) +
                (SELECT COUNT(*) FROM speed_slot) AS total`
      )
      .one().total;
  }

  listTimestamps(kind, key, cutoffMs) {
    return this.sql
      .exec('SELECT ts FROM speed_admit WHERE kind = ? AND key = ? AND ts >= ? ORDER BY ts ASC', kind, key, cutoffMs)
      .toArray()
      .map(row => Number(row.ts));
  }

  admit(payload) {
    const policy = effectiveSpeedTestPolicy(this.env);
    const nowMs = Number(payload.now) || Date.now();
    this.purge(nowMs);

    const day = utcDay(nowMs);
    const dayRow = this.sql.exec('SELECT reserved FROM speed_day WHERE day = ?', day).toArray()[0];
    const reserved = dayRow ? Number(dayRow.reserved) : 0;
    const reservationBytes = policy.maxDownloadBytes + policy.maxUploadBytes;

    const visitorRuns = this.listTimestamps('visitor', payload.visitorHash, nowMs - 60 * 60 * 1000);
    const lastStart = visitorRuns.length > 0 ? visitorRuns[visitorRuns.length - 1] : 0;
    if (lastStart && nowMs - lastStart < policy.cooldownMs) {
      return {
        ok: false,
        status: 429,
        code: 'COOLDOWN',
        retryAfterSeconds: Math.max(1, Math.ceil((policy.cooldownMs - (nowMs - lastStart)) / 1000)),
      };
    }
    if (visitorRuns.length >= policy.runsPerVisitorPerHour) {
      return {
        ok: false,
        status: 429,
        code: 'VISITOR_LIMIT',
        retryAfterSeconds: Math.max(5, Math.ceil((visitorRuns[0] + 60 * 60 * 1000 - nowMs) / 1000)),
      };
    }
    const ipRuns = this.listTimestamps('ip', payload.ipHash, nowMs - 60 * 60 * 1000);
    if (ipRuns.length >= policy.runsPerIpPerHour) {
      return {
        ok: false,
        status: 429,
        code: 'IP_LIMIT',
        retryAfterSeconds: Math.max(5, Math.ceil((ipRuns[0] + 60 * 60 * 1000 - nowMs) / 1000)),
      };
    }
    if (reserved + reservationBytes > policy.dailySiteBudgetBytes) {
      const nextDayMs = Date.UTC(
        new Date(nowMs).getUTCFullYear(),
        new Date(nowMs).getUTCMonth(),
        new Date(nowMs).getUTCDate() + 1
      );
      return {
        ok: false,
        status: 429,
        code: 'DAILY_BUDGET',
        retryAfterSeconds: Math.max(60, Math.ceil((nextDayMs - nowMs) / 1000)),
      };
    }

    const runId = 'r_' + crypto.randomUUID().replaceAll('-', '');
    const expiresAtMs = nowMs + policy.tokenTtlMs + SPEED_RUN_GRACE_MS;
    this.sql.exec('INSERT INTO speed_admit (kind, key, ts) VALUES (?, ?, ?)', 'visitor', payload.visitorHash, nowMs);
    this.sql.exec('INSERT INTO speed_admit (kind, key, ts) VALUES (?, ?, ?)', 'ip', payload.ipHash, nowMs);
    this.sql.exec(
      'INSERT INTO speed_day (day, reserved) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET reserved = reserved + excluded.reserved',
      day,
      reservationBytes
    );
    this.sql.exec(
      'INSERT INTO speed_run (run_id, downloaded, uploaded, requests, expires_at, completed) VALUES (?, 0, 0, 0, ?, 0)',
      runId,
      expiresAtMs
    );
    this.ctx.storage.setAlarm(nowMs + SPEED_STORE_ALARM_MS);
    return { ok: true, runId, expiresAtMs, reservedTodayBytes: reserved + reservationBytes };
  }

  reserve(payload) {
    const policy = effectiveSpeedTestPolicy(this.env);
    const nowMs = Number(payload.now) || Date.now();
    this.purge(nowMs);

    const run = this.sql.exec('SELECT * FROM speed_run WHERE run_id = ?', payload.runId).toArray()[0];
    if (!run) {
      return { ok: false, status: 403, code: 'RUN_UNKNOWN', retryAfterSeconds: 60 };
    }
    if (Number(run.completed) !== 0) {
      return { ok: false, status: 409, code: 'RUN_COMPLETED', retryAfterSeconds: 60 };
    }

    const requests = Number(run.requests) + 1;
    this.sql.exec('UPDATE speed_run SET requests = ? WHERE run_id = ?', requests, payload.runId);
    if (requests > policy.maxRequestsPerRun) {
      return { ok: false, status: 429, code: 'RUN_REQUEST_LIMIT', retryAfterSeconds: 60 };
    }

    const activeSlots = Number(
      this.sql
        .exec('SELECT COUNT(*) AS count FROM speed_slot WHERE run_id = ?', payload.runId)
        .one().count
    );
    if (activeSlots >= policy.concurrentStreams) {
      return { ok: false, status: 429, code: 'CONCURRENT_STREAMS', retryAfterSeconds: 1 };
    }

    const download = payload.phase === 'download';
    const used = Number(download ? run.downloaded : run.uploaded);
    const budget = download ? policy.maxDownloadBytes : policy.maxUploadBytes;
    const remaining = budget - used;
    if (remaining <= 0) {
      return { ok: false, status: 429, code: 'BUDGET_EXHAUSTED', retryAfterSeconds: 60 };
    }
    const granted = Math.max(
      0,
      Math.min(Math.floor(Number(payload.want) || 0), policy.maxRequestBytes, remaining)
    );
    if (granted <= 0) {
      return { ok: false, status: 429, code: 'BUDGET_EXHAUSTED', retryAfterSeconds: 60 };
    }

    if (download) {
      this.sql.exec('UPDATE speed_run SET downloaded = ? WHERE run_id = ?', used + granted, payload.runId);
    } else {
      this.sql.exec('UPDATE speed_run SET uploaded = ? WHERE run_id = ?', used + granted, payload.runId);
    }
    this.sql.exec(
      'INSERT OR REPLACE INTO speed_slot (slot_id, run_id, phase, expires_at) VALUES (?, ?, ?, ?)',
      String(payload.slotId),
      payload.runId,
      download ? 'download' : 'upload',
      nowMs + SPEED_SLOT_LEASE_MS
    );
    return { ok: true, bytes: granted };
  }

  release(payload) {
    this.sql.exec('DELETE FROM speed_slot WHERE slot_id = ?', String(payload.slotId));
    const unused = Math.floor(Number(payload.unusedBytes) || 0);
    if (payload.phase === 'upload' && unused > 0) {
      // Return the difference between the reserved allowance and the bytes actually received.
      // Served bytes are never refunded, so replaying requests cannot regain budget.
      this.sql.exec(
        'UPDATE speed_run SET uploaded = MAX(0, uploaded - ?) WHERE run_id = ?',
        Math.min(unused, this.sql.exec('SELECT uploaded FROM speed_run WHERE run_id = ?', payload.runId).toArray()[0]?.uploaded ?? 0),
        payload.runId
      );
    }
    return { ok: true };
  }

  complete(payload) {
    this.sql.exec('UPDATE speed_run SET completed = 1 WHERE run_id = ?', payload.runId);
    this.sql.exec('DELETE FROM speed_slot WHERE run_id = ?', payload.runId);
    return { ok: true };
  }

  stats() {
    const day = utcDay(Date.now());
    const row = this.sql.exec('SELECT reserved FROM speed_day WHERE day = ?', day).toArray()[0];
    return {
      ok: true,
      day,
      reservedTodayBytes: row ? Number(row.reserved) : 0,
      runs: Number(this.sql.exec('SELECT COUNT(*) AS count FROM speed_run').one().count),
      slots: Number(this.sql.exec('SELECT COUNT(*) AS count FROM speed_slot').one().count),
      admissions: Number(this.sql.exec('SELECT COUNT(*) AS count FROM speed_admit').one().count),
    };
  }

  async fetch(request) {
    const url = new URL(request.url);
    let payload = {};
    if (request.method === 'POST') {
      payload = await request.json().catch(() => ({}));
    }
    switch (url.pathname) {
      case '/admit':
        return Response.json(this.admit(payload));
      case '/reserve':
        return Response.json(this.reserve(payload));
      case '/release':
        return Response.json(this.release(payload));
      case '/complete':
        return Response.json(this.complete(payload));
      case '/stats':
        return Response.json(this.stats());
      default:
        return Response.json({ ok: false, error: 'Unknown control-plane operation.' }, { status: 404 });
    }
  }

  async alarm() {
    const nowMs = Date.now();
    this.purge(nowMs);
    if (this.countRows() > 0) this.ctx.storage.setAlarm(nowMs + SPEED_STORE_ALARM_MS);
  }
}

async function handleSpeedTest(request, env, ctx, pathname) {
  const url = new URL(request.url);
  const policy = effectiveSpeedTestPolicy(env);
  const nowMs = Date.now();

  if (speedTestDisabled(env)) {
    return speedRejection(503, 'SPEED_TEST_DISABLED', 3600, 'Speed testing is temporarily disabled by the operator.');
  }

  const forwarded = stripInternalHeaders(request);

  try {
    if (pathname === '/api/network/speed-test/init') {
      const admission = await callStore(env, '/admit', {
        visitorHash: hashQuotaKey(visitorKey(request), env.VISITOR_HMAC_SECRET),
        ipHash: hashQuotaKey(clientIp(request) || 'unknown', env.VISITOR_HMAC_SECRET),
        now: nowMs,
      });
      if (!admission.ok) {
        return speedRejection(
          admission.status || 429,
          admission.code || 'ADMISSION_REJECTED',
          admission.retryAfterSeconds || 60
        );
      }
      forwarded.headers.set(
        'x-intel-speed-admission',
        signSpeedAdmission(admission.runId, nowMs + 60 * 1000, env.VISITOR_HMAC_SECRET)
      );
      return handleAsNodeRequest(API_PORT, forwarded);
    }

    if (pathname === '/api/network/speed-test/complete') {
      let token = tokenFromRequest(request, url);
      let forwardedRequest = forwarded;
      if (!token) {
        // The client posts the token in the JSON body; read it once and replay the same bytes.
        // Bound the read so a hostile body cannot be buffered into Worker memory.
        const declaredLength = Number(request.headers.get('Content-Length') || '0');
        if (!Number.isFinite(declaredLength) || declaredLength <= 8192) {
          const rawBody = await forwarded.text();
          try {
            const parsed = JSON.parse(rawBody);
            if (typeof parsed?.token === 'string') token = parsed.token;
          } catch {}
          forwardedRequest = new Request(forwarded.url, {
            method: 'POST',
            headers: forwarded.headers,
            body: rawBody,
          });
        }
      }
      const verified = verifySpeedTestToken(token);
      if (verified.valid && verified.fresh && verified.runId) {
        // Best effort: server-side token expiry is the authoritative fallback.
        await callStore(env, '/complete', { runId: verified.runId, now: nowMs }).catch(() => {});
      }
      return handleAsNodeRequest(API_PORT, forwardedRequest);
    }

    const token = tokenFromRequest(request, url);
    const verified = verifySpeedTestToken(token);
    if (!verified.valid || !verified.fresh || !verified.runId) {
      return speedRejection(403, 'UNAUTHORIZED', 60, 'Missing, invalid or expired speed-test token.');
    }

    if (pathname === '/api/network/upload') {
      const contentType = (request.headers.get('Content-Type') || '').toLowerCase();
      if (!contentType.startsWith('application/octet-stream')) {
        return speedRejection(415, 'UNSUPPORTED_MEDIA_TYPE', 60, 'Uploads must be application/octet-stream.');
      }
      const slotId = crypto.randomUUID();
      const reservation = await callStore(env, '/reserve', {
        runId: verified.runId,
        phase: 'upload',
        want: policy.maxRequestBytes,
        slotId,
        now: nowMs,
      });
      if (!reservation.ok) {
        return speedRejection(
          reservation.status || 429,
          reservation.code || 'RESERVATION_REJECTED',
          reservation.retryAfterSeconds || 60
        );
      }
      forwarded.headers.set(
        'x-intel-speed-grant',
        signSpeedTransferGrant(token, {
          runId: verified.runId,
          phase: 'upload',
          bytes: reservation.bytes,
          expiresAtMs: nowMs + 60 * 1000,
        })
      );
      const response = await handleAsNodeRequest(API_PORT, forwarded);
      let receivedBytes = 0;
      try {
        const reported = await response.clone().json();
        if (Number.isFinite(Number(reported.receivedBytes))) receivedBytes = Number(reported.receivedBytes);
      } catch {
        receivedBytes = 0;
      }
      await releaseStore(env, {
        runId: verified.runId,
        phase: 'upload',
        slotId,
        unusedBytes: Math.max(0, reservation.bytes - receivedBytes),
      });
      return response;
    }

    // Download
    const slotId = crypto.randomUUID();
    const reservation = await callStore(env, '/reserve', {
      runId: verified.runId,
      phase: 'download',
      want: requestedChunkBytes(request, url, policy),
      slotId,
      now: nowMs,
    });
    if (!reservation.ok) {
      return speedRejection(
        reservation.status || 429,
        reservation.code || 'RESERVATION_REJECTED',
        reservation.retryAfterSeconds || 60
      );
    }
    forwarded.headers.set(
      'x-intel-speed-grant',
      signSpeedTransferGrant(token, {
        runId: verified.runId,
        phase: 'download',
        bytes: reservation.bytes,
        expiresAtMs: nowMs + 60 * 1000,
      })
    );
    const response = await handleAsNodeRequest(API_PORT, forwarded);
    if (!response.body) {
      ctx.waitUntil(releaseStore(env, { runId: verified.runId, phase: 'download', slotId }));
      return response;
    }
    const { readable, writable } = new TransformStream();
    const release = releaseStore(env, { runId: verified.runId, phase: 'download', slotId });
    ctx.waitUntil(response.body.pipeTo(writable).then(() => release, () => release));
    return new Response(readable, response);
  } catch (error) {
    console.error('Speed-test control-plane failure:', error instanceof Error ? error.message : error);
    // Fail closed for expensive transfer endpoints when durable coordination is unavailable.
    if (pathname === '/api/network/speed-test/complete') {
      return handleAsNodeRequest(API_PORT, forwarded);
    }
    return speedRejection(503, 'CONTROL_PLANE_UNAVAILABLE', 60, 'Speed testing is temporarily unavailable.');
  }
}

export class VisitorStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    this.database = {
      exec(query) { sql.exec(query).toArray(); },
      prepare(query) {
        return {
          get: (...values) => sql.exec(query, ...values).toArray()[0],
          all: (...values) => sql.exec(query, ...values).toArray(),
          run: (...values) => {
            sql.exec(query, ...values).toArray();
            return { changes: Number(sql.exec('SELECT changes() AS count').one().count) };
          },
        };
      },
    };
    ctx.storage.transactionSync(() => initializeDatabaseSchema(this.database));
  }

  fetch(request) {
    return withDatabase(this.database, () => handleAsNodeRequest(API_PORT, request));
  }
}

export default {
  async fetch(request, env, ctx) {
    const { pathname } = new URL(request.url);
    if (pathname !== '/api' && !pathname.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }
    if (!env.VISITOR_HMAC_SECRET || env.VISITOR_HMAC_SECRET.length < 32) {
      return apiResponse(Response.json({ error: 'Configure VISITOR_HMAC_SECRET with at least 32 characters.' }, { status: 503 }));
    }
    try {
      const persistent = pathname === '/api/health' || pathname.startsWith('/api/visitor/');
      const speedTest =
        pathname === '/api/network/speed-test/init' ||
        pathname === '/api/network/speed-test/complete' ||
        pathname === '/api/network/download' ||
        pathname === '/api/network/upload';
      let response;
      if (persistent) {
        response = await env.VISITOR_STORE.get(env.VISITOR_STORE.idFromName('visitor-store-v1')).fetch(request);
      } else if (speedTest) {
        response = await handleSpeedTest(request, env, ctx, pathname);
      } else {
        response = await handleAsNodeRequest(API_PORT, request);
      }
      return apiResponse(response);
    } catch (error) {
      console.error('Worker API failure:', error);
      return apiResponse(Response.json({ error: 'Internal server error.' }, { status: 500 }));
    }
  },
};
