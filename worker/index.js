import { createServer } from 'node:http';
import { handleAsNodeRequest } from 'cloudflare:node';
import { DurableObject } from 'cloudflare:workers';
import app, { initializeDatabaseSchema, withDatabase } from '../server.ts';
import { findAgentByUa, displayFor, PILLS } from '../src/lib/agentRegistry.ts';

// Workers' node:http adapter uses this as a routing key, not a public TCP port.
const API_PORT = 3000;
createServer(app).listen(API_PORT);

/**
 * Canonical edge-geolocation header built from `request.cf`.
 *
 * The Worker is the only component that can see the real Cloudflare edge object, and it
 * is also the only trust boundary: `request.cf` cannot be set by a client. Everything is
 * encoded so the value stays inside the ASCII ByteString range that fetch() headers allow.
 */
const EDGE_GEO_HEADER = 'x-intel-edge-geo';

/**
 * Client-hint response headers. Kept byte-for-byte identical to the Express
 * constants in src/server/middleware/clientHints.ts so both targets advertise
 * exactly one set. Critical-CH is a subset of Accept-CH (RFC 9652).
 */
const CLIENT_HINT_ACCEPT_CH =
  'Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Form-Factors';
const CLIENT_HINT_CRITICAL_CH =
  'Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version';
const CLIENT_HINT_VARY = 'Sec-CH-UA*';

/** Headers a client could otherwise spoof to fake an IP or a location. */
const UNTRUSTED_FORWARD_HEADERS = [
  'x-intel-edge-geo',
  'x-vercel-forwarded-for',
  'x-vercel-proxied-for',
  'x-vercel-ip-country',
  'x-vercel-ip-country-code',
  'x-vercel-ip-city',
  'x-vercel-ip-country-region',
  'x-vercel-ip-latitude',
  'x-vercel-ip-longitude',
  'x-vercel-ip-timezone',
  'x-vercel-ip-as-number',
  'x-vercel-ip-postal-code',
  'x-vercel-ip-continent',
  'x-vercel-id',
  'true-client-ip',
  'x-real-ip',
  'x-client-ip',
  'x-appengine-user-ip',
];

/** Document headers that would pin a stale/cached copy of a UA-specific verdict. */
const STRIP_DOCUMENT_HEADERS = [
  'content-length',
  'etag',
  'digest',
  'content-digest',
  'repr-digest',
];

function cfString(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : '';
}

function buildEdgeGeoHeader(request) {
  const cf = request.cf || {};
  const payload = {
    v: 1,
    country: cfString(cf.country),
    region: cfString(cf.region),
    regionCode: cfString(cf.regionCode),
    city: cfString(cf.city),
    latitude: cfString(cf.latitude),
    longitude: cfString(cf.longitude),
    timezone: cfString(cf.timezone),
    asn: typeof cf.asn === 'number' && Number.isFinite(cf.asn) ? String(cf.asn) : cfString(cf.asn),
    organization: cfString(cf.asOrganization),
    postalCode: cfString(cf.postalCode),
    continent: cfString(cf.continent),
    colo: cfString(cf.colo),
    // All-plan request.cf transport fields. JA3 / JA4T and raw TCP-SYN OS fingerprints are
    // Bot-Management-only and deliberately omitted — the server reports them as "Unavailable".
    tlsVersion: cfString(cf.tlsVersion),
    tlsCipher: cfString(cf.tlsCipher),
    clientTcpRtt:
      typeof cf.clientTcpRtt === 'number' && Number.isFinite(cf.clientTcpRtt)
        ? cf.clientTcpRtt
        : null,
    httpProtocol: cfString(cf.httpProtocol),
  };
  return encodeURIComponent(JSON.stringify(payload));
}

/**
 * Forwards the request to the API with a sanitized header set.
 *
 * Cloudflare overwrites `cf-connecting-ip`, so that value is the only trustworthy client
 * address. Any inbound geo/IP header is deleted and replaced, which closes the spoofing
 * path where a client could send `x-vercel-ip-country` through Cloudflare untouched.
 */
function forwardApiRequest(request) {
  const headers = new Headers(request.headers);
  for (const name of UNTRUSTED_FORWARD_HEADERS) headers.delete(name);

  const clientIp = request.headers.get('cf-connecting-ip') || '';
  if (clientIp) {
    headers.set('cf-connecting-ip', clientIp);
    headers.set('x-forwarded-for', clientIp);
  }
  headers.set(EDGE_GEO_HEADER, buildEdgeGeoHeader(request));

  return new Request(request, { headers });
}

/**
 * The single place that applies the client-hint / hardening response headers. Called
 * exactly once per response: API responses go through `apiResponse`, documents and
 * immutable assets through `applyClientHintHeaders` directly.
 */
function applyClientHintHeaders(response) {
  const result = new Response(response.body, response);
  result.headers.set('Accept-CH', CLIENT_HINT_ACCEPT_CH);
  result.headers.set('Critical-CH', CLIENT_HINT_CRITICAL_CH);
  result.headers.set('Vary', CLIENT_HINT_VARY);
  result.headers.set(
    'Permissions-Policy',
    'compute-pressure=*, ch-ua-model=(self), ch-ua-platform-version=(self), ch-ua-arch=(self), ch-ua-form-factors=(self)'
  );
  result.headers.set('X-Content-Type-Options', 'nosniff');
  return result;
}

function apiResponse(response) {
  const result = applyClientHintHeaders(response);
  result.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, no-transform');
  return result;
}

/* -------------------------------------------------------------------------- */
/* Edge bot verdict                                                            */
/* -------------------------------------------------------------------------- */

function recordOf(value) {
  return value && typeof value === 'object' ? value : {};
}

function firstString(record, ...keys) {
  for (const key of keys) {
    const candidate = record[key];
    if (typeof candidate === 'string' && candidate.trim()) return candidate.trim();
  }
  return '';
}

/** Resolves the exact pill label for an agent from the shared registry's PILLS table. */
function pillLabelFor(agent) {
  const id = firstString(agent, 'id', 'agentId', 'key', 'slug', 'name').toLowerCase();
  const name = firstString(agent, 'name', 'label', 'title').toLowerCase();
  if (!PILLS) return '';
  try {
    if (PILLS instanceof Map) {
      return String(PILLS.get(id) || PILLS.get(name) || '');
    }
    if (Array.isArray(PILLS)) {
      const found = PILLS.find((entry) => {
        const row = recordOf(entry);
        return [row.id, row.agentId, row.key, row.name, row.label].some(
          (value) => typeof value === 'string' && [id, name].includes(value.toLowerCase())
        );
      });
      if (found) {
        const row = recordOf(found);
        return firstString(row, 'label', 'pill', 'name');
      }
      return '';
    }
    const direct = PILLS[id] ?? PILLS[name];
    if (typeof direct === 'string') return direct;
    return firstString(recordOf(direct), 'label', 'pill', 'name');
  } catch {
    return '';
  }
}

/** RFC 9421 / Web Bot Auth header pair — the signal that an agent is genuinely signed. */
function hasSignedAgentHeaders(request) {
  return Boolean(
    request.headers.get('signature-agent') &&
      request.headers.get('signature-input') &&
      request.headers.get('signature')
  );
}

/**
 * Deterministically composes the name shown everywhere for a named agent. `displayFor`
 * from the registry is the primary source; when it returns an object without a composed
 * label we compose `Identity · Pill · Provider` ourselves so every surface agrees.
 */
function verdictName(display, agent, identity, pill) {
  if (typeof display === 'string' && display.trim()) return display.trim();
  if (display && typeof display === 'object') {
    const candidates = ['name', 'label', 'display', 'displayName', 'fullName', 'verdict', 'title'];
    const composed = candidates
      .map((key) => display[key])
      .find((value) => typeof value === 'string' && value.includes('·'));
    if (typeof composed === 'string' && composed.trim()) return composed.trim();
  }
  const caption =
    identity === 'verified'
      ? 'Verified'
      : identity === 'signed'
      ? 'Signed'
      : identity === 'spoofed'
      ? 'Spoofed'
      : 'Detected';
  const label = pill || firstString(agent, 'name', 'label', 'title');
  const provider = firstString(agent, 'provider', 'operator', 'organization', 'vendor', 'company');
  return [caption, label, provider].filter(Boolean).join(' · ');
}

/** Mirrors the registry's proof-tier → identity mapping so the badge matches its display. */
function identityFromAgent(info) {
  switch (info.minProofForVerified) {
    case 'cidr':
    case 'fcrdns':
    case 'allowlist':
      return 'verified';
    case 'rfc9421':
    case 'signed_agent':
      return 'signed';
    default:
      return 'unknown';
  }
}

/** The one edge verdict producer, fed by the raw UA plus optional Cloudflare Bot Management. */
function computeEdgeVerdict(request) {
  const rawUa = request.headers.get('user-agent') || '';
  let agent = null;
  try {
    agent = findAgentByUa(rawUa) || null;
  } catch {
    agent = null;
  }
  const info = recordOf(agent);

  // Optional chaining: deployments without Bot Management still get a verdict from UA alone.
  const botManagement = request.cf?.botManagement;
  const verifiedBot = Boolean(botManagement?.verifiedBot);
  const signedAgent = Boolean(agent) && hasSignedAgentHeaders(request);

  // The registry's proof tier supplies the registry-consistent badge (Verified/Signed);
  // a real Cloudflare Bot Management / Web Bot Auth signal can only strengthen it.
  let identity = identityFromAgent(info);
  if (verifiedBot) identity = 'verified';
  else if (signedAgent) identity = 'signed';

  let display = null;
  try {
    display = agent ? displayFor(agent, identity) : null;
  } catch {
    display = null;
  }

  const pill = pillLabelFor(info);
  return {
    agent,
    name: display ? verdictName(display, info, identity, pill) : '',
    provider: firstString(info, 'provider', 'operator', 'organization', 'vendor', 'company') || null,
    botType: firstString(info, 'id', 'agentId', 'key', 'slug', 'type', 'name') || null,
    identity,
    os: edgeOsLabel(request),
    verifiedBot,
    signedAgent,
  };
}

/**
 * Edge-visible OS hint. UA-CH is preferred over the (spoofable) UA string, and no
 * "(verified)" suffix is ever emitted: the Worker has no runtime hardware proof. The client
 * replaces this value with the runtime probe's OS when that proof is available.
 */
function edgeOsLabel(request) {
  const hint = request.headers.get('sec-ch-ua-platform') || '';
  const families = [
    [/linux/i, 'Linux'],
    [/macos|mac os|darwin|macintosh/i, 'macOS'],
    [/windows|win32/i, 'Windows'],
  ];
  for (const [pattern, label] of families) {
    if (pattern.test(hint)) return label;
  }
  const ua = request.headers.get('user-agent') || '';
  for (const [pattern, label] of families) {
    if (pattern.test(ua)) return label;
  }
  return null;
}

function botVerdictHeaders(verdict) {
  return {
    'X-Intel-Bot-Verdict': verdict.name || 'not_detected',
    'X-Intel-Bot-Agent': verdict.botType || 'none',
    'X-Intel-Bot-Identity': verdict.identity || 'unknown',
  };
}

function redirectWithVerdict(location) {
  // Response.redirect() produces immutable headers on some runtimes, so build a fresh
  // response and set both Location and the bot-verdict marker ourselves.
  return new Response(null, {
    status: 301,
    headers: { Location: location, 'X-Intel-Bot-Verdict': 'redirect' },
  });
}

function escapeHtmlAttribute(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function jsonForInlineScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * Document branch. Always requests /index.html explicitly (never the SPA fallback shell),
 * injects the edge verdict into <head>/<body>, brands the response with bot headers and
 * removes cache validators so the UA-specific HTML can never be served from a shared cache.
 */
async function handleDocument(request, env, verdict) {
  // Fetch the ORIGINAL path. With `not_found_handling: single-page-application`, the asset
  // layer serves index.html for any document path. Requesting `/index.html` explicitly makes
  // Wrangler's SPA canonicalisation 307 back to `/`, which loops when the Worker runs first.
  const asset = await env.ASSETS.fetch(request);

  const alreadyInjected = Boolean(asset.headers.get('x-intel-bot-verdict'));
  const compressed = Boolean(asset.headers.get('content-encoding'));
  let response;

  if (alreadyInjected || compressed) {
    // Compressed bytes cannot be rewritten safely; a pre-branded document needs no rewrite.
    response = new Response(asset.body, asset);
  } else {
    let metaInjected = false;
    let scriptInjected = false;
    const rewriter = new HTMLRewriter()
      .on('head', {
        element(element) {
          if (metaInjected) return;
          element.append(
            `<meta name="intel:verdict" content="${escapeHtmlAttribute(verdict.name)}">` +
              `<meta name="intel:bot-type" content="${escapeHtmlAttribute(verdict.botType || 'none')}">`,
            { html: true }
          );
          metaInjected = true;
        },
      })
      .on('body', {
        element(element) {
          if (scriptInjected) return;
          const payload = jsonForInlineScript({
            name: verdict.name || null,
            provider: verdict.provider,
            botType: verdict.botType,
            identity: verdict.identity,
            os: verdict.os,
          });
          element.append(
            `<script id="intel-initial-verdict" type="application/json">${payload}</script>`,
            { html: true }
          );
          scriptInjected = true;
        },
      });
    response = rewriter.transform(asset);
  }

  const result = applyClientHintHeaders(response);
  for (const [name, value] of Object.entries(botVerdictHeaders(verdict))) {
    result.headers.set(name, value);
  }
  for (const name of STRIP_DOCUMENT_HEADERS) result.headers.delete(name);
  result.headers.set('Cache-Control', 'private, no-store, max-age=0');
  return result;
}

/** API branch. Only here do we call apiResponse() or touch the ratelimit binding. */
async function handleApi(request, env, pathname, verdict) {
  // Optional edge rate limiting for identity writes. The Cloudflare ratelimit binding is
  // optional: deployments without it simply skip limiting instead of failing the request.
  // Verified / signed agents are exempt — they carry cryptographic or Bot Management proof
  // and must never be throttled by the anonymous-write limiter.
  if (
    env.IDENTIFY_RATE_LIMIT &&
    request.method === 'POST' &&
    pathname.startsWith('/api/visitor/') &&
    !verdict.verifiedBot &&
    !verdict.signedAgent
  ) {
    const key = request.headers.get('cf-connecting-ip') || 'unknown';
    try {
      const limitVerdict = await env.IDENTIFY_RATE_LIMIT.limit({ key });
      if (!limitVerdict.success) {
        const resetMs =
          typeof limitVerdict.reset === 'number' ? limitVerdict.reset : Date.now() + 60_000;
        const retryAfter = Math.max(0, Math.ceil((resetMs - Date.now()) / 1000));
        return apiResponse(
          Response.json(
            { error: 'Too many identification requests. Please retry later.' },
            { status: 429, headers: { 'Retry-After': String(retryAfter) } }
          )
        );
      }
    } catch (error) {
      // A limiter outage must never take the identification path down; fail open.
      console.error('IDENTIFY_RATE_LIMIT failure:', error);
    }
  }

  if (!env.VISITOR_HMAC_SECRET || env.VISITOR_HMAC_SECRET.length < 32) {
    return apiResponse(Response.json({ error: 'Configure VISITOR_HMAC_SECRET with at least 32 characters.' }, { status: 503 }));
  }
  try {
    const forwardedRequest = forwardApiRequest(request);
    // Visitor routes need request-scoped Durable-Object SQLite access; every other API
    // route runs statelessly so it cannot consume the daily row-write quota.
    const persistent =
      pathname.startsWith('/api/visitor/') ||
      pathname === '/api/intel/geolocation';
    const response = persistent
      ? await env.VISITOR_STORE.get(env.VISITOR_STORE.idFromName('visitor-store-v1')).fetch(forwardedRequest)
      : await handleAsNodeRequest(API_PORT, forwardedRequest);
    return apiResponse(response);
  } catch (error) {
    console.error('Worker API failure:', error);
    return apiResponse(Response.json({ error: 'Internal server error.' }, { status: 500 }));
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
    this.schemaReady = false;
    this.schemaAttemptedAtMs = 0;
    // blockConcurrencyWhile-style init: schema DDL plus the migration marker finish before any
    // fetch is delivered. No alarms / crons are used — this is the only bootstrap path.
    ctx.blockConcurrencyWhile(async () => {
      this.ensureSchema(true);
      if (this.schemaReady) {
        try {
          this.database
            .prepare('INSERT OR IGNORE INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)')
            .run('v4-canonical-identity', new Date().toISOString());
        } catch (error) {
          console.error('VisitorStore migration marker deferred:', error);
        }
      }
    });
  }

  /**
   * Schema bootstrap is idempotent DDL, but DDL still counts as a write once the daily
   * `rows_written` budget is exhausted. If it fails, the object must keep serving: the
   * tables already exist from earlier deployments, reads still work, and every write path
   * in the API degrades gracefully instead of taking the whole site down.
   */
  ensureSchema(force = false) {
    if (this.schemaReady) return;
    const now = Date.now();
    if (!force && now - this.schemaAttemptedAtMs < 5 * 60 * 1000) return;
    this.schemaAttemptedAtMs = now;
    try {
      this.ctx.storage.transactionSync(() => initializeDatabaseSchema(this.database));
      this.schemaReady = true;
    } catch (error) {
      console.error('VisitorStore schema init deferred:', error);
    }
  }

  fetch(request) {
    this.ensureSchema();
    return withDatabase(this.database, () => handleAsNodeRequest(API_PORT, request));
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    // Canonicalize the apex before any asset or API handling: `www` is 301'd to the single
    // HTTPS host and plaintext HTTP is upgraded in place, preserving path + query string.
    // Loopback is exempt so local `wrangler dev` / test-worker HTTP requests keep working.
    if (url.hostname === 'www.intel.adityahq.me') {
      return redirectWithVerdict(
        new URL(url.pathname + url.search, 'https://intel.adityahq.me').toString()
      );
    }
    const isLoopback =
      /^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i.test(url.hostname);
    if (url.protocol === 'http:' && !isLoopback) {
      return redirectWithVerdict(
        new URL(url.pathname + url.search, `https://${url.host}`).toString()
      );
    }

    const verdict = computeEdgeVerdict(request);

    // API branch — the only path that uses apiResponse() / the ratelimit binding.
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      return handleApi(request, env, pathname, verdict);
    }

    // Immutable hashed assets: pass through untouched — never rewritten and never branded
    // with a per-visitor bot verdict. (run_worker_first excludes /assets/* in production.)
    if (pathname.startsWith('/assets/')) {
      return applyClientHintHeaders(await env.ASSETS.fetch(request));
    }

    // Document branch — every page navigation / SPA deep link.
    return handleDocument(request, env, verdict);
  },
};
