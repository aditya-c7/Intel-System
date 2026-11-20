import { createServer } from 'node:http';
import { handleAsNodeRequest } from 'cloudflare:node';
import { DurableObject } from 'cloudflare:workers';
import app, { initializeDatabaseSchema, withDatabase } from '../server.ts';

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

function apiResponse(response) {
  const result = new Response(response.body, response);
  result.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, no-transform');
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
      const canonical = new URL(url.pathname + url.search, 'https://intel.adityahq.me');
      return Response.redirect(canonical.toString(), 301);
    }
    const isLoopback =
      /^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i.test(url.hostname);
    if (url.protocol === 'http:' && !isLoopback) {
      const secure = new URL(url.pathname + url.search, `https://${url.host}`);
      return Response.redirect(secure.toString(), 301);
    }

    if (pathname !== '/api' && !pathname.startsWith('/api/')) {
      const asset = await env.ASSETS.fetch(request);
      const result = new Response(asset.body, asset);
      result.headers.set('Accept-CH', CLIENT_HINT_ACCEPT_CH);
      result.headers.set('Critical-CH', CLIENT_HINT_CRITICAL_CH);
      result.headers.set('Vary', CLIENT_HINT_VARY);
      result.headers.set(
        'Permissions-Policy',
        'compute-pressure=*, ch-ua-model=(self), ch-ua-platform-version=(self), ch-ua-arch=(self), ch-ua-form-factors=(self)'
      );
      return result;
    }

    // Optional edge rate limiting for identity writes. The Cloudflare ratelimit binding is
    // optional: deployments without it simply skip limiting instead of failing the request.
    if (
      env.IDENTIFY_RATE_LIMIT &&
      request.method === 'POST' &&
      pathname.startsWith('/api/visitor/')
    ) {
      const key = request.headers.get('cf-connecting-ip') || 'unknown';
      try {
        const verdict = await env.IDENTIFY_RATE_LIMIT.limit({ key });
        if (!verdict.success) {
          const resetMs = typeof verdict.reset === 'number' ? verdict.reset : Date.now() + 60_000;
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
  },
};
