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
  result.headers.set(
    'Accept-CH',
    'Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Form-Factors, Sec-CH-UA-Full-Version-List'
  );
  result.headers.set(
    'Critical-CH',
    'Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List'
  );
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
    this.ensureSchema();
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
    const { pathname } = new URL(request.url);
    if (pathname !== '/api' && !pathname.startsWith('/api/')) {
      const asset = await env.ASSETS.fetch(request);
      const result = new Response(asset.body, asset);
      result.headers.set(
        'Accept-CH',
        'Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Form-Factors, Sec-CH-UA-Full-Version-List'
      );
      result.headers.set(
        'Critical-CH',
        'Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List'
      );
      result.headers.set(
        'Permissions-Policy',
        'compute-pressure=*, ch-ua-model=(self), ch-ua-platform-version=(self), ch-ua-arch=(self), ch-ua-form-factors=(self)'
      );
      return result;
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
