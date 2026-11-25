import { createServer } from 'node:http';
import { handleAsNodeRequest } from 'cloudflare:node';
import { DurableObject } from 'cloudflare:workers';
import app, { initializeDatabaseSchema, withDatabase } from '../server.ts';
import { findAgentByUa, displayFor, PILLS, AGENT_BY_ID } from '../src/lib/agentRegistry.ts';
import { verifyWebBotAuth, WBA_TRUSTED_SIGNERS } from '../src/lib/wbaVerifier.ts';
// Additive, flag-gated diagnostics ONLY. These two imports are pure helpers: the signature
// parser never fetches a key and the feed helper is a UA prefilter, never a verdict.
import { parseSignatureHeaders } from '../src/lib/webBotAuth.ts';
import { uaPrefilter } from '../src/lib/officialBotFeeds.ts';

// Workers' node:http adapter uses this as a routing key, not a public TCP port.
const API_PORT = 3000;
createServer(app).listen(API_PORT);

/**
 * Canonical edge-geolocation header built from `request.cf`.
 *
 * The Worker is the only component that can see the real Cloudflare edge object, and it
 * is also the only trust boundary: `request.cf` cannot be set by a client. Everything is
 * encoded so the value stays inside the ASCII ByteString range that fetch() headers allow.
 *
 * R3: it also carries a single transport-normalized client RTT (rtt_transport / rtt_source /
 * status, in milliseconds). That value comes ONLY from request.cf — never from a client
 * header and never from the Server-Timing `cfL4` response metric.
 */
const EDGE_GEO_HEADER = 'x-intel-edge-geo';

/** Additive, approximate JA4H-style HTTP fingerprint from the inbound request. */
const JA4H_HEADER = 'x-intel-ja4h';

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

/**
 * Version attribution. These three values are the edge's answer to "what code served this?"
 * and are stamped on every API response and SSR document as `x-intel-*` headers, plus exposed
 * in the native `/api/health` JSON. Defaults keep local/dev builds honest ("unknown" build SHA)
 * while a deployment can override each one with a Worker binding — no Node crypto or git
 * access at runtime, which keeps the health/ping routes stateless.
 */
const DEFAULT_PARSER_VERSION = '2.1.0';
const DEFAULT_WORKER_VERSION = '2.1.0';
const DEFAULT_BUILD_SHA = 'unknown';

/** Conservative hardening headers. Values are chosen so the existing React/Vite/Leaflet app
 * keeps working: inline scripts are needed for the theme bootstrap and the injected verdict,
 * the bunny.net stylesheet/fonts and HTTPS map tiles stay reachable, and same-origin framing
 * is allowed rather than denied. */
const SECURITY_HEADERS = {
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Frame-Options': 'SAMEORIGIN',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'self'",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.bunny.net",
    "font-src 'self' data: https://fonts.bunny.net",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' https:",
    "media-src 'self' blob:",
  ].join('; '),
};

/** Headers a client could otherwise spoof to fake an IP or a location. */
const UNTRUSTED_FORWARD_HEADERS = [
  'x-intel-edge-geo',
  JA4H_HEADER,
  'x-intel-original-ua',
  'x-intel-original-authority',
  'x-intel-original-signature-agent',
  'x-intel-original-signature-input',
  'x-intel-original-signature',
  'x-intel-wba-attestation',
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
  // The backend falls back to these when cf-connecting-ip is missing; only the Worker may
  // set them, and only from a validated public cf-connecting-ip (see forwardApiRequest).
  'x-forwarded-for',
  'forwarded',
  'x-appengine-user-ip',
  // R3 lookalikes for the sealed edge-transport headers. colo / protocol / client lat-lon /
  // normalized RTT come ONLY from request.cf via the worker-set x-intel-edge-geo header;
  // an inbound copy of any of these names is deleted before that header is stamped.
  'x-intel-edge-rtt',
  'x-intel-rtt',
  'x-intel-rtt-ms',
  'x-intel-rtt-transport',
  'x-intel-rtt-source',
  'x-intel-rtt-status',
  'x-intel-client-rtt',
  'x-intel-edge-transport',
  'x-intel-edge-protocol',
  'x-intel-edge-colo',
  'x-intel-client-latitude',
  'x-intel-client-longitude',
  'cf-client-rtt',
  'cf-rtt',
  'cf-request-rtt',
];

/** Document headers that would pin a stale/cached copy of a UA-specific verdict. */
const STRIP_DOCUMENT_HEADERS = [
  'content-length',
  'etag',
  'digest',
  'content-digest',
  'repr-digest',
];

/**
 * Files copied from `public/` into `dist/` by Vite. They must be served verbatim: no HTML
 * rewriting, no bot-meta injection, no X-Intel-Bot-* branding and no UA-specific
 * `Cache-Control: private/no-store`. Their own caching (as emitted by the asset layer) wins.
 */
const PASS_THROUGH_PATHS = new Set([
  '/robots.txt',
  '/llms.txt',
  '/agents.md',
  '/sitemap.xml',
]);

function cfString(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : '';
}

/**
 * Conservative public-IP check for the one address Cloudflare controls (`cf-connecting-ip`).
 * A private / reserved / malformed value must never become a forwardable client identity or a
 * shareable rate-limit bucket key. Both stacks are checked explicitly rather than trusting
 * a generic "looks like an IP" regex.
 */
function isPublicIpv4(value) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!match) return false;
  const parts = match.slice(1).map(Number);
  // Reject leading zeros (e.g. 010.0.0.1), which some parsers treat as octal.
  for (let i = 0; i < parts.length; i += 1) {
    if (parts[i] < 0 || parts[i] > 255 || String(parts[i]) !== match[i + 1]) return false;
  }
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // 100.64/10 CGNAT
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // 172.16/12
  if (a === 192 && b === 168) return false; // 192.168/16
  if (a === 192 && b === 0 && c === 0) return false; // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return false; // TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return false; // deprecated 6to4 relay
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
  return true;
}

/** Parses a global IPv6 literal into eight 16-bit groups, or null when reserved/malformed. */
function publicIpv6Groups(value) {
  if (typeof value !== 'string' || !/^[0-9a-fA-F:.]+$/.test(value) || value.includes('%')) return null;
  let text = value.trim();
  let v4Tail = null;
  if (text.includes('.')) {
    const lastColon = text.lastIndexOf(':');
    if (lastColon < 0) return null;
    const embedded = text.slice(lastColon + 1);
    if (!isPublicIpv4(embedded)) return null;
    const octets = embedded.split('.').map(Number);
    v4Tail = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
    text = text.slice(0, lastColon);
    // `::192.0.2.1` / `1:2::192.0.2.1` lose one colon when the IPv4 tail is split off.
    if (text.endsWith(':') && !text.includes('::')) text += ':';
  }
  let head = text;
  let tail = '';
  const compressed = text.includes('::');
  if (compressed) {
    if (text.indexOf('::') !== text.lastIndexOf('::')) return null;
    [head, tail] = text.split('::');
  }
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail ? tail.split(':') : [];
  const explicit = headGroups.length + tailGroups.length + (v4Tail ? 2 : 0);
  if (compressed ? explicit >= 8 : explicit !== 8) return null;
  const groups = [];
  for (const token of headGroups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null;
    groups.push(parseInt(token, 16));
  }
  if (compressed) {
    const missing = 8 - explicit;
    for (let i = 0; i < missing; i += 1) groups.push(0);
  }
  for (const token of tailGroups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null;
    groups.push(parseInt(token, 16));
  }
  if (v4Tail) groups.push(...v4Tail);
  const [g0, g1, g2, g3] = groups;
  if (groups.every((group) => group === 0)) return null; // :: and IPv4-compatible space
  if (g0 === 0) return null; // ::/8 (loopback, unspecified, mapped/compatible)
  if ((g0 & 0xe000) !== 0x2000) return null; // only 2000::/3 global unicast is public
  if (g0 === 0x2001 && g1 === 0x0db8) return null; // 2001:db8::/32 documentation
  if ((g0 & 0xfe00) === 0xfc00) return null; // fc00::/7 unique-local
  if ((g0 & 0xffc0) === 0xfe80) return null; // fe80::/10 link-local
  if ((g0 & 0xff00) === 0xff00) return null; // ff00::/8 multicast
  if (g0 === 0x2001 && g1 <= 0x01ff) return null; // 2001::/23 protocol assignments
  if (g0 === 0x0064 && g1 === 0xff9b) return null; // NAT64 well-known prefix
  if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return null; // 100::/64 discard-only
  return groups;
}

/** Returns the trimmed address only when it is a public routable IPv4 or IPv6 literal. */
function publicClientIp(value) {
  if (typeof value !== 'string') return '';
  const text = value.trim();
  if (!text) return '';
  return isPublicIpv4(text) || publicIpv6Groups(text) ? text : '';
}

/**
 * Resolves the three version-attribution values from optional Worker bindings, falling back to
 * the compiled defaults. Binding aliases are accepted so a deployment can wire whichever var
 * its build pipeline already emits without touching this file.
 */
function versionInfo(env) {
  const bag = env && typeof env === 'object' ? env : {};
  return {
    parserVersion: cfString(bag.INTEL_PARSER_VERSION) || DEFAULT_PARSER_VERSION,
    buildSha:
      cfString(bag.INTEL_BUILD_SHA) ||
      cfString(bag.BUILD_SHA) ||
      cfString(bag.GIT_COMMIT_SHA) ||
      cfString(bag.CF_BUILD_SHA) ||
      // WORKERS_CI_COMMIT_SHA is Cloudflare Workers CI's own default var. It is only read when
      // actually bound; an absent/empty value falls through to the honest 'unknown' default.
      cfString(bag.WORKERS_CI_COMMIT_SHA) ||
      DEFAULT_BUILD_SHA,
    workerVersion: cfString(bag.INTEL_WORKER_VERSION) || DEFAULT_WORKER_VERSION,
  };
}

/** The `x-intel-*` header triple; shared by API responses, SSR documents and native routes. */
function versionHeaders(env) {
  const { parserVersion, buildSha, workerVersion } = versionInfo(env);
  return {
    'x-intel-parser-version': parserVersion,
    'x-intel-build-sha': buildSha,
    'x-intel-worker-version': workerVersion,
  };
}

/**
 * p in the RTT → light-distance approximation. Typical networks fall between 1.5 and 2; the
 * conservative value 2 is used here. This is an ESTIMATE, never JA4L.
 */
const LIGHT_DISTANCE_PROPAGATION_FACTOR = 2;

function lightDistanceKm(rttMs) {
  if (typeof rttMs !== 'number' || !Number.isFinite(rttMs) || rttMs < 0) return null;
  const km = ((rttMs / 2) * 1000 * 0.206) / LIGHT_DISTANCE_PROPAGATION_FACTOR;
  return { rttMs, estimatedKm: Math.round(km) };
}

/** Plain-object mirror for request.cf object fields (`edgeL4` / `tlsClientAuth`). */
function cfObjectValue(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string' || typeof item === 'boolean' || item === null) result[key] = item;
    else if (typeof item === 'number' && Number.isFinite(item)) result[key] = item;
  }
  return result;
}

/** request.cf numeric fields arrive as either numbers or decimal strings depending on plan. */
function finiteNumeric(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

/** Mirrors networkTruth.ts hasQuicEdgeHint(): object own-properties (or 'quic'/'h3' string). */
function hasQuicEdgeHint(value) {
  try {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value).length > 0;
    }
    if (typeof value === 'string') return /quic|h3/i.test(value);
  } catch {
    return false;
  }
  return false;
}

/**
 * R3: the single transport-aware client RTT normalizer, aligned with the canonical
 * `src/lib/networkTruth.ts` `normalizeRtt()`. `request.cf` is the only source. The transport
 * is lowercase (`quic` / `tcp` / `unknown`); exactly one source is read, with NO cross-transport
 * fallback. 0 / negatives / NaN / absent => `no-data`; values outside 1-2000 ms => `invalid`
 * (always `rtt_ms: null`). Milliseconds only; the Server-Timing `cfL4` metric is never read.
 */
function normalizedRtt(cf, transport) {
  const rtt_transport = transport;
  const rtt_source =
    transport === 'quic' ? 'clientQuicRtt' : transport === 'tcp' ? 'clientTcpRtt' : null;
  const raw =
    rtt_source === 'clientQuicRtt'
      ? cf.clientQuicRtt
      : rtt_source === 'clientTcpRtt'
        ? cf.clientTcpRtt
        : null;
  const positive = typeof raw === 'number' && Number.isFinite(raw) && raw > 0 ? raw : null;
  const invalid = positive !== null && (positive < 1 || positive > 2000);
  const rtt_ms = invalid ? null : positive;
  return {
    label: invalid
      ? 'RTT outside 1-2000 ms sanity range'
      : positive === null
        ? transport === 'quic'
          ? 'QUIC RTT not available (0 is a placeholder, not a measurement)'
          : transport === 'tcp'
            ? 'TCP RTT not available'
            : 'RTT not available (transport unknown; no cross-transport fallback)'
        : 'edge-derived smoothed RTT (ms)',
    rtt_ms,
    rtt_transport,
    rtt_source,
    status: invalid ? 'invalid' : positive === null ? 'no-data' : 'measured',
  };
}

function buildEdgeGeoHeader(request) {
  const cf = request.cf || {};
  const botManagement = cf.botManagement;
  const httpProtocol = cfString(cf.httpProtocol);
  // Protocol is authoritative and lowercase: HTTP/3 / QUIC / h3 select `quic`, explicit
  // HTTP/1 or HTTP/2 select `tcp`. `edgeL4` is only a fallback hint when the protocol is absent
  // — it never overrides an explicit TCP protocol. This is a request.cf transport hint ONLY:
  // the Server-Timing `cfL4` response metric is never read.
  const isQuicProtocol = /http\/3|quic|h3/i.test(httpProtocol);
  const isTcpProtocol = /http\/(1|2)/i.test(httpProtocol);
  const rawEdgeL4 =
    cf.edgeL4 && typeof cf.edgeL4 === 'object' && !Array.isArray(cf.edgeL4) ? cf.edgeL4 : null;
  const edgeL4 = cfObjectValue(rawEdgeL4);
  const transport = isQuicProtocol
    ? 'quic'
    : isTcpProtocol
      ? 'tcp'
      : hasQuicEdgeHint(cf.edgeL4)
        ? 'quic'
        : 'unknown';
  const isQuic = transport === 'quic';
  // R3: one transport-normalized RTT from request.cf, with NO cross-transport fallback.
  const rtt = normalizedRtt(cf, transport);
  // Raw per-transport observations are normalized too (0 => null) so no placeholder can
  // become a fabricated 0 ms "measurement" downstream.
  const observedTcpRtt =
    typeof cf.clientTcpRtt === 'number' && Number.isFinite(cf.clientTcpRtt) && cf.clientTcpRtt > 0
      ? cf.clientTcpRtt
      : null;
  const observedQuicRtt =
    typeof cf.clientQuicRtt === 'number' && Number.isFinite(cf.clientQuicRtt) && cf.clientQuicRtt > 0
      ? cf.clientQuicRtt
      : null;
  // Legacy field kept for the server's existing readEdgeTransport() contract. It is the TCP
  // observation only — the normalized cross-transport RTT is `rtt` / `clientRttMs` below.
  const clientTcpRtt = observedTcpRtt;
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
    clientTcpRtt,
    clientTcpRttLabel: isQuic
      ? 'not applicable on QUIC/HTTP/3 (normalized RTT uses clientQuicRtt; 0 is a placeholder)'
      : 'edge-observed TCP round-trip time (milliseconds; 0 => no data)',
    httpProtocol,
    // R3 normalized RTT. Sealed inside x-intel-edge-geo; every client-supplied lookalike is
    // stripped before this header is stamped (see UNTRUSTED_FORWARD_HEADERS). Milliseconds
    // only; 0 => 'no-data', out-of-range => 'invalid' (both rtt_ms null), never from `cfL4`.
    rtt,
    // Flat aliases for the server's sealed-header reader, carrying the same normalized value.
    clientRttMs: rtt.rtt_ms,
    rttTransport: rtt.rtt_transport,
    rttSource: rtt.rtt_source,
    rttStatus: rtt.status,
    // Bot-Management-only hash fields (Enterprise plans). Null-guarded and isolated in a
    // distinctly named field so the free-plan TLS-lite components below are NEVER reported
    // as JA3 / JA4. Absent on free plans: "out of list" means unavailable, not malicious.
    cfJa4Enterprise: {
      label: 'Cloudflare Bot Management fingerprints (Enterprise only; null on free plans)',
      ja3Hash: typeof botManagement?.ja3Hash === 'string' ? botManagement.ja3Hash : null,
      ja4: typeof botManagement?.ja4 === 'string' ? botManagement.ja4 : null,
    },
    // RTT-derived distance estimate, explicitly NOT JA4L. The JA4H-style header stays
    // independent and truthful: httpVersionCode() still reads the real HTTP/3 protocol code.
    rttLightDistance: {
      label: 'RTT-based light-distance estimate (approximation)',
      propagationFactor: LIGHT_DISTANCE_PROPAGATION_FACTOR,
      // Per-transport fields kept for compatibility. A QUIC request has no TCP round trip, so
      // its TCP estimate is explicitly null; no cross-transport fallback is ever reported.
      tcp: isQuic ? null : lightDistanceKm(observedTcpRtt),
      quic: lightDistanceKm(observedQuicRtt),
      // Selected estimate: the R3 normalized RTT only — no cross-transport fallback.
      selected: lightDistanceKm(rtt.rtt_ms),
      selectedSource: rtt.rtt_source,
    },
    // Eight FREE request.cf TLS/network fields available on every plan. These are raw
    // edge-derived TLS components — NOT JA3/JA4 or any Bot-Management-only fingerprint — and
    // are labelled as such so no downstream surface ever misreports them as a JA3/JA4 hash.
    cfTlsLite: {
      label: 'edge-derived TLS components',
      // Cloudflare may deliver the hello length as a decimal string; parse it to a finite
      // number instead of dropping the field (and never emit NaN / Infinity into the header).
      tlsClientHelloLength: finiteNumeric(cf.tlsClientHelloLength),
      tlsClientCiphersSha1: cfString(cf.tlsClientCiphersSha1),
      tlsClientExtensionsSha1: cfString(cf.tlsClientExtensionsSha1),
      tlsClientRandom: cfString(cf.tlsClientRandom),
      // tlsClientAuth is an object (or null), not a string — keep its shape for downstream.
      tlsClientAuth: cfObjectValue(cf.tlsClientAuth),
      requestPriority: cfString(cf.requestPriority),
      edgeL4,
      // Normalized the same way as the R3 RTT: a 0 placeholder is no data, not a measurement.
      clientQuicRtt: observedQuicRtt,
    },
  };
  return encodeURIComponent(JSON.stringify(payload));
}

/**
 * Additive diagnostic opt-in. Diagnostics are enabled ONLY by the exact query flag
 * `intelDiag=1` on the incoming URL. When enabled, a single `x-intel-diag: 1` request header
 * is propagated to the upstream fetch; when absent, any client-supplied copy is removed so
 * the header is never emitted unless the flag is exactly present.
 */
const DIAG_HEADER = 'x-intel-diag';

function hasDiagFlag(request) {
  try {
    return new URL(request.url).searchParams.get('intelDiag') === '1';
  } catch {
    return false;
  }
}

function applyDiagHeader(headers, request) {
  if (hasDiagFlag(request)) headers.set(DIAG_HEADER, '1');
  else headers.delete(DIAG_HEADER);
}

/* -------------------------------------------------------------------------- */
/* OPTIONAL, flag-gated Web Bot Auth + official-bot-feed attribution           */
/* -------------------------------------------------------------------------- */

/**
 * Diagnostics are enabled ONLY by the exact query flag `intelWbaDiag=1`. When enabled, the
 * pure parse helper from src/lib/webBotAuth.ts and the UA prefilter from
 * src/lib/officialBotFeeds.ts derive NEUTRAL attributes. No signing key is fetched and no
 * signature is cryptographically verified in this path: the diagnostic NEVER claims
 * `verified` / `valid` / `good`. Its only status values are `absent`, `present` and
 * `neutral` (inconclusive).
 *
 * When the flag is absent, every client-supplied `x-intel-wba-*` header is stripped and
 * nothing else happens — so no extra work and no new network calls by default. Existing
 * JA4H / bot-verdict / version headers are left byte-for-byte untouched.
 */
const WBA_DIAG_FLAG = 'intelWbaDiag';
const WBA_STATUS_HEADER = 'x-intel-wba-status';
const BOT_FEED_MATCH_HEADER = 'x-intel-bot-feed-match';

function hasWbaDiagFlag(request) {
  try {
    return new URL(request.url).searchParams.get(WBA_DIAG_FLAG) === '1';
  } catch {
    return false;
  }
}

/** UA-based official-feed PREFILTER — explicitly not a verdict, never proof of identity. */
function botFeedPrefilter(request) {
  try {
    const ids = uaPrefilter(request.headers.get('user-agent') || '');
    return Array.isArray(ids) && ids.length ? ids.join(',') : 'none';
  } catch {
    return 'none';
  }
}

/** Per-request memo so request-side and response-side diagnostics share one pure parse. */
const wbaDiagByRequest = new WeakMap();

/**
 * Pure, non-throwing snapshot. Returns `{ enabled: false }` without the exact flag. With the
 * flag but no full Signature / Signature-Input / Signature-Agent triple it reports `absent`.
 * Otherwise the headers are parsed (no fetch, no crypto) into observational attributes only.
 */
function computeWbaDiagnostics(request) {
  try {
    if (!hasWbaDiagFlag(request)) return { enabled: false };
    const rawSignature = request.headers.get('signature');
    const rawInput = request.headers.get('signature-input');
    const rawAgent = request.headers.get('signature-agent');
    const feedMatch = botFeedPrefilter(request);
    if (!rawSignature || !rawInput || !rawAgent) {
      return {
        enabled: true,
        absent: true,
        status: 'absent',
        present: '0',
        label: '',
        agentUrl: '',
        agentForm: '',
        covered: '',
        keyid: '',
        error: '',
        feedMatch,
      };
    }
    let parsed = null;
    try {
      parsed = parseSignatureHeaders(rawSignature, rawInput, rawAgent);
    } catch {
      parsed = null;
    }
    const present = Boolean(parsed && parsed.present);
    const error = firstString(parsed || {}, 'error');
    // Observational only: `present` = well-formed material, `neutral` = inconclusive.
    // Never `verified` / `valid` — no cryptographic verification happens in this path.
    const status = present && !error ? 'present' : 'neutral';
    const params = parsed && parsed.params ? parsed.params : {};
    return {
      enabled: true,
      absent: false,
      status,
      present: present ? '1' : '0',
      label: firstString(parsed || {}, 'label'),
      agentUrl: firstString(parsed || {}, 'agentUrl'),
      agentForm: firstString(parsed || {}, 'agentForm'),
      covered: Array.isArray(parsed?.covered) ? parsed.covered.join(',') : '',
      keyid: firstString(params, 'keyid'),
      error,
      feedMatch,
    };
  } catch {
    return { enabled: false };
  }
}

function wbaDiagnostics(request) {
  let snap = wbaDiagByRequest.get(request);
  if (!snap) {
    snap = computeWbaDiagnostics(request);
    wbaDiagByRequest.set(request, snap);
  }
  return snap;
}

/**
 * Strip every client-supplied diagnostic header so it can never be spoofed upstream. The
 * pre-existing `x-intel-wba-attestation` is deliberately preserved — it belongs to the
 * existing verifier path and must keep its current behaviour (NON-DISRUPTION).
 */
function stripWbaDiagRequestHeaders(headers) {
  const names = [];
  headers.forEach((_value, name) => {
    const lower = name.toLowerCase();
    if (
      (lower.startsWith('x-intel-wba-') && lower !== 'x-intel-wba-attestation') ||
      lower === BOT_FEED_MATCH_HEADER
    ) {
      names.push(name);
    }
  });
  for (const name of names) headers.delete(name);
}

/**
 * Forward NEUTRAL diagnostic attributes as `x-intel-wba-*` request headers. With the flag
 * absent this only strips client-supplied copies and does nothing else.
 */
function applyWbaDiagRequestHeaders(headers, request) {
  stripWbaDiagRequestHeaders(headers);
  const snap = wbaDiagnostics(request);
  if (!snap.enabled) return;
  headers.set('x-intel-wba-diag-status', snap.status);
  headers.set('x-intel-wba-diag-present', snap.present);
  headers.set('x-intel-wba-diag-feed-match', snap.feedMatch);
  if (snap.label) headers.set('x-intel-wba-diag-label', snap.label);
  if (snap.agentUrl) headers.set('x-intel-wba-diag-agent-url', snap.agentUrl);
  if (snap.agentForm) headers.set('x-intel-wba-diag-agent-form', snap.agentForm);
  if (snap.covered) headers.set('x-intel-wba-diag-covered', snap.covered);
  if (snap.keyid) headers.set('x-intel-wba-diag-keyid', snap.keyid);
  if (snap.error) headers.set('x-intel-wba-diag-error', snap.error);
}

/** Additive response headers, emitted ONLY with the exact flag, strictly observational. */
function applyWbaDiagResponseHeaders(response, request) {
  const snap = wbaDiagnostics(request);
  if (!snap.enabled) return response;
  response.headers.set(WBA_STATUS_HEADER, snap.status);
  response.headers.set(BOT_FEED_MATCH_HEADER, snap.feedMatch);
  return response;
}

/**
 * JA4H-style HTTP header fingerprint — APPROXIMATE, never an exact JA4H hash. Cloudflare and
 * the Workers runtime may strip, normalise or reorder headers, and the hash is over the
 * EXPOSED header names rather than raw wire order.
 *
 * section a = method2 + version2 + cookie(c/n) + referer(r/n) + headerCount2 + acceptLang4
 * section b = first 12 hex chars of WebCrypto SHA-256 over exposed header names in order,
 *             excluding Cookie / Referer.
 */
function httpVersionCode(request) {
  const protocol = cfString(request.cf?.httpProtocol);
  if (/HTTP\/3/i.test(protocol)) return '30';
  if (/HTTP\/2/i.test(protocol)) return '20';
  if (/HTTP\/1\.1/i.test(protocol)) return '11';
  if (/HTTP\/1\.0/i.test(protocol)) return '10';
  return '00';
}

function acceptLanguageCode(request) {
  const primary = (request.headers.get('accept-language') || '').split(',')[0] || '';
  const code = primary.trim().toLowerCase().replace(/-/g, '').slice(0, 4);
  return code ? code.padEnd(4, '0') : '0000';
}

async function buildJa4hHeader(request) {
  const headers = request.headers;
  const allNames = [];
  headers.forEach((_value, name) => allNames.push(name.toLowerCase()));
  const exposedNames = allNames.filter((name) => name !== 'cookie' && name !== 'referer');

  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(exposedNames.join(',')));
  const sectionB = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0')
  )
    .join('')
    .slice(0, 12);

  const method = (request.method || 'GET').toUpperCase().slice(0, 2).padEnd(2, '0');
  const cookie = headers.has('cookie') ? 'c' : 'n';
  const referer = headers.has('referer') || headers.has('referrer') ? 'r' : 'n';
  const count = String(allNames.length).padStart(2, '0');
  const sectionA = method + httpVersionCode(request) + cookie + referer + count + acceptLanguageCode(request);
  return `ja4h${sectionA}_${sectionB}`;
}

/**
 * Optional, opt-in origin enforcement. The ONLY switch is the exact query flag
 * `intelStrictOrigin=1`; without it (or with any other value) this is a no-op and no request
 * is ever rejected on origin grounds. A missing / `null` / unparseable Origin fails open.
 */
function strictOriginMismatch(request) {
  try {
    if (new URL(request.url).searchParams.get('intelStrictOrigin') !== '1') return false;
    const origin = (request.headers.get('origin') || '').trim();
    if (!origin || origin === 'null') return false;
    const expected = new URL(request.url).origin;
    return origin.replace(/\/+$/, '').toLowerCase() !== expected.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Forwards the request to the API with a sanitized header set.
 *
 * Cloudflare overwrites `cf-connecting-ip`, so that value is the only trustworthy client
 * address. Any inbound geo/IP header is deleted and replaced, which closes the spoofing
 * path where a client could send `x-vercel-ip-country` through Cloudflare untouched.
 */
async function forwardApiRequest(request) {
  const headers = new Headers(request.headers);
  for (const name of UNTRUSTED_FORWARD_HEADERS) headers.delete(name);

  // The Workers→Node request adapter splits a comma-containing `user-agent` at the first
  // comma, which truncated `AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot…)`
  // to `…(KHTML` and made named crawlers look human on the API path. Forward the complete
  // value in an encoded, comma-free header that the server prefers over `user-agent`.
  const userAgent = request.headers.get('user-agent');
  if (userAgent) {
    headers.set('user-agent', userAgent);
    headers.set('x-intel-original-ua', encodeURIComponent(userAgent));
  }

  // Web Bot Auth / authority values are always taken from the REAL inbound request and
  // encoded before forwarding, mirroring x-intel-original-ua above. A client-supplied
  // x-intel-original-* header is deleted first, so it can never spoof these. The genuine
  // Signature / Signature-Agent / Signature-Input headers are deliberately left in place.
  const originalAuthority = request.headers.get('host') || new URL(request.url).host;
  if (originalAuthority) {
    headers.set('x-intel-original-authority', encodeURIComponent(originalAuthority));
  }
  const wbaHeaderPairs = [
    ['x-intel-original-signature-agent', 'signature-agent'],
    ['x-intel-original-signature-input', 'signature-input'],
    ['x-intel-original-signature', 'signature'],
    ['x-intel-wba-attestation', 'x-intel-wba-attestation'],
  ];
  for (const [target, source] of wbaHeaderPairs) {
    const value = request.headers.get(source);
    if (value) headers.set(target, encodeURIComponent(value));
  }

  // Only Cloudflare can set cf-connecting-ip, but a private / reserved / malformed value must
  // never be forwarded or treated as a client identity. x-forwarded-for (and RFC7239
  // `forwarded`) were stripped above, so the backend can no longer fall back to a spoofed IP.
  const clientIp = publicClientIp(request.headers.get('cf-connecting-ip'));
  if (clientIp) {
    headers.set('cf-connecting-ip', clientIp);
    headers.set('x-forwarded-for', clientIp);
  } else {
    headers.delete('cf-connecting-ip');
    headers.delete('x-forwarded-for');
  }
  headers.set(EDGE_GEO_HEADER, buildEdgeGeoHeader(request));

  // Additive diagnostics: mirror the exact `intelDiag=1` opt-in to the upstream request.
  applyDiagHeader(headers, request);

  // Additive JA4H-style fingerprint: recomputed from the REAL inbound headers and stamped
  // over any client-supplied copy (which was stripped above via UNTRUSTED_FORWARD_HEADERS).
  headers.set(JA4H_HEADER, await buildJa4hHeader(request));

  // Additive, flag-gated Web Bot Auth + official-bot-feed diagnostics (neutral attributes
  // only; no key fetch, no crypto verify). With the flag absent this only strips spoofed
  // client-supplied x-intel-wba-* headers and leaves everything else untouched.
  applyWbaDiagRequestHeaders(headers, request);

  return new Request(request, { headers });
}

/** Merge Vary tokens instead of replacing them (the Express route does the same). */
function mergeVary(headers, values) {
  const existing = headers.get('Vary') || '';
  const tokens = existing
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  for (const value of values) {
    if (!tokens.some((item) => item.toLowerCase() === value.toLowerCase())) tokens.push(value);
  }
  if (tokens.length) headers.set('Vary', tokens.join(', '));
  else headers.delete('Vary');
}

/**
 * The single place that applies the client-hint / hardening response headers. Called
 * exactly once per response: API responses go through `apiResponse`, documents and
 * immutable assets through `applyClientHintHeaders` directly.
 */
function applyClientHintHeaders(response, env, request) {
  const result = new Response(response.body, response);
  result.headers.set('Accept-CH', CLIENT_HINT_ACCEPT_CH);
  result.headers.set('Critical-CH', CLIENT_HINT_CRITICAL_CH);
  // Preserve upstream Vary (e.g. Accept-Encoding / Cookie) and add Sec-CH-UA* to it.
  mergeVary(result.headers, [CLIENT_HINT_VARY]);
  result.headers.set(
    'Permissions-Policy',
    'compute-pressure=*, ch-ua-model=(self), ch-ua-platform-version=(self), ch-ua-arch=(self), ch-ua-form-factors=(self)'
  );
  result.headers.set('X-Content-Type-Options', 'nosniff');

  // Version attribution: same three values on every surface so a response can be traced to
  // the exact parser / build / worker that produced it.
  for (const [name, value] of Object.entries(versionHeaders(env))) result.headers.set(name, value);

  // Hardening. Values are deliberately permissive where the app needs them (inline theme
  // script, injected verdict JSON, bunny.net fonts, HTTPS map tiles) and strict elsewhere.
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) result.headers.set(name, value);

  // CORS stays same-origin. The allowed origin is derived from the request URL — never from
  // the client-controlled `Origin` header — so it needs no `Vary: Origin` and cannot be used
  // to grant a third party access to first-party API data.
  if (request) {
    try {
      result.headers.set('Access-Control-Allow-Origin', new URL(request.url).origin);
    } catch {
      /* malformed request URL: omit CORS rather than emit a wildcard */
    }
  }

  // Additive, flag-gated diagnostics: x-intel-wba-status / x-intel-bot-feed-match are emitted
  // ONLY when intelWbaDiag=1 is present, and are strictly observational (never verified/good).
  // All existing JA4H / bot / version / hardening headers above remain intact.
  applyWbaDiagResponseHeaders(result, request);
  return result;
}

function apiResponse(response, env, request) {
  const result = applyClientHintHeaders(response, env, request);
  result.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, no-transform');
  return result;
}

/**
 * API counterpart of the document branding pass: the same apiResponse() contract plus the
 * additive verdict/JA4H headers. Native routes do NOT bypass apiResponse() — they call
 * apiResponse()/applyClientHintHeaders() directly and then keep their own route-specific
 * Cache-Control / body contracts (see nativeHealth, nativePing and nativeIdentityPing).
 */
async function apiResponseWithVerdict(response, env, request, verdict) {
  const result = apiResponse(response, env, request);
  for (const [name, value] of Object.entries(botVerdictHeaders(verdict))) {
    result.headers.set(name, value);
  }
  result.headers.set(JA4H_HEADER, await buildJa4hHeader(request));
  return result;
}

/* -------------------------------------------------------------------------- */
/* Short-lived signed-agent cookie (WebCrypto only — no Node crypto in Workers) */
/* -------------------------------------------------------------------------- */

const textEncoder = new TextEncoder();

function toBase64Url(bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256Base64Url(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(message));
  return toBase64Url(signature);
}

/** Hex HMAC matching the Express visitor-token signer (crypto.createHmac(...).digest('hex')). */
async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(message));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Length-checked, constant-time comparison for the hex token above. */
function constantTimeHexEqual(expected, presented) {
  if (
    typeof expected !== 'string' ||
    typeof presented !== 'string' ||
    expected.length !== presented.length
  ) {
    return false;
  }
  let difference = 0;
  for (let i = 0; i < expected.length; i += 1) {
    difference |= expected.charCodeAt(i) ^ presented.charCodeAt(i);
  }
  return difference === 0;
}

/** Mirrors the Express visitor-token check without its former public fallback secret. */
async function verifyVisitorToken(visitorId, token, env) {
  if (!visitorId || !token) return false;
  const secret = env && typeof env.VISITOR_HMAC_SECRET === 'string' ? env.VISITOR_HMAC_SECRET : '';
  // No hardcoded/public literal: a missing or short binding means the cookie is unverified.
  if (secret.length < 32) return false;
  try {
    return constantTimeHexEqual(await hmacSha256Hex(secret, visitorId), token);
  } catch {
    return false;
  }
}

/**
 * A verified Web Bot Auth request earns a 60-second, HMAC-signed `intel_wba` cookie so the
 * backend/client can recognise subsequent same-agent traffic without re-verifying on every
 * navigation. Returns null (no cookie) unless the signature is verified and the shared
 * secret is configured with sufficient entropy. Any failure fails open — never breaks the doc.
 */
async function buildWbaCookie(request, verdict, env) {
  const secret = env.VISITOR_HMAC_SECRET;
  if (verdict.signatureStatus !== 'verified' || typeof secret !== 'string' || secret.length < 32) {
    return null;
  }
  try {
    const host = request.headers.get('host') || new URL(request.url).host;
    const ua = request.headers.get('user-agent') || '';
    const ip = request.headers.get('cf-connecting-ip') || '';
    const [uaDigest, ipDigest] = await Promise.all([sha256Hex(ua), sha256Hex(ip)]);
    const payload = {
      op: verdict.verifiedOperator || '',
      agentId: verdict.verifiedAgentId || '',
      host,
      uaHash: uaDigest.slice(0, 16),
      ipHash: ipDigest.slice(0, 16),
      exp: Date.now() + 60_000,
    };
    const part = toBase64Url(textEncoder.encode(JSON.stringify(payload)));
    const signature = await hmacSha256Base64Url(secret, part);
    return `intel_wba=${part}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=60`;
  } catch (error) {
    console.error('intel_wba cookie generation failed:', error);
    return null;
  }
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
 * The verifier reads headers via Object.keys()/index access, so a Headers instance (whose
 * entries are not enumerable own properties) must be materialised into a plain record first.
 */
function headersToRecord(headers) {
  const record = {};
  headers.forEach((value, name) => {
    record[name] = value;
  });
  return record;
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

/** The one edge verdict producer: raw UA, optional Cloudflare Bot Management and Web Bot Auth. */
async function computeEdgeVerdict(request) {
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

  // The cheap header pre-check keeps signature verification off the overwhelming majority of
  // anonymous requests. Only requests presenting a full RFC 9421 signature triple are verified.
  const hasSigned = hasSignedAgentHeaders(request);
  let verification = { status: 'none' };
  if (hasSigned) {
    try {
      const authority = request.headers.get('host') || new URL(request.url).host;
      const result = await verifyWebBotAuth({
        headers: headersToRecord(request.headers),
        authority,
        trust: WBA_TRUSTED_SIGNERS,
      });
      verification = recordOf(result);
    } catch (error) {
      // A verification outage must never reject a visitor — fail open to an unverified verdict.
      console.error('Web Bot Auth verification failure:', error);
      verification = { status: 'error' };
    }
  }

  const signatureStatus = firstString(verification, 'status', 'signatureStatus') || 'none';
  const signedAgent = signatureStatus === 'verified'; // genuine, cryptographically verified
  const verifiedAgentId = firstString(verification, 'agentId', 'agent_id', 'agent', 'id');
  const verifiedOperator = firstString(
    verification,
    'operator',
    'signer',
    'organization',
    'vendor',
    'name'
  );
  const evidence = verification.evidence ?? null;

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
  let name = display ? verdictName(display, info, identity, pill) : '';
  let provider = firstString(info, 'provider', 'operator', 'organization', 'vendor', 'company') || null;
  let botType = firstString(info, 'id', 'agentId', 'key', 'slug', 'type', 'name') || null;

  // When the signature is genuine, the verified identity is authoritative for the name shown
  // in the verdict (and therefore in the X-Intel-Bot-* headers and SSR payload).
  if (signedAgent && (verifiedAgentId || verifiedOperator)) {
    // `displayFor()` reads `displayName` / `provider`, so passing a bare synthesized record
    // (with only `name` / `operator`) produced a vague "Signed · undefined" label. Resolve the
    // verified id through the canonical registry so the SSR name/provider are exact (e.g.
    // "Signed · Manus Bot · Manus"). Fall back to a fully-populated record for future signers
    // that are not yet in the registry, never to one with undefined fields.
    const verifiedAgentDef = (verifiedAgentId && AGENT_BY_ID[verifiedAgentId]) || null;
    const verifiedInfo = verifiedAgentDef || {
      id: verifiedAgentId,
      agentId: verifiedAgentId,
      name: verifiedAgentId,
      displayName: verifiedAgentId || verifiedOperator,
      provider: verifiedOperator,
      operator: verifiedOperator,
    };
    let verifiedDisplay = null;
    try {
      verifiedDisplay = displayFor(verifiedInfo, identity);
    } catch {
      verifiedDisplay = null;
    }
    name = verdictName(verifiedDisplay, verifiedInfo, identity, pillLabelFor(verifiedInfo));
    provider = verifiedAgentDef?.provider || verifiedOperator || provider;
    botType = verifiedAgentId || botType;
  }

  return {
    agent,
    name,
    provider,
    botType,
    identity,
    os: edgeOsLabel(request),
    verifiedBot,
    signedAgent,
    verifiedAgentId,
    verifiedOperator,
    signatureStatus,
    evidence,
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
    // Additive lower-case aliases derived from the SAME edge verdict — no new verdict logic.
    'x-intel-bot-result': verdict.name || 'not_detected',
    'x-intel-bot-category': verdict.botType || 'none',
    'x-intel-bot-identity': verdict.identity || 'unknown',
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
  const assetHeaders = new Headers(request.headers);
  applyDiagHeader(assetHeaders, request);
  const asset = await env.ASSETS.fetch(new Request(request, { headers: assetHeaders }));

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
            signedAgent: verdict.signedAgent,
            verifiedAgentId: verdict.verifiedAgentId || null,
            verifiedOperator: verdict.verifiedOperator || null,
            signatureStatus: verdict.signatureStatus || 'none',
            evidence: verdict.evidence ?? null,
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

  const result = applyClientHintHeaders(response, env, request);
  for (const [name, value] of Object.entries(botVerdictHeaders(verdict))) {
    result.headers.set(name, value);
  }
  for (const name of STRIP_DOCUMENT_HEADERS) result.headers.delete(name);
  result.headers.set('Cache-Control', 'private, no-store, max-age=0');

  const wbaCookie = await buildWbaCookie(request, verdict, env);
  if (wbaCookie) result.headers.append('Set-Cookie', wbaCookie);
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
    // Never collapse every unattributed request into one shared 'unknown' bucket: that bucket
    // would throttle all such clients together (and let one client poison it for everyone).
    // An unvalidated address instead gets a unique, non-shareable key for this request only.
    const clientIp = publicClientIp(request.headers.get('cf-connecting-ip'));
    const key = clientIp || `unkeyed:${crypto.randomUUID()}`;
    try {
      const limitVerdict = await env.IDENTIFY_RATE_LIMIT.limit({ key });
      if (!limitVerdict.success) {
        const resetMs =
          typeof limitVerdict.reset === 'number' ? limitVerdict.reset : Date.now() + 60_000;
        const retryAfter = Math.max(0, Math.ceil((resetMs - Date.now()) / 1000));
        return await apiResponseWithVerdict(
          Response.json(
            { error: 'Too many identification requests. Please retry later.' },
            { status: 429, headers: { 'Retry-After': String(retryAfter) } }
          ),
          env,
          request,
          verdict
        );
      }
    } catch (error) {
      // A limiter outage must never take the identification path down; fail open.
      console.error('IDENTIFY_RATE_LIMIT failure:', error);
    }
  }

  if (!env.VISITOR_HMAC_SECRET || env.VISITOR_HMAC_SECRET.length < 32) {
    return await apiResponseWithVerdict(Response.json({ error: 'Configure VISITOR_HMAC_SECRET with at least 32 characters.' }, { status: 503 }), env, request, verdict);
  }
  try {
    const forwardedRequest = await forwardApiRequest(request);
    // Visitor routes need request-scoped Durable-Object SQLite access; every other API
    // route runs statelessly so it cannot consume the daily row-write quota.
    const persistent =
      pathname.startsWith('/api/visitor/') ||
      pathname === '/api/intel/geolocation';
    const response = persistent
      ? await env.VISITOR_STORE.get(env.VISITOR_STORE.idFromName('visitor-store-v1')).fetch(forwardedRequest)
      : await handleAsNodeRequest(API_PORT, forwardedRequest);
    return await apiResponseWithVerdict(response, env, request, verdict);
  } catch (error) {
    console.error('Worker API failure:', error);
    return await apiResponseWithVerdict(Response.json({ error: 'Internal server error.' }, { status: 500 }), env, request, verdict);
  }
}

/* -------------------------------------------------------------------------- */
/* Native stateless API routes                                                 */
/* -------------------------------------------------------------------------- */

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value));
  return toBase64Url(digest);
}

/** Reads the first matching visitor-id cookie, mirroring cookie-parser's decode step. */
function readCookieValue(cookieHeader, names) {
  if (!cookieHeader) return '';
  for (const pair of cookieHeader.split(';')) {
    const separator = pair.indexOf('=');
    if (separator < 0) continue;
    if (!names.includes(pair.slice(0, separator).trim())) continue;
    let value = pair.slice(separator + 1).trim();
    try {
      value = decodeURIComponent(value);
    } catch {
      /* keep the raw value if it is not valid percent-encoding */
    }
    if (value) return value;
  }
  return '';
}

/** Native /api/health: no Express, no database, no Durable Object — always answerable. */
function nativeHealth(request, env) {
  const { parserVersion, buildSha, workerVersion } = versionInfo(env);
  return apiResponse(
    Response.json({
      status: 'ok',
      visitorsCount: null,
      visitsCount: null,
      regionCode: 'global-edge',
      regionLabel: 'Global Edge Network',
      parserVersion,
      buildSha,
      workerVersion,
    }),
    env,
    request
  );
}

/** Native /api/network/ping (GET + HEAD) with the Express route's exact cache contract. */
function nativePing(method, request, env) {
  const serverTimestamp = Date.now();
  const baseHeaders = {
    Pragma: 'no-cache',
    Expires: '0',
    'Timing-Allow-Origin': '*',
  };
  const response =
    method === 'HEAD'
      ? new Response(null, { status: 200, headers: baseHeaders })
      : Response.json(
          { ok: true, serverTimestamp, serverTimestampMs: serverTimestamp },
          { headers: baseHeaders }
        );
  const result = apiResponse(response, env, request);
  result.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  return result;
}

/** Native /api/intel/identity-ping: preserves the HTTP-cache identity recovery contract. */
async function nativeIdentityPing(request, env) {
  const cookieHeader = request.headers.get('cookie');
  const cookieVisitor = readCookieValue(cookieHeader, ['_intel_vid_client', 'intel_http_vid']);
  const cookieToken = readCookieValue(cookieHeader, ['intel_http_token']);
  const headers = {};
  let response;
  if (!cookieVisitor) {
    // A cleared cookie must never revalidate a cached identity: answer 204 BEFORE reading
    // If-None-Match, exactly as the hardened Express route does.
    headers.ETag = '"identity-none"';
    response = new Response(null, { status: 204, headers });
  } else {
    // The per-load nonce resets the ETag on a fresh page load, so a label captured before a
    // cookie clear can never be revived by a later conditional request.
    const loadNonce = (request.headers.get('x-intel-load-nonce') || '').slice(0, 120);
    const etag = `"${await sha256Base64Url(`${cookieVisitor}|${cookieToken}|${loadNonce}`)}"`;
    headers.ETag = etag;
    const presented = request.headers.get('if-none-match') || '';
    // Echoing an arbitrary If-None-Match used to answer 304 for ANY conditional request;
    // only an exact match against the current cookie / token / nonce may revalidate.
    if (presented && presented === etag) {
      response = new Response(null, { status: 304, headers });
    } else {
      response = Response.json(
        {
          identity: {
            visitor_id: cookieVisitor,
            hardware_fingerprint: '',
            browser_fingerprint: '',
            created_at: new Date().toISOString(),
            // Derived from THIS request's cookie + HMAC token, never from a cached response.
            recognition_source: (await verifyVisitorToken(cookieVisitor, cookieToken, env))
              ? 'First-Party Cookie'
              : 'Unverified Cookie',
          },
          // Handed back so the next conditional request can carry the same per-load nonce.
          load_nonce: loadNonce,
        },
        { headers }
      );
    }
  }
  const result = applyClientHintHeaders(response, env, request);
  // Mirror the Express route: private/no-store revalidation and a Vary that keeps both
  // UA-CH-negotiated and cookie-bound identities isolated in any shared cache.
  result.headers.set('Cache-Control', 'private, no-store, no-cache, must-revalidate, max-age=0');
  mergeVary(result.headers, ['Cookie', CLIENT_HINT_VARY]);
  return result;
}

/**
 * Intercepts the three stateless API routes with native Response objects. Returning null lets
 * every other /api path continue down the existing Express / Durable-Object path unchanged.
 */
async function handleNativeApi(request, env, pathname) {
  const method = request.method;
  if (pathname === '/api/health') {
    return method === 'GET' ? nativeHealth(request, env) : null;
  }
  if (pathname === '/api/network/ping') {
    return method === 'GET' || method === 'HEAD' ? nativePing(method, request, env) : null;
  }
  if (pathname === '/api/intel/identity-ping') {
    return method === 'GET' ? nativeIdentityPing(request, env) : null;
  }
  return null;
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

    // Stateless native routes answer without Express, the Durable Object or WBA verification.
    // Everything else under /api keeps the existing forwarding path unchanged.
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      const native = await handleNativeApi(request, env, pathname);
      if (native) return native;
    }

    // Optional origin enforcement. ONLY the exact `intelStrictOrigin=1` query flag can produce
    // a rejection; without it no request is ever rejected for its Origin. Native routes were
    // already answered above, and assets / pass-through files are excluded so they stay
    // verbatim even when a deployment opts in.
    if (strictOriginMismatch(request)) {
      if (pathname === '/api' || pathname.startsWith('/api/')) {
        return apiResponse(
          Response.json({ error: 'Origin check failed.' }, { status: 403 }),
          env,
          request
        );
      }
      if (!pathname.startsWith('/assets/') && !PASS_THROUGH_PATHS.has(pathname)) {
        return applyClientHintHeaders(new Response('Forbidden', { status: 403 }), env, request);
      }
    }

    const verdict = await computeEdgeVerdict(request);

    // API branch — the only path that uses apiResponse() / the ratelimit binding.
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      return handleApi(request, env, pathname, verdict);
    }

    // Immutable hashed assets: pass through untouched — never rewritten and never branded
    // with a per-visitor bot verdict. (run_worker_first excludes /assets/* in production.)
    if (pathname.startsWith('/assets/')) {
      return applyClientHintHeaders(await env.ASSETS.fetch(request), env, request);
    }

    // Crawler control / LLM metadata files are copied verbatim from public/ into dist/.
    // Serve them directly so they keep their own caching and are never UA-branded.
    if (PASS_THROUGH_PATHS.has(pathname)) {
      return applyClientHintHeaders(await env.ASSETS.fetch(request), env, request);
    }

    // Document branch — every page navigation / SPA deep link.
    return handleDocument(request, env, verdict);
  },
};
