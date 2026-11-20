/**
 * Web Bot Auth (RFC 9421 HTTP Message Signatures) header parsing and Ed25519 verification.
 *
 * DESIGN CONTRACT
 * - Dependency-free and browser-safe. No imports, no Node APIs, and no platform globals are
 *   touched at module load. `globalThis.crypto.subtle`, `fetch` and `TextEncoder` are used only
 *   at CALL time inside the async helpers.
 * - Fail-open: `verifyWebBotAuth` never throws; every failure path returns a WbaVerification
 *   with a non-verified status and human-readable evidence.
 * - No trust is inferred from IP/ASN data. A signature is verified only against keys published
 *   by an explicitly allowlisted signer directory (optionally constrained to pinned keys).
 *
 * The `@signature-params` line of the signature base uses the raw Signature-Input dictionary
 * member value verbatim, exactly as required by RFC 9421 §2.3.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                                */
/* -------------------------------------------------------------------------- */

export interface WbaParsed {
  present: boolean;
  label: string;
  keyId: string;
  tag: string;
  created: number | null;
  expires: number | null;
  covered: string[];
  rawSignatureInput: string;
  signatureBytes: Uint8Array | null;
  agentHost: string | null;
  agentOrigin: string | null;
}

export type WbaStatus =
  | 'verified'
  | 'invalid'
  | 'expired'
  | 'unknown_signer'
  | 'unsupported'
  | 'unavailable'
  | 'absent';

export interface WbaVerification {
  status: WbaStatus;
  verified: boolean;
  operator: string | null;
  agentId: string | null;
  signerHost: string | null;
  keyId: string | null;
  keySource: 'pinned' | 'directory' | null;
  evidence: string[];
  checkedAtMs: number;
}

export interface WbaTrustedSigner {
  agentId: string;
  operator: string;
  directoryHosts: readonly string[];
  pinnedKeyX?: readonly string[];
  pinnedKeyIds?: readonly string[];
  requirePinnedKey?: boolean;
  directoryUrl?: string;
}

export interface WbaVerifyOptions {
  headers: Record<string, string | string[] | undefined>;
  authority?: string;
  nowMs?: number;
  trust?: readonly WbaTrustedSigner[];
  fetchDirectory?: (url: string) => Promise<{ body: string; cacheControl?: string } | null>;
  cache?: Map<string, { keys: { crv: string; kty: string; x: string }[]; fetchedAtMs: number; expiresAtMs: number }>;
  subtle?: SubtleCrypto;
}

/* -------------------------------------------------------------------------- */
/* Trust anchors                                                              */
/* -------------------------------------------------------------------------- */

export const WBA_TRUSTED_SIGNERS: readonly WbaTrustedSigner[] = [
  {
    agentId: 'manus_bot',
    operator: 'Manus',
    directoryHosts: ['api.manus.im', 'manus.im', 'manus.ai'],
    requirePinnedKey: false,
    directoryUrl: 'https://api.manus.im/.well-known/http-message-signatures-directory',
  },
  {
    agentId: 'grok_agent',
    operator: 'xAI',
    directoryHosts: ['cursorusercontent.com'],
    requirePinnedKey: true,
    pinnedKeyX: ['STDZXOMW-Cg7paRpv_BtjujEHIQVNbzidfjY9M9w6hc'],
    pinnedKeyIds: ['Vuxu4khgzIe0b30Nd6hq2envAuVBFMTDqorSNIUb_Oo'],
    directoryUrl: 'https://cursorusercontent.com/.well-known/http-message-signatures-directory',
  },
];

/* -------------------------------------------------------------------------- */
/* Internal helpers — pure string/byte utilities (no platform APIs)           */
/* -------------------------------------------------------------------------- */

type WbaHeaders = Record<string, string | string[] | undefined>;

interface JwkLike {
  crv: string;
  kty: string;
  x: string;
  kid?: string;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Split on a separator that is outside quoted strings and parentheses. */
function splitTopLevel(value: string, separator: string): string[] {
  const out: string[] = [];
  let start = 0;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quoted) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') quoted = false;
      continue;
    }
    if (ch === '"') quoted = true;
    else if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (ch === separator && depth === 0) {
      out.push(value.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(value.slice(start).trim());
  return out.filter((part) => part.length > 0);
}

/** Case-insensitive header lookup; preserves every occurrence so duplicates can be rejected. */
function headerValues(headers: WbaHeaders, name: string): string[] {
  const wanted = name.toLowerCase();
  const values: string[] = [];
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() !== wanted) continue;
    const raw = headers[key];
    if (Array.isArray(raw)) {
      for (const item of raw) if (typeof item === 'string') values.push(item);
    } else if (typeof raw === 'string') {
      values.push(raw);
    }
  }
  return values;
}

function stripQuotes(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') {
    return v.slice(1, -1).replace(/\\(['"\\])/g, '$1');
  }
  return v;
}

/** Decode standard or URL-safe base64 (with or without padding) into bytes. */
function base64ToBytes(input: string): Uint8Array | null {
  let text = input.replace(/[\s\r\n]/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!text) return new Uint8Array(0);
  if (text.length % 4 === 1 || !/^[A-Za-z0-9+/]+$/.test(text)) return null;
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < text.length; i++) {
    const idx = B64.indexOf(text[i]);
    if (idx < 0) return null;
    buffer = (buffer << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** Encode bytes as base64url (RFC 4648 §5, no padding). */
function bytesToBase64Url(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64URL[b0 >> 2];
    out += B64URL[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += B64URL[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += B64URL[b2 & 63];
  }
  return out;
}

function isReservedHost(host: string): boolean {
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (/\.(local|internal|test|invalid|example|onion)$/.test(host)) return true;
  if (host === 'metadata' || host === 'metadata.google.internal') return true;
  if (!host.includes('.')) return true;
  return false;
}

/**
 * Parse a Signature-Agent structured field value into { host, origin }.
 * Accepts the plain string form (`"https://host"`) and the dictionary/member form
 * (`member="https://host";param=x`, optionally wrapped in a List). HTTPS is mandatory and
 * IP literals, explicit ports, userinfo and reserved/internal hosts are all rejected.
 */
function parseAgentIdentity(values: string[]): { host: string | null; origin: string | null } {
  for (const raw of values) {
    const text = typeof raw === 'string' ? raw : '';
    const candidates: string[] = [];
    for (const match of text.match(/"(?:[^"\\]|\\.)*"/g) ?? []) candidates.push(stripQuotes(match));
    for (const match of text.match(/'[^']*'/g) ?? []) candidates.push(match.slice(1, -1));
    for (const match of text.match(/https:\/\/[^\s,;"'()]+/gi) ?? []) candidates.push(match);

    for (const candidate of candidates) {
      const m = /^https:\/\/([^\s/?#]+)/i.exec(candidate);
      if (!m) continue;
      const authority = m[1];
      if (!authority || authority.includes('@') || authority.includes(':')) continue; // userinfo / port
      let host = authority.toLowerCase().replace(/\.$/, '');
      if (!host || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) continue; // IPv4
      if (host.includes('[') || host.includes(']') || host.includes(':')) continue; // IPv6
      if (isReservedHost(host)) continue;
      return { host, origin: `https://${host}` };
    }
  }
  return { host: null, origin: null };
}

/** RFC 8037 thumbprint with a caller-supplied SubtleCrypto (used internally by verification). */
async function thumbprintWith(subtle: SubtleCrypto, jwk: { crv: string; kty: string; x: string }): Promise<string> {
  const canonical =
    '{"crv":' + JSON.stringify(jwk.crv) +
    ',"kty":' + JSON.stringify(jwk.kty) +
    ',"x":' + JSON.stringify(jwk.x) + '}';
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return bytesToBase64Url(new Uint8Array(digest));
}

function ttlFromCacheControl(cacheControl: string | undefined): number {
  const DEFAULT_TTL = 3_600_000;
  if (!cacheControl) return DEFAULT_TTL;
  const match = /(?:s-maxage|max-age)\s*=\s*"?(\d+)"?/i.exec(cacheControl);
  const seconds = match ? Number(match[1]) : DEFAULT_TTL / 1000;
  const ttl = Number.isFinite(seconds) ? seconds * 1000 : DEFAULT_TTL;
  return Math.min(86_400_000, Math.max(300_000, ttl));
}

/** Keep the directory `kid` alongside the cache-safe { crv, kty, x } projection. */
const KID_BY_KEY = new WeakMap<object, string>();

function sanitizeJwk(raw: unknown): JwkLike | null {
  if (!raw || typeof raw !== 'object') return null;
  const record = raw as Record<string, unknown>;
  if (typeof record.x !== 'string' || record.x.length === 0) return null;
  const key: JwkLike = {
    crv: typeof record.crv === 'string' && record.crv ? record.crv : 'Ed25519',
    kty: typeof record.kty === 'string' && record.kty ? record.kty : 'OKP',
    x: record.x,
  };
  if (typeof record.kid === 'string' && record.kid) {
    key.kid = record.kid;
    KID_BY_KEY.set(key, record.kid);
  }
  return key;
}

/* -------------------------------------------------------------------------- */
/* Public parsing / base helpers                                               */
/* -------------------------------------------------------------------------- */

/**
 * Parse the three Web Bot Auth headers. Never throws. Malformed or ambiguous inputs leave the
 * affected fields empty (the verifier then reports 'invalid' / 'absent' accordingly).
 */
export function parseWbaHeaders(headers: WbaHeaders): WbaParsed {
  const parsed: WbaParsed = {
    present: false,
    label: '',
    keyId: '',
    tag: '',
    created: null,
    expires: null,
    covered: [],
    rawSignatureInput: '',
    signatureBytes: null,
    agentHost: null,
    agentOrigin: null,
  };

  const inputValues = headerValues(headers, 'signature-input');
  const signatureValues = headerValues(headers, 'signature');
  const agentValues = headerValues(headers, 'signature-agent');
  parsed.present = inputValues.some((value) => typeof value === 'string' && value.trim().length > 0);
  if (!parsed.present) return parsed;

  const identity = parseAgentIdentity(agentValues);
  parsed.agentHost = identity.host;
  parsed.agentOrigin = identity.origin;

  // Reject duplicate or comma-joined dictionary members (ambiguous signature selection).
  const inputMembers = splitTopLevel(inputValues[0] ?? '', ',');
  const signatureText = signatureValues[0] ?? '';
  const signatureMembers = signatureText.trim() ? splitTopLevel(signatureText, ',') : [];
  if (inputValues.length !== 1 || signatureValues.length > 1 ||
      inputMembers.length !== 1 || signatureMembers.length > 1) {
    return parsed;
  }

  // --- Signature-Input: label=(components);params ---------------------------
  const member = inputMembers[0];
  const eq = member.indexOf('=');
  if (eq > 0) parsed.label = member.slice(0, eq).trim();
  const value = eq >= 0 ? member.slice(eq + 1).trim() : '';
  const open = value.indexOf('(');
  const close = value.lastIndexOf(')');
  if (open < 0 || close <= open) return parsed;

  parsed.rawSignatureInput = value; // verbatim dictionary member value, incl. parameters
  const coveredText = value.slice(open + 1, close);
  const tokenPattern = /"(?:[^"\\]|\\.)*"|\S+/g;
  for (const match of coveredText.match(tokenPattern) ?? []) {
    const name = stripQuotes(match).toLowerCase();
    if (name && name !== '@signature-params' && !parsed.covered.includes(name)) parsed.covered.push(name);
  }

  for (const param of splitTopLevel(value.slice(close + 1), ';')) {
    const p = param.indexOf('=');
    if (p < 0) continue;
    const name = param.slice(0, p).trim().toLowerCase();
    const rawValue = param.slice(p + 1).trim();
    if (name === 'created' || name === 'expires') {
      const n = Number(rawValue);
      if (Number.isFinite(n)) parsed[name] = n;
    } else if (name === 'keyid') {
      parsed.keyId = stripQuotes(rawValue);
    } else if (name === 'tag') {
      parsed.tag = stripQuotes(rawValue);
    }
  }

  // --- Signature: label=:base64bytes: --------------------------------------
  const sigMember = signatureMembers[0] ?? '';
  const sigEq = sigMember.indexOf('=');
  const sigValue = sigEq >= 0 ? sigMember.slice(sigEq + 1).trim() : '';
  if (sigValue.length >= 2 && sigValue[0] === ':' && sigValue[sigValue.length - 1] === ':') {
    parsed.signatureBytes = base64ToBytes(sigValue.slice(1, -1));
  }

  return parsed;
}

/** RFC 8037 canonical JWK thumbprint: base64url(SHA-256(`{"crv",...,"kty",...,"x",...}`)). */
export async function computeJwkThumbprint(jwk: { crv: string; kty: string; x: string }): Promise<string> {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error('WebCrypto SubtleCrypto is unavailable');
  return thumbprintWith(subtle, jwk);
}

/**
 * Build the RFC 9421 signature base for the covered components we handle. The bytes fed to
 * Ed25519 are the UTF-8 encoding of this string. Each line is LF-terminated; the base ends with
 * exactly one LF and there is no extra blank line after the @signature-params line.
 */
export function buildSignatureBase(parsed: WbaParsed, authority: string): string | null {
  if (!parsed.agentOrigin) return null;
  if (!parsed.rawSignatureInput) return null;
  const lines: string[] = [];
  for (const component of parsed.covered) {
    if (component === '@authority') {
      lines.push(`"@authority": ${authority}`);
    } else if (component === 'signature-agent') {
      lines.push(`"signature-agent": "${parsed.agentOrigin}"`);
    }
    // @target-uri and other components are intentionally not synthesized: we have their
    // authoritative value only for the two components above.
  }
  if (lines.length === 0) return null;
  lines.push(`"@signature-params": ${parsed.rawSignatureInput}`);
  return lines.join('\n') + '\n';
}

/* -------------------------------------------------------------------------- */
/* Verification                                                               */
/* -------------------------------------------------------------------------- */

async function fetchDirectoryKeys(
  url: string,
  fetchDirectory: WbaVerifyOptions['fetchDirectory']
): Promise<{ keys: JwkLike[]; ttlMs: number } | null> {
  try {
    let body: string | undefined;
    let cacheControl: string | undefined;
    if (fetchDirectory) {
      const response = await fetchDirectory(url);
      if (!response || typeof response.body !== 'string') return null;
      body = response.body;
      cacheControl = response.cacheControl;
    } else {
      const f = globalThis.fetch;
      if (typeof f !== 'function') return null;
      const response = await f(url, { redirect: 'error' });
      if (!response || response.ok === false || (typeof response.status === 'number' && response.status >= 400)) return null;
      body = await response.text();
      cacheControl = response.headers && typeof response.headers.get === 'function'
        ? response.headers.get('cache-control') ?? undefined
        : undefined;
    }
    if (typeof body !== 'string') return null;
    const json = JSON.parse(body) as { keys?: unknown };
    if (!json || !Array.isArray(json.keys)) return null;
    const keys: JwkLike[] = [];
    for (const raw of json.keys.slice(0, 500)) {
      const key = sanitizeJwk(raw);
      if (key) keys.push(key);
    }
    return { keys, ttlMs: ttlFromCacheControl(cacheControl) };
  } catch {
    return null;
  }
}

function resolveAuthority(opts: WbaVerifyOptions, headers: WbaHeaders): string {
  if (typeof opts.authority === 'string' && opts.authority.trim()) return opts.authority.trim();
  for (const name of ['host', ':authority', 'x-forwarded-host']) {
    const values = headerValues(headers, name);
    if (!values.length) continue;
    const authority = values[0].split(',')[0].trim();
    if (authority) return authority;
  }
  return '';
}

/** Verify a Web Bot Auth signature. Fail-open: always resolves, never rejects. */
export async function verifyWebBotAuth(opts: WbaVerifyOptions): Promise<WbaVerification> {
  const options = opts || ({} as WbaVerifyOptions);
  const nowMs = Number.isFinite(options.nowMs) ? (options.nowMs as number) : Date.now();
  const evidence: string[] = [];
  const finish = (status: WbaStatus, extra?: Partial<WbaVerification>): WbaVerification => ({
    status,
    verified: status === 'verified',
    operator: null,
    agentId: null,
    signerHost: null,
    keyId: null,
    keySource: null,
    ...extra,
    evidence: extra && extra.evidence ? [...evidence, ...extra.evidence] : [...evidence],
    checkedAtMs: nowMs,
  });

  try {
    const headers = options.headers || {};
    const parsed = parseWbaHeaders(headers);
    if (!parsed.present) return finish('absent');

    if (parsed.tag !== 'web-bot-auth') return finish('unsupported');
    evidence.push('wba.tag:web-bot-auth');

    const hasAgent = parsed.covered.includes('signature-agent');
    const hasAuthority = parsed.covered.includes('@authority') || parsed.covered.includes('@target-uri');
    if (!hasAgent || !hasAuthority) return finish('invalid', { evidence: ['wba.coverage:fail'] });
    evidence.push('wba.coverage:' + parsed.covered.join('+'));

    const createdMs = parsed.created === null ? NaN : parsed.created * 1000;
    const expiresMs = parsed.expires === null ? NaN : parsed.expires * 1000;
    if (!Number.isFinite(createdMs) || !Number.isFinite(expiresMs)) return finish('expired');
    // created <= now + 5s <= expires, with a hard 24h maximum signature lifetime.
    if (!(createdMs <= nowMs + 5_000 && nowMs + 5_000 <= expiresMs)) return finish('expired');
    if (expiresMs - createdMs > 86_400_000) return finish('expired');
    evidence.push('wba.time:valid');

    if (!parsed.signatureBytes || parsed.signatureBytes.length === 0 || !parsed.agentHost) {
      return finish('invalid');
    }
    if (parsed.keyId) evidence.push('wba.keyid:' + parsed.keyId);

    const trust = options.trust ?? WBA_TRUSTED_SIGNERS;
    const signer = trust.find((candidate) =>
      candidate.directoryHosts.some((host) => host.toLowerCase() === (parsed.agentHost as string).toLowerCase())
    );
    if (!signer) return finish('unknown_signer');

    const baseIdentity: Partial<WbaVerification> = {
      operator: signer.operator,
      agentId: signer.agentId,
      signerHost: parsed.agentHost,
      keyId: parsed.keyId || null,
    };

    const subtle = options.subtle ?? (globalThis.crypto && globalThis.crypto.subtle);
    if (!subtle || typeof subtle.verify !== 'function' || typeof subtle.importKey !== 'function') {
      return finish('unavailable', { ...baseIdentity, evidence: ['wba.crypto:unavailable'] });
    }

    // Obtain candidate public keys. A pinned-only signer (no directory) uses its pinned X values
    // directly; otherwise keys come from the well-known directory and are cached by URL.
    let keys: JwkLike[];
    let keySource: 'pinned' | 'directory';
    if (!signer.directoryUrl && signer.pinnedKeyX && signer.pinnedKeyX.length > 0) {
      keys = signer.pinnedKeyX.map((x, i) => {
        const key: JwkLike = { crv: 'Ed25519', kty: 'OKP', x };
        const kid = signer.pinnedKeyIds && signer.pinnedKeyIds[i];
        if (kid) {
          key.kid = kid;
          KID_BY_KEY.set(key, kid);
        }
        return key;
      });
      keySource = 'pinned';
    } else {
      const url = signer.directoryUrl || `https://${parsed.agentHost}/.well-known/http-message-signatures-directory`;
      const cache = options.cache;
      const cached = cache && cache.get(url);
      if (cached && cached.expiresAtMs > nowMs) {
        keys = cached.keys as JwkLike[];
      } else {
        const directory = await fetchDirectoryKeys(url, options.fetchDirectory);
        if (!directory) {
          return finish('unavailable', { ...baseIdentity, evidence: ['wba.directory:unavailable'] });
        }
        keys = directory.keys;
        if (cache) {
          cache.set(url, {
            keys: keys.map(({ crv, kty, x }) => ({ crv, kty, x })),
            fetchedAtMs: nowMs,
            expiresAtMs: nowMs + directory.ttlMs,
          });
        }
      }
      keySource = 'directory';
    }
    if (keys.length === 0) {
      return finish('unavailable', { ...baseIdentity, keySource, evidence: ['wba.keys:none'] });
    }

    // Compute thumbprints when possible (needed when keyid is a RFC 8037 thumbprint).
    const thumbprints = new Map<JwkLike, string>();
    if (typeof subtle.digest === 'function') {
      for (const key of keys) {
        try {
          thumbprints.set(key, await thumbprintWith(subtle, key));
        } catch {
          /* individual key cannot be thumbprinted; kid/x matching still applies */
        }
      }
    }

    let candidates: JwkLike[];
    if (parsed.keyId) {
      candidates = keys.filter((key) =>
        (key.kid && key.kid === parsed.keyId) ||
        thumbprints.get(key) === parsed.keyId
      );
      if (candidates.length === 0) {
        return finish('unavailable', { ...baseIdentity, keySource, evidence: ['wba.keyid:unmatched'] });
      }
    } else {
      candidates = keys; // no keyid → try every published key
    }

    if (signer.requirePinnedKey) {
      const pinnedX = new Set(signer.pinnedKeyX ?? []);
      const pinnedIds = new Set(signer.pinnedKeyIds ?? []);
      candidates = candidates.filter((key) =>
        pinnedX.has(key.x) ||
        (key.kid ? pinnedIds.has(key.kid) : false) ||
        (thumbprints.has(key) ? pinnedIds.has(thumbprints.get(key) as string) : false)
      );
      if (candidates.length === 0) {
        return finish('unknown_signer', { ...baseIdentity, keySource, evidence: ['wba.pinned:fail'] });
      }
    }

    const authority = resolveAuthority(options, headers);
    const base = buildSignatureBase(parsed, authority);
    if (!base) return finish('invalid', { ...baseIdentity, keySource });

    const message = new TextEncoder().encode(base);
    // Copy into a plain ArrayBuffer-backed view (WebCrypto's BufferSource rejects SharedArrayBuffer).
    const signature = new Uint8Array(parsed.signatureBytes.length);
    signature.set(parsed.signatureBytes);
    for (const key of candidates) {
      try {
        const cryptoKey = await subtle.importKey(
          'jwk',
          { kty: key.kty, crv: key.crv, x: key.x } as JsonWebKey,
          { name: 'Ed25519' },
          false,
          ['verify']
        );
        const ok = await subtle.verify('Ed25519', cryptoKey, signature, message);
        if (!ok) continue;
        // evidence already carries tag / coverage / time / keyid in that order.
        evidence.push('wba.verified:' + parsed.agentHost);
        return finish('verified', { ...baseIdentity, keySource });
      } catch {
        /* try the next key */
      }
    }
    return finish('invalid', { ...baseIdentity, keySource, evidence: ['wba.signature:invalid'] });
  } catch {
    return finish('invalid', { evidence: ['wba.error'] });
  }
}
