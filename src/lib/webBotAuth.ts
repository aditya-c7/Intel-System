/**
 * Web Bot Auth (RFC 9421 HTTP Message Signatures) verification helper.
 *
 * LOCKED CONSTRAINTS
 * - WebCrypto only. No third-party SDK, no Node APIs, no platform globals touched at import time.
 * - Pure where possible; the single async entry point receives injected `fetch` and `subtle`.
 * - Outcomes are exactly NEUTRAL (no signature / inconclusive), VALID, or INVALID(reason).
 *   An unverified request is never called "valid" and never called "malicious".
 *
 * Signature base (RS4): ASCII lines `"component": value\n`, final
 * `"@signature-params": <raw Signature-Input member value with label stripped>`, no trailing LF.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                                */
/* -------------------------------------------------------------------------- */

export type HeaderValue = string | readonly string[] | null | undefined;

export interface SignatureParams {
  created?: number;
  expires?: number;
  keyid?: string;
  tag?: string;
  alg?: string;
}

export interface ParsedWebBotAuth {
  present: boolean;
  label: string | null;
  /** Raw Signature-Input dictionary member value, with `label=` stripped. */
  rawInputValue: string | null;
  /** Ordered, lowercased covered component identifiers. */
  covered: string[];
  params: SignatureParams;
  signatureBytes: Uint8Array | null;
  /** Validated HTTPS Signature-Agent URL. */
  agentUrl: string | null;
  /** Exact serialized value to place in the `signature-agent` base line. */
  agentComponentValue: string | null;
  agentForm: 'legacy' | 'dictionary' | null;
  /** Structural parse error; null when parsing succeeded. */
  error: string | null;
}

export interface PolicyResult {
  ok: boolean;
  reason?: string;
}

export type VerificationState =
  | { state: 'absent'; reason?: string }
  | { state: 'parse_error'; reason: string }
  | { state: 'policy_error'; reason: string }
  | { state: 'unverified'; reason: string }
  | { state: 'signature_mismatch'; reason?: string }
  | {
      state: 'verified';
      keyid: string;
      agentUrl: string;
      directoryUrl: string;
      keySource: 'directory' | 'cache';
      verifiedAtMs: number;
    };

export type WebBotAuthOutcome =
  | { kind: 'NEUTRAL'; reason: string }
  | { kind: 'VALID'; keyid: string; agentUrl: string; directoryUrl: string; keySource: 'directory' | 'cache'; verifiedAtMs: number }
  | { kind: 'INVALID'; reason: string };

export interface Jwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

export interface CacheEntry {
  kind: 'keys' | 'negative';
  jwk?: Jwk;
  fetchedAtMs: number;
  /** Positive TTL or negative-cache TTL. Negative entries are always <= 5 minutes. */
  expiresAtMs: number;
}

export type DirectoryCache = Map<string, CacheEntry>;

/** Minimal WebCrypto surface so both browser `crypto.subtle` and injected shims fit. */
export interface SubtleLike {
  digest(algorithm: string, data: BufferSource): Promise<ArrayBuffer>;
  importKey(
    format: string,
    keyData: unknown,
    algorithm: unknown,
    extractable: boolean,
    keyUsages: string[],
  ): Promise<unknown>;
  verify(algorithm: string, key: unknown, signature: BufferSource, data: BufferSource): Promise<boolean>;
}

export interface FetchLikeResponse {
  ok?: boolean;
  status?: number;
  headers?: { get(name: string): string | null } | Record<string, string>;
  text(): Promise<string>;
}

export type FetchLike = (
  url: string,
  init?: { redirect?: string; signal?: unknown; headers?: Record<string, string> },
) => Promise<FetchLikeResponse | null | undefined>;

export interface VerifyWebBotAuthOptions {
  rawSignature: HeaderValue;
  rawInput: HeaderValue;
  rawAgent?: HeaderValue;
  /** Value of the `@authority` component (e.g. `api.example.com`). */
  authority?: string;
  nowMs?: number;
  fetch?: FetchLike;
  subtle?: SubtleLike;
  cache?: DirectoryCache;
  /** Defaults: 5000 ms, 65536 bytes, 100 keys. */
  timeoutMs?: number;
  maxDirectoryBytes?: number;
  maxDirectoryKeys?: number;
}

/* -------------------------------------------------------------------------- */
/* Pure string/byte primitives                                                 */
/* -------------------------------------------------------------------------- */

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const WELL_KNOWN_SUFFIX = '/.well-known/http-message-signatures-directory';
const ALLOWED_PARAMS = new Set(['created', 'expires', 'keyid', 'tag', 'alg']);

function isAscii(value: string): boolean {
  return !/[^\x00-\x7F]/.test(value);
}

function unquote(value: string): string | null {
  const v = value.trim();
  if (v.length < 2 || v[0] !== '"' || v[v.length - 1] !== '"') return null;
  let inner = v.slice(1, -1);
  if (/\\/.test(inner) && !/\\(["\\])/.test(inner.replace(/\\\\/g, ''))) return null;
  inner = inner.replace(/\\(["\\])/g, '$1');
  if (inner.includes('"') || /[\r\n]/.test(inner)) return null;
  return inner;
}

/** Split on a separator that is outside quoted strings and inner-list parentheses. */
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

function base64ToBytes(input: string): Uint8Array | null {
  const text = input.replace(/[\s\r\n]/g, '');
  if (!text || text.length % 4 === 1 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
  const clean = text.replace(/=+$/, '');
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < clean.length; i++) {
    const idx = B64.indexOf(clean[i]);
    if (idx < 0) return null;
    buffer = (buffer << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  // Reject non-zero trailing bits (non-canonical base64).
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null;
  return new Uint8Array(out);
}

function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? B64[b2 & 63] : '=';
  }
  return out;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function xBytes(x: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]{43}$/.test(x)) return null;
  return base64ToBytes(x.replace(/-/g, '+').replace(/_/g, '/'));
}

function headerText(value: HeaderValue): string | null {
  if (value == null) return null;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    if (value.length !== 1 || typeof value[0] !== 'string') return '__DUPLICATE__';
    return value[0];
  }
  return null;
}

function validHttpsUrl(raw: string): boolean {
  const candidate = raw.trim();
  if (!candidate || /\s/.test(candidate)) return false;
  if (!/^https:\/\//i.test(candidate)) return false;
  try {
    const url = new URL(candidate);
    if (url.protocol.toLowerCase() !== 'https:') return false;
    if (url.username !== '' || url.password !== '' || url.hash !== '') return false;
    if (!url.hostname) return false;
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Signature-Agent: legacy quoted string + draft dictionary form              */
/* -------------------------------------------------------------------------- */

function parseAgent(rawAgent: HeaderValue): Pick<ParsedWebBotAuth, 'agentUrl' | 'agentComponentValue' | 'agentForm' | 'error'> {
  const none = { agentUrl: null, agentComponentValue: null, agentForm: null, error: null } as const;
  if (rawAgent === undefined || rawAgent === null) return none;
  const head = headerText(rawAgent);
  if (head === '__DUPLICATE__') return { ...none, error: 'duplicate_signature_agent' };
  const text = (head ?? '').trim();
  if (!text) return { ...none, error: 'missing_signature_agent' };

  let url: string | null = null;
  let form: 'legacy' | 'dictionary' = 'legacy';

  if (text.startsWith('"') && text.endsWith('"')) {
    const matches = text.match(/"(?:[^"\\]|\\.)*"/g) ?? [];
    if (matches.length !== 1 || matches[0] !== text) {
      return { ...none, error: 'ambiguous_signature_agent' };
    }
    url = unquote(text);
    if (url === null) return { ...none, error: 'invalid_signature_agent' };
  } else {
    form = 'dictionary';
    const members = splitTopLevel(text, ',');
    for (const member of members) {
      const eq = member.indexOf('=');
      if (eq <= 0) continue;
      const firstValue = splitTopLevel(member.slice(eq + 1).trim(), ';')[0] ?? '';
      const candidate = unquote(firstValue);
      if (candidate !== null && validHttpsUrl(candidate)) {
        url = candidate;
        break;
      }
    }
    if (url === null) return { ...none, error: 'invalid_signature_agent' };
  }

  if (!validHttpsUrl(url)) return { ...none, error: 'invalid_signature_agent_url' };
  return { agentUrl: url, agentComponentValue: text, agentForm: form, error: null };
}

/* -------------------------------------------------------------------------- */
/* Pure helpers                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Parse Signature / Signature-Input / Signature-Agent structured fields.
 * Never throws. Duplicate labels, duplicate components and unknown params are rejected.
 */
export function parseSignatureHeaders(
  rawSignature: HeaderValue,
  rawInput: HeaderValue,
  rawAgent?: HeaderValue,
): ParsedWebBotAuth {
  const parsed: ParsedWebBotAuth = {
    present: false,
    label: null,
    rawInputValue: null,
    covered: [],
    params: {},
    signatureBytes: null,
    agentUrl: null,
    agentComponentValue: null,
    agentForm: null,
    error: null,
  };

  const sigHead = headerText(rawSignature);
  const inHead = headerText(rawInput);
  parsed.present = Boolean((sigHead && sigHead.trim()) || (inHead && inHead.trim()));
  if (!parsed.present) return parsed;

  const agent = parseAgent(rawAgent);
  parsed.agentUrl = agent.agentUrl;
  parsed.agentComponentValue = agent.agentComponentValue;
  parsed.agentForm = agent.agentForm;

  if (sigHead === null || inHead === null) {
    parsed.error = 'missing_signature_header';
    return parsed;
  }
  if (sigHead === '__DUPLICATE__' || inHead === '__DUPLICATE__') {
    parsed.error = 'duplicate_signature_header';
    return parsed;
  }
  if (agent.error && rawAgent !== undefined && rawAgent !== null) {
    parsed.error = agent.error;
    return parsed;
  }

  // --- Signature-Input: dictionary with exactly one label -> inner list + params.
  const inputMembers = splitTopLevel(inHead.trim(), ',');
  if (inputMembers.length !== 1) {
    parsed.error = inputMembers.length === 0 ? 'empty_signature_input' : 'duplicate_signature_label';
    return parsed;
  }
  const member = inputMembers[0];
  const eq = member.indexOf('=');
  if (eq <= 0) {
    parsed.error = 'invalid_signature_input';
    return parsed;
  }
  const label = member.slice(0, eq).trim();
  if (!/^[A-Za-z_!#$%&'*+.^_`|~0-9-]+$/.test(label)) {
    parsed.error = 'invalid_signature_label';
    return parsed;
  }
  parsed.label = label;
  const value = member.slice(eq + 1).trim();
  if (!value.startsWith('(')) {
    parsed.error = 'invalid_signature_input';
    return parsed;
  }
  const close = value.indexOf(')');
  if (close < 0) {
    parsed.error = 'invalid_signature_input';
    return parsed;
  }
  parsed.rawInputValue = value; // verbatim, label stripped (RFC 9421 §2.3)

  const coveredText = value.slice(1, close);
  const tokenPattern = /"(?:[^"\\]|\\.)*"/g;
  let cursor = 0;
  let tokenMatch: RegExpExecArray | null;
  while ((tokenMatch = tokenPattern.exec(coveredText)) !== null) {
    const token = tokenMatch[0];
    const gap = coveredText.slice(cursor, tokenMatch.index);
    if (gap.trim() !== '') {
      parsed.error = 'invalid_covered_component';
      return parsed;
    }
    const name = unquote(token);
    if (name === null || !name || !isAscii(name)) {
      parsed.error = 'invalid_covered_component';
      return parsed;
    }
    const lowered = name.toLowerCase();
    if (lowered === '@signature-params') {
      parsed.error = 'reserved_covered_component';
      return parsed;
    }
    if (parsed.covered.includes(lowered)) {
      parsed.error = 'duplicate_covered_component';
      return parsed;
    }
    parsed.covered.push(lowered);
    cursor = tokenMatch.index + token.length;
  }
  if (coveredText.slice(cursor).trim() !== '' || parsed.covered.length === 0) {
    parsed.error = 'invalid_covered_component';
    return parsed;
  }

  const tail = value.slice(close + 1).trim();
  if (tail && !tail.startsWith(';')) {
    parsed.error = 'invalid_signature_parameters';
    return parsed;
  }
  const seenParams = new Set<string>();
  for (const part of splitTopLevel(tail.replace(/^;/, ''), ';')) {
    const pi = part.indexOf('=');
    if (pi <= 0) {
      parsed.error = 'invalid_signature_parameters';
      return parsed;
    }
    const name = part.slice(0, pi).trim().toLowerCase() as keyof SignatureParams;
    const raw = part.slice(pi + 1).trim();
    if (!ALLOWED_PARAMS.has(name)) {
      parsed.error = `unknown_signature_param:${name}`;
      return parsed;
    }
    if (seenParams.has(name)) {
      parsed.error = `duplicate_signature_param:${name}`;
      return parsed;
    }
    seenParams.add(name);
    if (name === 'created' || name === 'expires') {
      if (!/^\d+$/.test(raw)) {
        parsed.error = `invalid_${name}`;
        return parsed;
      }
      parsed.params[name] = Number(raw);
    } else {
      const decoded = unquote(raw);
      if (decoded === null || !isAscii(decoded)) {
        parsed.error = `invalid_${name}`;
        return parsed;
      }
      parsed.params[name] = decoded;
    }
  }

  // --- Signature: dictionary label -> byte sequence `:base64:`.
  const sigMembers = splitTopLevel(sigHead.trim(), ',');
  if (sigMembers.length !== 1) {
    parsed.error = sigMembers.length === 0 ? 'empty_signature' : 'duplicate_signature_label';
    return parsed;
  }
  const sigPart = sigMembers[0];
  const sep = sigPart.indexOf('=');
  if (sep <= 0) {
    parsed.error = 'invalid_signature';
    return parsed;
  }
  const sigLabel = sigPart.slice(0, sep).trim();
  if (sigLabel !== label) {
    parsed.error = 'signature_label_mismatch';
    return parsed;
  }
  const sigValue = sigPart.slice(sep + 1).trim();
  if (sigValue.length < 2 || sigValue[0] !== ':' || sigValue[sigValue.length - 1] !== ':') {
    parsed.error = 'signature_not_byte_sequence';
    return parsed;
  }
  const bytes = base64ToBytes(sigValue.slice(1, -1));
  if (!bytes) {
    parsed.error = 'invalid_signature_base64';
    return parsed;
  }
  parsed.signatureBytes = bytes;
  return parsed;
}

/**
 * Build the RS4 signature base. Each covered component contributes one ASCII line; the final
 * line carries the raw Signature-Input member value. There is deliberately NO trailing LF.
 */
export function buildSignatureBase(
  input: ParsedWebBotAuth,
  components: Record<string, string | undefined>,
): string | null {
  if (!input || !input.rawInputValue || input.covered.length === 0) return null;
  if (!components || typeof components !== 'object') return null;
  if (!isAscii(input.rawInputValue)) return null;
  const lines: string[] = [];
  for (const name of input.covered) {
    if (!/^[a-z0-9@_-]+$/.test(name) || !isAscii(name)) return null;
    const value = components[name];
    if (value === undefined || value === null || !isAscii(value) || /[\r\n]/.test(value)) return null;
    lines.push(`"${name}": ${value}`);
  }
  lines.push(`"@signature-params": ${input.rawInputValue}`);
  const base = lines.join('\n');
  return isAscii(base) ? base : null;
}

/** RFC 8037 JWK thumbprint: base64url(SHA-256(`{"crv":"Ed25519","kty":"OKP","x":"..."}`)), no padding. */
export async function jwkThumbprint(x: string, subtle?: SubtleLike): Promise<string> {
  if (typeof x !== 'string' || x.length === 0) throw new Error('invalid_jwk_x');
  const canonical = '{"crv":"Ed25519","kty":"OKP","x":' + JSON.stringify(x) + '}';
  const crypto = subtle ?? getGlobalSubtle();
  if (!crypto) throw new Error('crypto_unavailable');
  const digest = await crypto.digest('SHA-256', new TextEncoder().encode(canonical));
  return bytesToBase64Url(new Uint8Array(digest));
}

/** Pure policy gate. Enforces alg, tag, required params, time window and coverage. */
export function enforcePolicy(parsed: ParsedWebBotAuth, nowMs: number): PolicyResult {
  if (!parsed || !parsed.present) return { ok: false, reason: 'no_signature' };
  if (parsed.error) return { ok: false, reason: parsed.error };
  const p = parsed.params;
  if (p.alg !== 'ed25519') return { ok: false, reason: 'unsupported_alg' };
  if (p.tag !== 'web-bot-auth') return { ok: false, reason: 'invalid_tag' };
  if (typeof p.created !== 'number' || typeof p.expires !== 'number' || typeof p.keyid !== 'string') {
    return { ok: false, reason: 'missing_required_param' };
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(p.keyid)) return { ok: false, reason: 'invalid_keyid_format' };
  if (!Number.isFinite(nowMs)) return { ok: false, reason: 'invalid_now' };
  if (p.expires < p.created) return { ok: false, reason: 'expires_before_created' };
  const nowSec = Math.floor(nowMs / 1000);
  if (!(p.created <= nowSec && nowSec <= p.expires)) return { ok: false, reason: 'outside_validity_window' };
  if (!parsed.covered.includes('@authority') || !parsed.covered.includes('signature-agent')) {
    return { ok: false, reason: 'missing_covered_component' };
  }
  if (!parsed.agentUrl) return { ok: false, reason: 'invalid_signature_agent' };
  if (!parsed.signatureBytes || parsed.signatureBytes.length !== 64) {
    return { ok: false, reason: 'invalid_signature_length' };
  }
  return { ok: true };
}

/** Map internal verification state to the only three allowed outcomes. Pure and total. */
export function resolveOutcome(state: VerificationState): WebBotAuthOutcome {
  switch (state.state) {
    case 'absent':
      return { kind: 'NEUTRAL', reason: state.reason ?? 'no_signature' };
    case 'unverified':
      return { kind: 'NEUTRAL', reason: state.reason };
    case 'parse_error':
    case 'policy_error':
    case 'signature_mismatch':
      return { kind: 'INVALID', reason: state.reason ?? 'signature_mismatch' };
    case 'verified':
      return {
        kind: 'VALID',
        keyid: state.keyid,
        agentUrl: state.agentUrl,
        directoryUrl: state.directoryUrl,
        keySource: state.keySource,
        verifiedAtMs: state.verifiedAtMs,
      };
  }
}

/* -------------------------------------------------------------------------- */
/* Directory fetch helpers                                                     */
/* -------------------------------------------------------------------------- */

function getGlobalSubtle(): SubtleLike | null {
  const c = (globalThis as { crypto?: { subtle?: SubtleLike } }).crypto;
  return c && c.subtle ? c.subtle : null;
}

function responseHeader(headers: FetchLikeResponse['headers'], name: string): string | null {
  if (!headers) return null;
  const getter = (headers as { get?: (n: string) => string | null }).get;
  if (typeof getter === 'function') return getter.call(headers, name) ?? null;
  const record = headers as Record<string, string>;
  const key = Object.keys(record).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? record[key] : null;
}

function timeoutSignal(ms: number): { signal: unknown; cancel(): void } {
  if (typeof AbortController === 'undefined') return { signal: undefined, cancel() {} };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

function cacheKey(url: string, keyid: string): string {
  return `${url}\u0000${keyid}`;
}

function ttlFromCacheControl(header: string | null, nowMs: number): number {
  const match = /(?:s-maxage|max-age)\s*=\s*"?(\d+)"?/i.exec(header ?? '');
  const seconds = match ? Number(match[1]) : 300;
  const ttl = Number.isFinite(seconds) ? Math.min(86_400_000, Math.max(30_000, seconds * 1000)) : 300_000;
  return nowMs + ttl;
}

function sanitizeJwk(raw: unknown): Jwk | null {
  if (!raw || typeof raw !== 'object') return null;
  const record = raw as Record<string, unknown>;
  if (record.kty !== 'OKP' || record.crv !== 'Ed25519' || typeof record.x !== 'string') return null;
  if (!xBytes(record.x)) return null;
  return { kty: 'OKP', crv: 'Ed25519', x: record.x };
}

async function verifyEd25519(
  subtle: SubtleLike,
  jwk: Jwk,
  signature: Uint8Array,
  base: string,
): Promise<boolean> {
  try {
    const key = await subtle.importKey(
      'jwk',
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const copy = new Uint8Array(signature.length);
    copy.set(signature);
    return await subtle.verify('Ed25519', key, copy, new TextEncoder().encode(base));
  } catch {
    return false;
  }
}

type KeyLookup =
  | { ok: true; jwk: Jwk; keySource: 'directory' | 'cache' }
  | { ok: false; reason: string };

/**
 * Fetch + authenticate a directory key. Cache key is (URL, keyid); all published keys are cached
 * so old keyids survive a rotation overlap. A transient fetch failure never evicts a cached key;
 * negative results are cached for at most five minutes.
 */
async function fetchDirectoryKey(
  url: string,
  keyid: string,
  opts: Required<Pick<VerifyWebBotAuthOptions, 'nowMs' | 'timeoutMs' | 'maxDirectoryBytes' | 'maxDirectoryKeys' | 'subtle'>> &
    Pick<VerifyWebBotAuthOptions, 'fetch' | 'cache'>,
): Promise<KeyLookup> {
  const cache = opts.cache;
  const ck = cacheKey(url, keyid);
  const cached = cache?.get(ck);
  if (cached?.kind === 'keys' && cached.expiresAtMs > opts.nowMs) {
    return { ok: true, jwk: cached.jwk as Jwk, keySource: 'cache' };
  }
  if (cached?.kind === 'negative' && cached.expiresAtMs > opts.nowMs) {
    return { ok: false, reason: 'directory_negative_cache' };
  }

  const { signal, cancel } = timeoutSignal(opts.timeoutMs);
  try {
    const fetcher = opts.fetch ?? (globalThis as { fetch?: FetchLike }).fetch;
    if (typeof fetcher !== 'function') throw new Error('fetch_unavailable');
    const response = await fetcher(url, { redirect: 'error', signal });
    if (!response || response.ok === false || (typeof response.status === 'number' && response.status >= 400)) {
      throw new Error('directory_fetch_failed');
    }
    const declaredLength = responseHeader(response.headers, 'content-length');
    if (declaredLength && Number(declaredLength) > opts.maxDirectoryBytes) throw new Error('directory_too_large');
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > opts.maxDirectoryBytes) throw new Error('directory_too_large');

    const digestHeader = responseHeader(response.headers, 'content-digest');
    if (!digestHeader) throw new Error('missing_content_digest');
    const bodyDigest = bytesToBase64(new Uint8Array(await opts.subtle.digest('SHA-256', new TextEncoder().encode(body))));
    const digestMatch = /(?:^|,)\s*sha-256\s*=\s*:([^:]*):/i.exec(digestHeader);
    if (!digestMatch || digestMatch[1] !== bodyDigest) throw new Error('content_digest_mismatch');

    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch {
      throw new Error('invalid_directory_json');
    }
    const keys = (json as { keys?: unknown })?.keys;
    if (!Array.isArray(keys)) throw new Error('invalid_directory_json');
    if (keys.length > opts.maxDirectoryKeys) throw new Error('too_many_directory_keys');

    const byKid = new Map<string, Jwk>();
    for (const raw of keys) {
      const jwk = sanitizeJwk(raw);
      if (!jwk) continue;
      byKid.set(await jwkThumbprint(jwk.x, opts.subtle), jwk);
    }
    if (byKid.size === 0) throw new Error('no_valid_directory_keys');

    // Possession proof: the directory's own HTTP Message Signature (tag
    // http-message-signatures-directory) must verify under a key it publishes.
    const dirSig = responseHeader(response.headers, 'signature') ?? '';
    const dirInput = responseHeader(response.headers, 'signature-input') ?? '';
    const dirParsed = parseSignatureHeaders(dirSig, dirInput, undefined);
    if (dirParsed.error || !dirParsed.present) throw new Error('missing_directory_signature');
    if (dirParsed.params.tag !== 'http-message-signatures-directory') {
      throw new Error('invalid_directory_signature_tag');
    }
    let authority: string;
    try {
      authority = new URL(url).host;
    } catch {
      throw new Error('invalid_directory_url');
    }
    const dirBase = buildSignatureBase(dirParsed, { '@authority': authority, 'content-digest': digestHeader });
    if (!dirBase || !dirParsed.signatureBytes) throw new Error('directory_signature_base_unavailable');
    const claimed = dirParsed.params.keyid;
    const candidates = claimed && byKid.has(claimed) ? [byKid.get(claimed) as Jwk] : Array.from(byKid.values());
    let possessed = false;
    for (const candidate of candidates) {
      if (await verifyEd25519(opts.subtle, candidate, dirParsed.signatureBytes, dirBase)) {
        possessed = true;
        break;
      }
    }
    if (!possessed) throw new Error('directory_possession_proof_failed');

    const expiresAtMs = ttlFromCacheControl(responseHeader(response.headers, 'cache-control'), opts.nowMs);
    for (const [kid, jwk] of byKid) {
      cache?.set(cacheKey(url, kid), { kind: 'keys', jwk, fetchedAtMs: opts.nowMs, expiresAtMs });
    }
    const wanted = byKid.get(keyid);
    if (!wanted) return { ok: false, reason: 'keyid_not_published' };
    return { ok: true, jwk: wanted, keySource: 'directory' };
  } catch (error) {
    // Normalize unexpected throwables to a stable reason; never leak raw error text into an outcome.
    const known = new Set([
      'fetch_unavailable', 'directory_fetch_failed', 'directory_too_large', 'missing_content_digest',
      'content_digest_mismatch', 'invalid_directory_json', 'too_many_directory_keys',
      'no_valid_directory_keys', 'missing_directory_signature', 'invalid_directory_signature_tag',
      'invalid_directory_url', 'directory_signature_base_unavailable', 'directory_possession_proof_failed',
    ]);
    const message = error instanceof Error ? error.message : '';
    const reason = known.has(message) ? message : 'directory_fetch_failed';
    // Stale-if-error: a transient failure must not evict a key we already validated.
    if (cached?.kind === 'keys' && cached.jwk) {
      return { ok: true, jwk: cached.jwk, keySource: 'cache' };
    }
    cache?.set(ck, {
      kind: 'negative',
      fetchedAtMs: opts.nowMs,
      expiresAtMs: opts.nowMs + 60_000, // negative cache: 1 min (<= 5 min)
    });
    return { ok: false, reason };
  } finally {
    cancel();
  }
}

export function directoryUrlFor(agentUrl: string): string {
  const url = new URL(agentUrl);
  const path = url.pathname.replace(/\/+$/, '');
  if (path !== WELL_KNOWN_SUFFIX) url.pathname = path + WELL_KNOWN_SUFFIX;
  url.hash = '';
  return url.toString();
}

/* -------------------------------------------------------------------------- */
/* Async verification entry point                                              */
/* -------------------------------------------------------------------------- */

/** Verify a Web Bot Auth request. Never throws; always returns NEUTRAL, VALID, or INVALID. */
export async function verifyWebBotAuthRequest(opts: VerifyWebBotAuthOptions): Promise<WebBotAuthOutcome> {
  const options = opts ?? ({} as VerifyWebBotAuthOptions);
  const nowMs = Number.isFinite(options.nowMs) ? (options.nowMs as number) : Date.now();
  try {
    const parsed = parseSignatureHeaders(options.rawSignature, options.rawInput, options.rawAgent);
    if (!parsed.present) return resolveOutcome({ state: 'absent' });
    const policy = enforcePolicy(parsed, nowMs);
    if (!policy.ok) return resolveOutcome({ state: 'policy_error', reason: policy.reason ?? 'policy_failed' });

    const subtle = options.subtle ?? getGlobalSubtle();
    if (!subtle) return resolveOutcome({ state: 'unverified', reason: 'crypto_unavailable' });

    const authority = options.authority ?? '';
    if (!authority || !isAscii(authority)) return resolveOutcome({ state: 'policy_error', reason: 'invalid_authority' });
    const base = buildSignatureBase(parsed, {
      '@authority': authority,
      'signature-agent': parsed.agentComponentValue as string,
    });
    if (!base) return resolveOutcome({ state: 'policy_error', reason: 'signature_base_unavailable' });

    const agentUrl = parsed.agentUrl as string;
    const keyid = parsed.params.keyid as string;
    const directoryUrl = directoryUrlFor(agentUrl);
    const lookup = await fetchDirectoryKey(directoryUrl, keyid, {
      nowMs,
      subtle,
      fetch: options.fetch,
      cache: options.cache,
      timeoutMs: Number.isFinite(options.timeoutMs) ? (options.timeoutMs as number) : 5000,
      maxDirectoryBytes: Number.isFinite(options.maxDirectoryBytes) ? (options.maxDirectoryBytes as number) : 65_536,
      maxDirectoryKeys: Number.isFinite(options.maxDirectoryKeys) ? (options.maxDirectoryKeys as number) : 100,
    });
    if (!lookup.ok) return resolveOutcome({ state: 'unverified', reason: lookup.reason });

    const valid = await verifyEd25519(subtle, lookup.jwk, parsed.signatureBytes as Uint8Array, base);
    if (!valid) return resolveOutcome({ state: 'signature_mismatch' });
    return resolveOutcome({
      state: 'verified',
      keyid,
      agentUrl,
      directoryUrl,
      keySource: lookup.keySource,
      verifiedAtMs: nowMs,
    });
  } catch {
    return resolveOutcome({ state: 'unverified', reason: 'verification_error' });
  }
}

/** Alias kept short for callers that prefer the canonical name. */
export const verifyWebBotAuth = verifyWebBotAuthRequest;
