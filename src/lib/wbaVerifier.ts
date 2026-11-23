/**
 * Web Bot Auth (RFC 9421 HTTP Message Signatures) verifier facade.
 *
 * ALL cryptographic work is delegated to the vendored, pure helper `src/lib/webBotAuth.ts`:
 * byte-identical RFC 9421 signature base (NO trailing LF), structured-field parsing, RFC 8037
 * keyid thumbprints, ED25519 verification, Signature-Agent bare-origin + dictionary support,
 * Content-Digest + directory possession proof, and the NEUTRAL / VALID / INVALID tri-state.
 * Nothing in this file re-implements a signature base or a key lookup — that is where the old
 * verifier diverged from the spec (trailing LF, unproven directories, two anchors only).
 *
 * This facade adds only:
 *   - operator TRUST ANCHORS (an unverified Signature-Agent host is never fetched, so this is
 *     also the SSRF boundary);
 *   - mapping the helper's tri-state outcome onto the legacy `WbaStatus` vocabulary;
 *   - additive proof fields (`reason`, `identity`, `verification_method`, `category`, `outcome`)
 *     for the server / `composeBotVerdict` to consume;
 *   - a BOUNDED in-memory result cache keyed by a signature nonce. Expiry is lazy on insert —
 *     no Durable Object alarms, no timers, no platform state at import time.
 *
 * Fail-open contract is unchanged: `verifyWebBotAuth` never throws and never rejects a visitor.
 */

import {
  buildSignatureBase as buildHelperSignatureBase,
  directoryUrlFor,
  jwkThumbprint,
  parseSignatureHeaders,
  verifyWebBotAuthRequest,
  type DirectoryCache,
  type FetchLike,
  type HeaderValue,
  type ParsedWebBotAuth,
  type SubtleLike,
  type WebBotAuthOutcome,
} from './webBotAuth';

/* -------------------------------------------------------------------------- */
/* Public types (legacy surface kept, additive fields marked)                  */
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
  /** Additive: exact Signature-Agent component value used in the signature base. */
  agentComponentValue?: string | null;
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
  /* --- additive, non-escalating proof fields for server consumers --- */
  /** Proof reason: `signed-agent` / `verified-agent` / `no_signature` / `<tri-state reason>`. */
  reason?: string | null;
  /** WBA identity grade. A verified ED25519 signature is always `signed`. */
  identity?: 'signed' | 'verified' | 'unknown' | 'spoofed' | null;
  /** How the identity was proven: `rfc9421` / `page_attestation` / `none`. */
  verification_method?: 'rfc9421' | 'signed_agent' | 'page_attestation' | 'none' | null;
  /** Agent category carried by the trust anchor (`ai_agent` / `ai_assistant` / …). */
  category?: string | null;
  /** The helper's tri-state outcome, published verbatim. */
  outcome?: 'NEUTRAL' | 'VALID' | 'INVALID' | null;
  /** Directory URL that supplied the key (additive telemetry). */
  directoryUrl?: string | null;
}

export interface WbaTrustedSigner {
  agentId: string;
  operator: string;
  directoryHosts: readonly string[];
  /** Additive: first-party subdomain suffixes (e.g. `.bot.goog`). Never a public suffix. */
  directoryHostSuffixes?: readonly string[];
  /** Additive: category published as a proof field. */
  category?: string;
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
  /** Legacy fetch hook. Return the well-known directory body; include full headers to satisfy
   * the directory Content-Digest + possession-proof checks in `webBotAuth.ts`. */
  fetchDirectory?: (url: string) => Promise<{
    body: string;
    cacheControl?: string;
    headers?: Record<string, string>;
  } | null>;
  /** Legacy directory cache (accepted for API compatibility). */
  cache?: Map<string, { keys: Array<{ crv: string; kty: string; x: string }>; fetchedAtMs: number; expiresAtMs: number }>;
  /** Native helper cache, when a caller wants cross-request key reuse. */
  directoryCache?: DirectoryCache;
  subtle?: SubtleCrypto;
}

/* -------------------------------------------------------------------------- */
/* Trust anchors                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Allowlisted first-party Web Bot Auth signers. A signature is verified ONLY against a key
 * published in the signer's own `.well-known/http-message-signatures-directory`, and the helper
 * authenticates that directory with Content-Digest + a possession signature before using it.
 * Host matching is exact (plus explicitly listed first-party suffixes) — never a cloud ASN.
 */
export const WBA_TRUSTED_SIGNERS: readonly WbaTrustedSigner[] = [
  {
    agentId: 'manus_bot',
    operator: 'Manus',
    directoryHosts: ['api.manus.im', 'manus.im', 'manus.ai'],
    category: 'ai_agent',
    requirePinnedKey: false,
    directoryUrl: 'https://api.manus.im/.well-known/http-message-signatures-directory',
  },
  {
    agentId: 'grok_agent',
    operator: 'xAI',
    directoryHosts: ['cursorusercontent.com'],
    category: 'ai_agent',
    requirePinnedKey: true,
    pinnedKeyX: ['STDZXOMW-Cg7paRpv_BtjujEHIQVNbzidfjY9M9w6hc'],
    pinnedKeyIds: ['Vuxu4khgzIe0b30Nd6hq2envAuVBFMTDqorSNIUb_Oo'],
    directoryUrl: 'https://cursorusercontent.com/.well-known/http-message-signatures-directory',
  },
  /* --- P0-5 report anchors --- */
  {
    agentId: 'google_agent',
    operator: 'Google',
    // Google publishes a bare-origin Signature-Agent (`https://agent.bot.goog`).
    directoryHosts: ['agent.bot.goog'],
    directoryHostSuffixes: ['.bot.goog'],
    category: 'ai_agent',
  },
  {
    agentId: 'openai_agent',
    operator: 'OpenAI',
    directoryHosts: ['openai.com', 'chatgpt.com'],
    category: 'ai_agent',
  },
  {
    agentId: 'anthropic_agent',
    operator: 'Anthropic',
    directoryHosts: ['anthropic.com', 'claude.ai'],
    category: 'ai_agent',
  },
  {
    agentId: 'cloudflare_agent',
    operator: 'Cloudflare',
    directoryHosts: ['cloudflare.com'],
    category: 'ai_agent',
  },
  {
    agentId: 'perplexity_agent',
    operator: 'Perplexity',
    directoryHosts: ['perplexity.ai', 'perplexity.com', 'www.perplexity.com'],
    category: 'ai_agent',
  },
  {
    agentId: 'mistral_agent',
    operator: 'Mistral',
    directoryHosts: ['mistral.ai'],
    category: 'ai_agent',
  },
];

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

type WbaHeaders = Record<string, string | string[] | undefined>;

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

/** Preserve duplicate header arrays so `webBotAuth.ts` can reject them as ambiguous. */
function asHeaderValue(values: string[]): HeaderValue {
  if (values.length === 0) return null;
  if (values.length === 1) return values[0];
  return values;
}

function hostFromAgentUrl(agentUrl: string | null): string | null {
  if (!agentUrl) return null;
  try {
    return new URL(agentUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function matchesTrustAnchor(signer: WbaTrustedSigner, host: string): boolean {
  const lower = host.toLowerCase();
  if (signer.directoryHosts.some((candidate) => candidate.toLowerCase() === lower)) return true;
  return (signer.directoryHostSuffixes ?? []).some(
    (suffix) => suffix.length > 1 && lower.endsWith(suffix.toLowerCase()),
  );
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

/** Adapt the legacy `fetchDirectory` hook to the helper's FetchLike. Full headers (including
 * Content-Digest and the directory Signature / Signature-Input) must be supplied by the caller;
 * a body-only hook deliberately fails closed because the directory cannot be authenticated. */
function toFetchLike(hook: WbaVerifyOptions['fetchDirectory']): FetchLike | undefined {
  if (typeof hook !== 'function') return undefined;
  return async (url) => {
    const response = await hook(url);
    if (!response || typeof response.body !== 'string') return null;
    const headers: Record<string, string> = { ...(response.headers ?? {}) };
    if (response.cacheControl && !headers['cache-control']) headers['cache-control'] = response.cacheControl;
    return {
      ok: true,
      status: 200,
      headers,
      text: async () => response.body,
    };
  };
}

/* --- bounded, in-memory result cache keyed by a signature nonce (no DO alarms) --- */

const NONCE_CACHE_LIMIT = 2_048;
const NONCE_TTL_UNVERIFIED_MS = 60_000;
const NONCE_TTL_VERIFIED_MAX_MS = 3_600_000;

interface NonceEntry {
  result: WbaVerification;
  expiresAtMs: number;
}

/** Module-local and bounded: Workers isolate resets it, and lazy pruning bounds memory. */
const nonceCache = new Map<string, NonceEntry>();

function fnv1a(text: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function signatureNonce(headers: WbaHeaders, authority: string): string {
  const parts = ['signature', 'signature-input', 'signature-agent']
    .map((name) => headerValues(headers, name).join('\u0000'))
    .join('\u0001');
  const combined = `${authority}\u0001${parts}`;
  return `${fnv1a(combined).toString(36)}.${fnv1a(combined.split('').reverse().join('')).toString(36)}`;
}

function cachedResult(nonce: string, nowMs: number): WbaVerification | null {
  const entry = nonceCache.get(nonce);
  if (!entry) return null;
  if (entry.expiresAtMs <= nowMs) {
    nonceCache.delete(nonce);
    return null;
  }
  return { ...entry.result, evidence: [...entry.result.evidence] };
}

function rememberResult(nonce: string, result: WbaVerification, ttlMs: number, nowMs: number): void {
  // Lazy expiry — no timers and no Durable Object alarms.
  for (const [key, entry] of nonceCache) {
    if (entry.expiresAtMs <= nowMs) nonceCache.delete(key);
  }
  while (nonceCache.size >= NONCE_CACHE_LIMIT) {
    const oldest = nonceCache.keys().next();
    if (oldest.done) break;
    nonceCache.delete(oldest.value);
  }
  nonceCache.set(nonce, {
    result: { ...result, evidence: [...result.evidence] },
    expiresAtMs: nowMs + Math.max(1, Math.min(ttlMs, NONCE_TTL_VERIFIED_MAX_MS)),
  });
}

/* -------------------------------------------------------------------------- */
/* Public parsing / base helpers (delegating to the vendored helper)           */
/* -------------------------------------------------------------------------- */

/**
 * Parse the three Web Bot Auth headers. Structured-field parsing is owned by `webBotAuth.ts`,
 * so this stays a pure projection onto the legacy `WbaParsed` surface. Never throws.
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
    agentComponentValue: null,
  };
  try {
    const bag = headers || {};
    const helper = parseSignatureHeaders(
      asHeaderValue(headerValues(bag, 'signature')),
      asHeaderValue(headerValues(bag, 'signature-input')),
      asHeaderValue(headerValues(bag, 'signature-agent')),
    );
    if (!helper.present) return parsed;
    parsed.present = true;
    parsed.label = helper.label ?? '';
    parsed.keyId = helper.params.keyid ?? '';
    parsed.tag = helper.params.tag ?? '';
    parsed.created = typeof helper.params.created === 'number' ? helper.params.created : null;
    parsed.expires = typeof helper.params.expires === 'number' ? helper.params.expires : null;
    parsed.covered = [...helper.covered];
    parsed.rawSignatureInput = helper.rawInputValue ?? '';
    parsed.signatureBytes = helper.signatureBytes;
    parsed.agentHost = hostFromAgentUrl(helper.agentUrl);
    parsed.agentOrigin = helper.agentUrl ? new URL(helper.agentUrl).origin : null;
    parsed.agentComponentValue = helper.agentComponentValue;
  } catch {
    /* projection is best-effort; malformed input stays empty */
  }
  return parsed;
}

/** RFC 8037 canonical JWK thumbprint, delegated to the vendored helper. */
export async function computeJwkThumbprint(jwk: { crv: string; kty: string; x: string }): Promise<string> {
  return jwkThumbprint(jwk.x);
}

/**
 * Build the RFC 9421 signature base for the covered components we can synthesize. The helper
 * emits the byte-exact RS4 layout with NO trailing LF and the raw Signature-Input member value.
 */
export function buildSignatureBase(parsed: WbaParsed, authority: string): string | null {
  if (!parsed || !parsed.rawSignatureInput || parsed.covered.length === 0) return null;
  const helperInput = {
    rawInputValue: parsed.rawSignatureInput,
    covered: parsed.covered,
  } as ParsedWebBotAuth;
  const components: Record<string, string> = { '@authority': authority };
  if (parsed.covered.includes('signature-agent')) {
    components['signature-agent'] = parsed.agentComponentValue ?? '';
  }
  return buildHelperSignatureBase(helperInput, components);
}

/* -------------------------------------------------------------------------- */
/* Verification                                                               */
/* -------------------------------------------------------------------------- */

function mapStatus(outcome: WebBotAuthOutcome): { status: WbaStatus; reason: string; neutral: boolean } {
  if (outcome.kind === 'VALID') {
    return { status: 'verified', reason: 'signed-agent', neutral: false };
  }
  const reason = outcome.reason;
  if (outcome.kind === 'NEUTRAL') {
    if (reason === 'no_signature') return { status: 'absent', reason, neutral: true };
    return { status: 'unavailable', reason, neutral: true };
  }
  if (/(^|_)(expired|outside_validity_window|invalid_created|invalid_expires)$/.test(reason)) {
    return { status: 'expired', reason, neutral: false };
  }
  if (/unsupported_alg|invalid_tag/.test(reason)) {
    return { status: 'unsupported', reason, neutral: false };
  }
  return { status: 'invalid', reason, neutral: false };
}

/** Verify a Web Bot Auth signature. Fail-open: always resolves, never rejects. */
export async function verifyWebBotAuth(opts: WbaVerifyOptions): Promise<WbaVerification> {
  const options = opts ?? ({} as WbaVerifyOptions);
  const nowMs = Number.isFinite(options.nowMs) ? (options.nowMs as number) : Date.now();
  const headers = options.headers ?? {};
  const authority = resolveAuthority(options, headers);
  const evidence: string[] = [];

  const finish = (status: WbaStatus, extra?: Partial<WbaVerification>): WbaVerification => ({
    status,
    verified: status === 'verified',
    operator: null,
    agentId: null,
    signerHost: null,
    keyId: null,
    keySource: null,
    checkedAtMs: nowMs,
    identity: status === 'verified' ? 'signed' : 'unknown',
    verification_method: status === 'verified' ? 'rfc9421' : 'none',
    reason: null,
    category: null,
    outcome: null,
    directoryUrl: null,
    ...extra,
    evidence: [...evidence, ...(extra?.evidence ?? [])],
  });

  try {
    const rawSignature = asHeaderValue(headerValues(headers, 'signature'));
    const rawInput = asHeaderValue(headerValues(headers, 'signature-input'));
    const rawAgent = asHeaderValue(headerValues(headers, 'signature-agent'));

    const parsed = parseSignatureHeaders(rawSignature, rawInput, rawAgent);
    const nonce = signatureNonce(headers, authority);
    const cached = cachedResult(nonce, nowMs);
    if (cached) return cached;

    if (!parsed.present) {
      return finish('absent', {
        reason: 'no_signature',
        outcome: 'NEUTRAL',
        evidence: ['wba.absent'],
      });
    }
    if (parsed.error || !parsed.agentUrl || !parsed.signatureBytes) {
      const reason = parsed.error ?? 'invalid_signature';
      return finish('invalid', {
        reason,
        outcome: 'INVALID',
        keyId: parsed.params.keyid ?? null,
        evidence: [`wba.parse:${reason}`],
      });
    }

    /* Trust boundary: only an allowlisted, first-party Signature-Agent host is ever fetched. */
    const trust = options.trust ?? WBA_TRUSTED_SIGNERS;
    const agentHost = hostFromAgentUrl(parsed.agentUrl);
    const signer = agentHost ? trust.find((candidate) => matchesTrustAnchor(candidate, agentHost)) : undefined;
    if (!signer) {
      return finish('unknown_signer', {
        reason: 'unknown_signer',
        outcome: 'INVALID',
        signerHost: agentHost,
        keyId: parsed.params.keyid ?? null,
        evidence: ['wba.signer:unknown'],
      });
    }

    const subtle = options.subtle ?? (globalThis.crypto && globalThis.crypto.subtle);
    if (!subtle || typeof (subtle as unknown as SubtleLike).verify !== 'function') {
      return finish('unavailable', {
        reason: 'crypto_unavailable',
        outcome: 'NEUTRAL',
        signerHost: agentHost,
        keyId: parsed.params.keyid ?? null,
        evidence: ['wba.crypto:unavailable'],
      });
    }
    if (!authority) {
      return finish('invalid', {
        reason: 'invalid_authority',
        outcome: 'INVALID',
        signerHost: agentHost,
        evidence: ['wba.authority:missing'],
      });
    }

    const baseIdentity: Partial<WbaVerification> = {
      operator: signer.operator,
      agentId: signer.agentId,
      signerHost: agentHost,
      keyId: parsed.params.keyid ?? null,
      category: signer.category ?? null,
    };

    const outcome = await verifyWebBotAuthRequest({
      rawSignature,
      rawInput,
      rawAgent,
      authority,
      nowMs,
      subtle: subtle as unknown as SubtleLike,
      fetch: toFetchLike(options.fetchDirectory),
      cache: options.directoryCache ?? new Map<unknown, unknown>() as DirectoryCache,
    });

    const mapped = mapStatus(outcome);
    const baseEvidence = [
      ...(parsed.params.tag ? [`wba.tag:${parsed.params.tag}`] : []),
      `wba.coverage:${parsed.covered.join('+')}`,
      `wba.keyid:${parsed.params.keyid ?? 'none'}`,
    ];

    if (mapped.status === 'verified' && outcome.kind === 'VALID') {
      // Pinned anchors stay pinned. The helper matches `keyid` by RFC 8037 thumbprint, so a
      // verified keyid is the pinned key iff it equals a pinned key id or a pinned thumbprint.
      let keySource: WbaVerification['keySource'] = 'directory';
      if (signer.requirePinnedKey) {
        const pinned = new Set<string>(signer.pinnedKeyIds ?? []);
        for (const x of signer.pinnedKeyX ?? []) {
          try {
            pinned.add(await jwkThumbprint(x, subtle as unknown as SubtleLike));
          } catch {
            /* a bad pinned value simply cannot match */
          }
        }
        if (!parsed.params.keyid || !pinned.has(parsed.params.keyid)) {
          const failed = finish('unknown_signer', {
            ...baseIdentity,
            reason: 'wba.pinned:fail',
            outcome: 'INVALID',
            evidence: [...baseEvidence, 'wba.pinned:fail'],
          });
          rememberResult(nonce, failed, NONCE_TTL_UNVERIFIED_MS, nowMs);
          return failed;
        }
        keySource = 'pinned';
      }

      const verified: WbaVerification = finish('verified', {
        ...baseIdentity,
        keySource,
        reason: 'signed-agent',
        identity: 'signed',
        verification_method: 'rfc9421',
        outcome: 'VALID',
        directoryUrl: outcome.directoryUrl ?? directoryUrlFor(parsed.agentUrl as string),
        evidence: [...baseEvidence, `wba.verified:${agentHost}`],
      });
      const expiresMs = typeof parsed.params.expires === 'number' ? parsed.params.expires * 1000 : nowMs + NONCE_TTL_UNVERIFIED_MS;
      rememberResult(nonce, verified, Math.min(NONCE_TTL_VERIFIED_MAX_MS, expiresMs - nowMs), nowMs);
      return verified;
    }

    const failed = finish(mapped.status, {
      ...baseIdentity,
      reason: mapped.reason,
      outcome: outcome.kind,
      evidence: [...baseEvidence, `wba.${outcome.kind.toLowerCase()}:${mapped.reason}`],
    });
    rememberResult(nonce, failed, NONCE_TTL_UNVERIFIED_MS, nowMs);
    return failed;
  } catch {
    return finish('invalid', {
      reason: 'wba.error',
      outcome: 'INVALID',
      evidence: ['wba.error'],
    });
  }
}
