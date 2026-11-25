/**
 * Phase 4 — canonical identity engine (pure, dependency-free).
 *
 * 512-bit SimHash with b=32 / r=16 (locked in LSH_CONFIG). LSH candidate retrieval count is
 * kept STRICTLY SEPARATE from the collision-density guard: a large candidate set is fine, but
 * an exact-hash collision density >= 2 blocks a fuzzy merge regardless of how many candidates
 * were retrieved. Five-stage resolution order:
 *   storage continuity -> exact hardware (+collision guard) -> LSH fuzzy -> privacy-hardened
 *   degraded -> new enrollment.
 */

import { LSH_CONFIG, type IdentityAxes } from './telemetryContract';

const MASK64 = (1n << 64n) - 1n;
const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const SEEDS = [
  0x9e3779b97f4a7c15n, 0xbf58476d1ce4e5b9n, 0x94d049bb133111ebn, 0x7f4a7c15bf58476dn,
  0x2545f4914f6cdd1dn, 0xd6e8feb86659fd93n, 0x9e3779b185ebca87n, 0xa0761d6478bd642fn,
] as const;

function fnv64(input: string, seed: bigint): bigint {
  let h = (FNV_OFFSET ^ seed) & MASK64;
  for (let i = 0; i < input.length; i += 1) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * FNV_PRIME) & MASK64;
  }
  return h;
}

function tokenWords(token: string): bigint[] {
  return SEEDS.map((seed) => fnv64(token, seed));
}

/** Deterministic 512-bit SimHash over a flat feature map or a serialized string. */
export function simhash512(features: Record<string, unknown> | string): bigint {
  const tokens: string[] = [];
  if (typeof features === 'string') {
    if (features) tokens.push(features);
  } else {
    for (const key of Object.keys(features || {}).sort()) {
      const value = features[key];
      if (value === null || value === undefined) continue;
      tokens.push(`${key}=${typeof value === 'object' ? JSON.stringify(value) : String(value)}`);
    }
  }
  const weights = new Array<number>(LSH_CONFIG.bits).fill(0);
  for (const token of tokens) {
    const words = tokenWords(token); // 8 × 64 = 512 bits
    for (let w = 0; w < 8; w += 1) {
      const word = words[w];
      for (let bit = 0; bit < 64; bit += 1) {
        const idx = w * 64 + bit;
        weights[idx] += (word >> BigInt(bit)) & 1n ? 1 : -1;
      }
    }
  }
  let result = 0n;
  for (let i = LSH_CONFIG.bits - 1; i >= 0; i -= 1) {
    result <<= 1n;
    if (weights[i] >= 0) result |= 1n;
  }
  return result & ((1n << BigInt(LSH_CONFIG.bits)) - 1n);
}

export function simhashToHex(hash: bigint): string {
  return (hash & ((1n << BigInt(LSH_CONFIG.bits)) - 1n))
    .toString(16)
    .padStart(LSH_CONFIG.bits / 4, '0');
}

export function simhashFromHex(hex: string): bigint {
  try {
    return BigInt(`0x${hex}`) & ((1n << BigInt(LSH_CONFIG.bits)) - 1n);
  } catch {
    return 0n;
  }
}

export function hammingSimilarity512(a: bigint, b: bigint): number {
  let diff = (a ^ b) & ((1n << BigInt(LSH_CONFIG.bits)) - 1n);
  let distance = 0;
  while (diff) {
    distance += Number(diff & 1n);
    diff >>= 1n;
  }
  return 1 - distance / LSH_CONFIG.bits;
}

/** 32 bands of 16 bits each — the identity_lsh_bands primary key is (band_idx, band_hash, hardware_id). */
export function bandHashes(hash: bigint): Array<{ band_idx: number; band_hash: string }> {
  const bands: Array<{ band_idx: number; band_hash: string }> = [];
  for (let idx = 0; idx < LSH_CONFIG.bands; idx += 1) {
    const slice = (hash >> BigInt(idx * LSH_CONFIG.rows)) & ((1n << BigInt(LSH_CONFIG.rows)) - 1n);
    bands.push({ band_idx: idx, band_hash: slice.toString(16).padStart(LSH_CONFIG.rows / 4, '0') });
  }
  return bands;
}

/* -------------------------------------------------------------------------- */
/* LSH fuzzy decision                                                          */
/* -------------------------------------------------------------------------- */

export const LSH_THRESHOLDS = {
  minSimilarity: 0.88,
  minMargin: 0.1,
  maxCollisionDensity: 2,
} as const;

export interface LshCandidate {
  hardwareId: string;
  simhash: bigint;
  /** Canonical visitor id for this hardware anchor, when the caller knows it. Optional so
   *  existing retrieval code (which returns hardwareId + simhash only) stays compatible. */
  visitorId?: string | null;
}

export interface FuzzyDecisionInput {
  query: bigint;
  candidates: readonly LshCandidate[];
}

export interface FuzzyDecision {
  match: boolean;
  bestHardwareId: string | null;
  /** The matched visitor id to hand back to the caller. Falls back to the matched hardware
   *  id when the caller did not supply candidate.visitorId (backward compatible). */
  bestVisitorId: string | null;
  similarity: number;
  margin: number;
  /** Distinct hardware anchors sharing the best candidate's exact hash. */
  collisionDensity: number;
  /** Number of candidates retrieved by LSH — deliberately NOT used by the collision guard. */
  candidateCount: number;
  reason: string;
  stage: 'lsh_fuzzy' | 'new_enrollment';
}

export function decideLshFuzzyMatch(input: FuzzyDecisionInput): FuzzyDecision {
  const candidates = (input.candidates || []).slice();
  const candidateCount = candidates.length; // retrieval count, kept separate from density
  if (candidateCount === 0) {
    return {
      match: false,
      bestHardwareId: null,
      bestVisitorId: null,
      similarity: 0,
      margin: 0,
      collisionDensity: 0,
      candidateCount,
      reason: 'no LSH candidates retrieved',
      stage: 'new_enrollment',
    };
  }
  const scored = candidates
    .map((candidate) => ({ candidate, similarity: hammingSimilarity512(input.query, candidate.simhash) }))
    .sort((a, b) => b.similarity - a.similarity);
  const best = scored[0];
  const runnerUp = scored.length > 1 ? scored[1].similarity : 0;
  const margin = best.similarity - runnerUp;
  // Collision density counts exact-hash duplicates of the best candidate, independent of the
  // number of candidates the LSH bands returned.
  const collisionDensity = scored.filter((entry) => entry.candidate.simhash === best.candidate.simhash).length;
  let reason = 'accepted';
  let match = true;
  if (best.similarity < LSH_THRESHOLDS.minSimilarity) {
    match = false;
    reason = `similarity ${best.similarity.toFixed(4)} < ${LSH_THRESHOLDS.minSimilarity}`;
  } else if (margin < LSH_THRESHOLDS.minMargin && scored.length > 1) {
    match = false;
    reason = `margin ${margin.toFixed(4)} < ${LSH_THRESHOLDS.minMargin}`;
  } else if (collisionDensity >= LSH_THRESHOLDS.maxCollisionDensity) {
    match = false;
    reason = `collision density ${collisionDensity} >= ${LSH_THRESHOLDS.maxCollisionDensity}`;
  }
  return {
    match,
    bestHardwareId: match ? best.candidate.hardwareId : null,
    bestVisitorId: match ? best.candidate.visitorId || best.candidate.hardwareId : null,
    similarity: best.similarity,
    margin,
    collisionDensity,
    candidateCount,
    reason,
    stage: match ? 'lsh_fuzzy' : 'new_enrollment',
  };
}

/* -------------------------------------------------------------------------- */
/* Structural-anchor fallback                                                   */
/* -------------------------------------------------------------------------- */

export interface StructuralAnchorInput {
  /** 8x8 coarse-quantized canvas digest (stable across farbling noise). */
  canvasCoarseHash?: string | null;
  /** Silicon architecture anchor from the hardware-truth probe. */
  architecture?: string | null;
  gpuVendor?: string | null;
  gpuRenderer?: string | null;
}

/**
 * Features for the structural anchor: coarse (quantized) canvas geometry plus silicon
 * GPU/architecture. These deliberately exclude the fine canvas hash and the raw audio
 * sum, which drift under Brave/Safari/Tor farbling, so a privacy-hardened or noisy
 * visitor can still be recovered through the existing LSH fuzzy matcher.
 */
export function structuralAnchorFeatures(anchor: StructuralAnchorInput): Record<string, unknown> {
  return {
    canvas_coarse: (anchor.canvasCoarseHash || '').trim() || 'na',
    arch: (anchor.architecture || '').trim() || 'na',
    gpu_vendor: (anchor.gpuVendor || '').trim() || 'na',
    gpu_renderer: (anchor.gpuRenderer || '').trim() || 'na',
  };
}

/** SimHash of the structural anchor, fed to `decideLshFuzzyMatch` as the query. */
export function structuralAnchorHash(anchor: StructuralAnchorInput): bigint {
  return simhash512(structuralAnchorFeatures(anchor));
}

/**
 * Fallback resolution when the exact hardware id is unavailable (e.g. the hardware seed
 * changed after canvas/audio were excluded, or storage was wiped). The collision-density
 * guard is unchanged — `LSH_THRESHOLDS.maxCollisionDensity` is 2 and `decideLshFuzzyMatch`
 * rejects `>= 2`, so an accepted match always has density < 2.
 */
export function resolveStructuralAnchor(
  anchor: StructuralAnchorInput,
  candidates: readonly LshCandidate[]
): FuzzyDecision {
  return decideLshFuzzyMatch({ query: structuralAnchorHash(anchor), candidates });
}

/* -------------------------------------------------------------------------- */
/* Five-stage resolver                                                         */
/* -------------------------------------------------------------------------- */

export type IdentityMatchStage = IdentityAxes['match_stage'];

export interface IdentityResolutionInput {
  storageVisitorId?: string | null;
  storageValid?: boolean;
  exactHardwareId?: string | null;
  /** distinct_storage_seeds_count < 2 blocks exact-hardware merges. */
  distinctStorageSeedsCount?: number;
  privacyHardened?: boolean;
  query?: bigint;
  candidates?: readonly LshCandidate[];
  /** Optional structural-anchor fallback used when no explicit query is supplied. */
  structuralAnchor?: StructuralAnchorInput;
}

export interface IdentityResolution {
  stage: IdentityMatchStage;
  matchLabel: string;
  /** Matched visitor id, carried through to the caller (never just a match label). Null on
   *  stages that cannot identify a visitor (privacy-degraded / new enrollment). */
  visitorId: string | null;
  collisionRisk: 'low' | 'high';
  confidenceTier: IdentityAxes['confidence_tier'];
  fuzzy?: FuzzyDecision;
}

/**
 * Resolve identity in strict stage order. The exact-hardware stage is gated by the collision
 * guard: fewer than two distinct storage seeds cannot safely merge on hardware alone.
 */
export function resolveIdentityStage(input: IdentityResolutionInput = {}): IdentityResolution {
  // 1. First-party storage continuity — strongest, no entropy guesswork.
  if (input.storageValid && input.storageVisitorId) {
    return {
      stage: 'storage_continuity',
      matchLabel: input.storageVisitorId,
      visitorId: input.storageVisitorId,
      collisionRisk: 'low',
      confidenceTier: 'First-Party Continuity Match',
    };
  }

  // 2. Exact hardware + collision guard.
  if (input.exactHardwareId && (input.distinctStorageSeedsCount ?? 0) >= 2) {
    return {
      stage: 'exact_hardware',
      matchLabel: input.exactHardwareId,
      // Only a hardware id is known here; the caller's own visitor id stays canonical.
      visitorId: null,
      collisionRisk: 'low',
      confidenceTier: 'High-Agreement Hardware Match',
    };
  }

  // 3. LSH fuzzy (only when a query and candidates are supplied). An explicit query wins;
  //    otherwise the structural-anchor fallback provides one (with the same collision guard).
  const query =
    input.query !== undefined
      ? input.query
      : input.structuralAnchor
      ? structuralAnchorHash(input.structuralAnchor)
      : undefined;
  if (query !== undefined && input.candidates && input.candidates.length > 0) {
    const fuzzy = decideLshFuzzyMatch({ query, candidates: input.candidates });
    if (fuzzy.match && fuzzy.bestHardwareId) {
      return {
        stage: 'lsh_fuzzy',
        matchLabel: fuzzy.bestHardwareId,
        visitorId: fuzzy.bestVisitorId,
        collisionRisk: fuzzy.collisionDensity >= 2 ? 'high' : 'low',
        confidenceTier: 'Probabilistic Fuzzy Match',
        fuzzy,
      };
    }
  }

  // 4. Privacy-hardened degraded profile — reduced entropy, never a positive ID claim.
  if (input.privacyHardened) {
    return {
      stage: 'privacy_hardened',
      matchLabel: 'privacy-degraded',
      visitorId: null,
      collisionRisk: 'high',
      confidenceTier: 'Privacy-Hardened Profile (Reduced Entropy)',
    };
  }

  // 5. New enrollment.
  return {
    stage: 'new_enrollment',
    matchLabel: '',
    visitorId: null,
    collisionRisk: 'low',
    confidenceTier: 'New Unobserved Profile',
  };
}

/* -------------------------------------------------------------------------- */
/* R4 — supplementary high-recall identity (coverage-first sibling)            */
/* -------------------------------------------------------------------------- */

/**
 * WEB RESEARCH BRIEF R4 — fingerprint-style supplementary high-recall id.
 *
 * This is a COVERAGE hint emitted ALONGSIDE the primary visitor id. It never replaces the
 * primary id, never becomes a sole blocking key and never makes a confidence claim. The
 * output shape is the same alphanumeric <= 25-char base62 shape as the primary id (20 chars
 * here), derived deterministically by HMAC-SHA-256 over ALREADY RESOLVED stable signals
 * only. No random UUID, Math.random, Date.now, network call or Durable Object write occurs.
 *
 * DESIGN INVARIANTS:
 *   - Inputs are whitelisted resolved signals: normalized UA, first language, truncated IP
 *     (IPv4 /24 or IPv6 /48), timezone NAME (never the DST-volatile offset), platform,
 *     architecture and browser family. Raw PII (full IP, raw UA) is never used as a seed.
 *   - Canonicalization is lowercase + trim + whitespace collapse + delimiter stripping;
 *     the HMAC message is sorted `key=value` pairs joined by the fixed `|` delimiter, so
 *     key insertion order cannot change the result.
 *   - The purpose key is VERSIONED (`high-recall:v1`). Exactly one prior key
 *     (`high-recall:v0`) is accepted during a rotation; anything older is rejected.
 *   - The HMAC key is scoped by an explicitly caller-supplied pepper. It is never inferred
 *     from the untrusted resolved bundle nor silently defaulted: without a pepper the resolver
 *     reports `visitor_found: false`. `instance-local` is only a compatibility/test value;
 *     production callers must not use it as their scope.
 *   - Collision risk is BOUNDED by the coarse cohort width of the resolved signals, not by
 *     the 20-char output: many visitors may share an HR id, which is why it is a hint only.
 *   - `visitor_found` means "a stable HR candidate was derived" (coverage), NOT that a
 *     storage/hardware match was confirmed. The result deliberately has NO confidence field.
 */

/** Active purpose key. Versioned so a rotation can be rolled without breaking lookups. */
export const HIGH_RECALL_PURPOSE_KEY = 'high-recall:v1';
/** Exactly one prior key is accepted (one rotation). Older versions are rejected. */
export const HIGH_RECALL_PRIOR_PURPOSE_KEY = 'high-recall:v0';
/** Same base62 alphabet as the primary id generator (server/identity/resolver.ts). */
export const HIGH_RECALL_ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const HIGH_RECALL_ID_LENGTH = 20;
export const HIGH_RECALL_MAX_ID_LENGTH = 25;
/** Public, NON-SECRET compatibility/test pepper (frozen golden fixtures use this value).
 *  It is never defaulted or inferred from the resolved bundle; production callers must NOT
 *  use it as a scope because it is guessable. An explicit caller decision is sufficient. */
export const HIGH_RECALL_DEFAULT_PEPPER = 'instance-local';
/** Only these canonical fields may enter the HMAC message. */
export const HIGH_RECALL_STABLE_FIELDS: readonly string[] = [
  'architecture',
  'browser',
  'ip_prefix',
  'language',
  'platform',
  'timezone',
  'ua',
];

/** Canonical, PII-minimized input built by `buildHighRecallInput`. Contains only resolved
 *  stable tokens plus the trusted caller scope and purpose-key version. */
export interface HighRecallInput {
  readonly values: Readonly<Record<string, string>>;
  /** Trusted, caller-supplied scope. Empty means "no trusted pepper" — no id is minted. */
  readonly pepper: string;
  readonly key_version: string;
}

/** Pure result of `resolveSupplementaryHighRecallId` — four fields, NO confidence score. */
export interface SupplementaryHighRecallResult {
  visitor_id: string | null;
  visitor_found: boolean;
  reason: string;
  key_version: string;
}

/**
 * Additive optional SIBLING object. It is attached beside the existing identity fields;
 * `visitor_id` / `visitor_found` / `match_stage` / `identification` are never mutated.
 * `confidence` is deliberately absent (or exactly 0 when a caller needs an explicit value)
 * because an HR hint carries no calibrated probability.
 */
export interface SupplementaryHighRecallIdentity {
  visitor_id: string | null;
  visitor_found: boolean;
  confidence?: 0;
  first_seen_at?: string;
  last_seen_at?: string;
}

export type HighRecallFriction = 'low' | 'moderate' | 'new';

export interface HighRecallFrictionDecision {
  friction: HighRecallFriction;
  /** Always false: an HR hint is never a sole blocking key. */
  blocks: false;
  reason: string;
}

/* --- defensive primitives (all total) ------------------------------------- */

function hrSafeGet(source: unknown, key: string): unknown {
  if (source === null || source === undefined) return undefined;
  const kind = typeof source;
  if (kind !== 'object' && kind !== 'function') return undefined;
  try {
    return (source as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Lowercase / trim / whitespace-collapse / delimiter-strip / bound. */
function hrToken(value: unknown): string {
  if (typeof value !== 'string') return '';
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f|=,]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  if (!cleaned) return '';
  return cleaned.length > 256 ? cleaned.slice(0, 256).trim() : cleaned;
}

function hrFirstToken(source: unknown, keys: readonly string[]): string {
  for (const key of keys) {
    const token = hrToken(hrSafeGet(source, key));
    if (token) return token;
  }
  return '';
}

/** Trim/bound ONLY — preserves case for already-canonical ids and ISO timestamps. */
function hrPlainString(value: unknown): string {
  if (typeof value !== 'string') return '';
  const text = value.trim();
  if (!text) return '';
  return text.length > 256 ? text.slice(0, 256).trim() : text;
}

/** IPv4 -> first three octets + .0/24. Rejects leading-zero octets, out-of-range octets
 *  (including the fourth one, which is not part of the output), bad prefix lengths and
 *  hostile input. */
function hrTruncateIpv4(value: string): string {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(value);
  if (!match) return '';
  const parts = [match[1], match[2], match[3], match[4]];
  // Leading zeros are ambiguous/octal-looking; only the literal '0' is canonical.
  if (parts.some((part) => part.length > 1 && part.startsWith('0'))) return '';
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return '';
  if (match[5] !== undefined) {
    const prefix = Number(match[5]);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return '';
  }
  return `${octets.slice(0, 3).join('.')}.0/24`;
}

/** IPv6 -> first three (zero-padded) hextets + ::/48. Handles `::`, `::1`, trailing `::`
 *  and a trailing prefix length. Embedded IPv4 (dotted or hex-mapped/compatible) and
 *  over-long forms are rejected rather than guessed. */
function hrTruncateIpv6(value: string): string {
  let text = value.trim().toLowerCase();
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end < 0) return '';
    text = text.slice(1, end);
  }
  text = text.split('%')[0]; // strip zone id
  if (text.includes('.')) return ''; // embedded IPv4 in dotted form is unsupported
  if (text.includes('/')) text = text.slice(0, text.indexOf('/'));
  if (!text) return '';

  let groups: string[];
  if (text.includes('::')) {
    const halves = text.split('::');
    if (halves.length !== 2) return ''; // more than one compression is invalid
    // An empty half is legal only at the very start/end (`::1`, `2001:db8::`); an empty
    // group inside a half (`2001:::1`) is not.
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    if (left.some((part) => !part) || right.some((part) => !part)) return '';
    // `::` must stand in for at least one all-zero hextet: eight explicit groups plus
    // `::` (e.g. `1:2:3:4:5:6:7:8::`) is over-long.
    const missing = 8 - left.length - right.length;
    if (missing < 1) return '';
    groups = [...left, ...new Array<string>(missing).fill('0'), ...right];
  } else {
    const parts = text.split(':');
    if (parts.some((part) => !part)) return ''; // stray leading/trailing/double colon
    groups = parts;
  }
  if (groups.length !== 8) return '';
  const expanded = groups.map((group) => group.padStart(4, '0'));
  for (const group of expanded) if (!/^[0-9a-f]{1,4}$/.test(group)) return '';

  // Reject embedded IPv4 written in hex: IPv4-mapped (`::ffff:c000:201`) and
  // IPv4-compatible (`::c000:201`) forms. `::` and `::1` stay valid.
  const ipv4Mapped = expanded.slice(0, 5).every((group) => group === '0000') && expanded[5] === 'ffff';
  const ipv4Compatible = expanded.slice(0, 6).every((group) => group === '0000') && expanded[6] !== '0000';
  if (ipv4Mapped || ipv4Compatible) return '';

  const head = expanded.slice(0, 3);
  return `${head.join(':')}::/48`;
}

/** Never returns a raw IP: only the /24 or /48 prefix token can leave this function. */
function hrIpPrefix(value: unknown): string {
  const text = hrToken(value);
  if (!text) return '';
  return hrTruncateIpv4(text) || hrTruncateIpv6(text);
}

function hrNormalizedUa(source: unknown): string {
  const direct = hrFirstToken(source, [
    'normalizedUserAgent', 'normalizedUa', 'uaNormalized', 'ua_normal', 'normalizedUserAgentString',
  ]);
  if (direct) return direct;
  const details = hrSafeGet(source, 'browser_details') ?? hrSafeGet(source, 'browserDetails');
  const parts = [
    hrFirstToken(details, ['browser_name', 'browserName']),
    hrFirstToken(details, ['browser_major_version', 'browserMajorVersion']),
    hrFirstToken(details, ['os', 'osFamily']),
    hrFirstToken(details, ['os_version', 'osVersion']),
  ].filter(Boolean);
  return parts.join(' ');
}

/**
 * Re-canonicalize a caller-supplied `ua` value to the resolved/normalized shape that
 * `hrNormalizedUa` produces from a bundle: a short, lowercase token sequence. A raw UA
 * string (`Mozilla/5.0 (...) AppleWebKit/...`) carries host-specific detail and is rejected
 * rather than hashed when it arrives directly in a `values` map.
 */
function hrCanonicalUa(value: unknown): string {
  const token = hrToken(value);
  if (!token) return '';
  if (/\bmozilla\/|\bapplewebkit\/|\(khtml|\bgecko\b|\(|\)|;/.test(token)) return '';
  return token;
}

function hrLanguage(source: unknown): string {
  const direct = hrFirstToken(source, ['firstLanguage', 'primaryLanguage', 'language', 'browserLanguage']);
  if (direct) return direct;
  const langs = hrSafeGet(source, 'languages') ?? hrSafeGet(hrSafeGet(source, 'browserDevice'), 'languages');
  try {
    if (Array.isArray(langs)) return hrToken(langs[0]);
    if (langs instanceof Set) return hrToken(langs.values().next().value);
  } catch {
    // A hostile iterable contributes nothing.
  }
  return '';
}

/* Pure-JS SHA-256 + HMAC-SHA-256, vendored from src/client/signals/hash.ts so this lib
 * stays import-free and synchronous in Node, the browser bundle and Workers alike. */

const HR_SHA_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const hrRotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n));

function hrUtf8Bytes(input: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < input.length; i += 1) {
    let code = input.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < input.length) {
      const low = input.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i += 1;
      }
    }
    if (code < 0x80) out.push(code);
    else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 63));
    else if (code < 0x10000) out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    else out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
  }
  return new Uint8Array(out);
}

function hrSha256Bytes(bytes: Uint8Array): Uint8Array {
  const bitLen = bytes.length * 8;
  const paddedLen = (bytes.length + 9 + 63) & ~63;
  const buf = new Uint8Array(paddedLen);
  buf.set(bytes);
  buf[bytes.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(paddedLen - 8, Math.floor(bitLen / 4294967296) >>> 0, false);
  dv.setUint32(paddedLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let off = 0; off < paddedLen; off += 64) {
    for (let i = 0; i < 16; i += 1) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i += 1) {
      const a15 = w[i - 15];
      const a2 = w[i - 2];
      const s0 = hrRotr(a15, 7) ^ hrRotr(a15, 18) ^ (a15 >>> 3);
      const s1 = hrRotr(a2, 17) ^ hrRotr(a2, 19) ^ (a2 >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i += 1) {
      const s1 = hrRotr(e, 6) ^ hrRotr(e, 11) ^ hrRotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + s1 + ch + HR_SHA_K[i] + w[i]) >>> 0;
      const s0 = hrRotr(a, 2) ^ hrRotr(a, 13) ^ hrRotr(a, 22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + mj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  const state = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 8; i += 1) odv.setUint32(i * 4, state[i], false);
  return out;
}

function hrHmacSha256(keyMaterial: string, message: string): Uint8Array {
  let key = hrUtf8Bytes(keyMaterial);
  if (key.length > 64) key = hrSha256Bytes(key);
  const padded = new Uint8Array(64);
  padded.set(key);
  const msg = hrUtf8Bytes(message);
  const inner = new Uint8Array(64 + msg.length);
  const outer = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i += 1) {
    inner[i] = padded[i] ^ 0x36;
    outer[i] = padded[i] ^ 0x5c;
  }
  inner.set(msg, 64);
  const innerDigest = hrSha256Bytes(inner);
  outer.set(innerDigest, 64);
  return hrSha256Bytes(outer);
}

/** Big-endian HMAC bytes -> fixed-length base62 id (same alphabet/shape as primary). */
function hrBase62(bytes: Uint8Array, length: number): string {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out = HIGH_RECALL_ID_ALPHABET[Number(value % BigInt(HIGH_RECALL_ID_ALPHABET.length))] + out;
    value /= BigInt(HIGH_RECALL_ID_ALPHABET.length);
  }
  return out;
}

/* --- public helpers -------------------------------------------------------- */

/**
 * Build the canonical, PII-minimized HR input from an ALREADY RESOLVED signal bundle.
 * Only whitelisted stable fields are read; raw PII (full IP / raw UA) never leaves here.
 * `trustedPepper` is a caller-supplied scope and must NOT come from `resolved`, which is
 * untrusted. When it is absent the returned `pepper` is empty and the resolver refuses to
 * mint an id. Total over hostile input — a malformed bundle yields an empty `values` map.
 */
export function buildHighRecallInput(resolved: unknown, trustedPepper?: string): HighRecallInput {
  try {
    const values: Record<string, string> = {};
    const add = (key: string, value: string): void => {
      const canonical = hrToken(value);
      if (canonical && HIGH_RECALL_STABLE_FIELDS.includes(key)) values[key] = canonical;
    };

    add('ua', hrNormalizedUa(resolved));
    add('language', hrLanguage(resolved));
    add('ip_prefix', hrIpPrefix(hrFirstToken(resolved, [
      'clientIp', 'publicIp', 'ipAddress', 'ip', 'remoteAddr', 'cfConnectingIp',
    ])));
    add('timezone', hrFirstToken(resolved, [
      'timezone', 'timezoneName', 'tz', 'browserTimezone', 'ipTimezone',
    ]));
    add('platform', hrFirstToken(resolved, ['platform', 'hostOs', 'osFamily', 'normalizedPlatform']));
    add('architecture', hrFirstToken(resolved, ['architecture', 'cpuArchitecture', 'deviceArchitecture']));
    const details = hrSafeGet(resolved, 'browser_details') ?? hrSafeGet(resolved, 'browserDetails');
    add('browser', hrFirstToken(resolved, ['browserFamily', 'browserName']) || hrFirstToken(details, ['browser_name']));

    // The pepper is a trusted SCOPE supplied by the caller, never a signal read from the
    // untrusted resolved bundle (tenantId / instanceId / pepper / keyScope are all untrusted
    // here). An absent pepper stays empty so the resolver fails closed instead of deriving
    // an id with a guessable key.
    const pepper = hrToken(trustedPepper);
    const keyVersion =
      hrFirstToken(resolved, ['highRecallKeyVersion', 'key_version', 'keyVersion']) || HIGH_RECALL_PURPOSE_KEY;

    const sortedValues: Record<string, string> = {};
    for (const key of Object.keys(values).sort()) sortedValues[key] = values[key];
    return { values: sortedValues, pepper, key_version: keyVersion };
  } catch {
    return { values: {}, pepper: '', key_version: HIGH_RECALL_PURPOSE_KEY };
  }
}

/**
 * Derive the supplementary high-recall id. Pure, synchronous, non-throwing, no IO.
 * The message is `key=value` pairs sorted by key and joined with `|`; the HMAC key is
 * `purposeKey \0 trustedPepper`. Exactly one prior purpose key is accepted on rotation.
 * Caller-supplied `values` are re-canonicalized here so no whitelisted key can smuggle raw
 * PII into the message. A trusted pepper is mandatory; without one no id is minted.
 *
 * `visitor_found: true` means a candidate was DERIVED (coverage), not that a visitor was
 * confirmed by storage or hardware. There is intentionally no confidence score.
 */
export function resolveSupplementaryHighRecallId(input: unknown): SupplementaryHighRecallResult {
  try {
    const source = input !== null && typeof input === 'object' ? (input as Record<string, unknown>) : null;
    if (!source) {
      return { visitor_id: null, visitor_found: false, reason: 'invalid_high_recall_input', key_version: HIGH_RECALL_PURPOSE_KEY };
    }

    const rawValues = hrSafeGet(source, 'values');
    const values: Record<string, string> = {};
    if (rawValues !== null && typeof rawValues === 'object') {
      for (const key of Object.keys(rawValues).sort()) {
        if (!HIGH_RECALL_STABLE_FIELDS.includes(key)) continue;
        const raw = hrSafeGet(rawValues, key);
        // Callers may supply `values` directly, bypassing buildHighRecallInput. Re-apply the
        // builder's PII-minimizing canonicalization: a raw full IP or raw UA must never enter
        // the HMAC message. Invalid values are dropped rather than hashed.
        const canonical =
          key === 'ip_prefix' ? hrIpPrefix(raw)
          : key === 'ua' ? hrCanonicalUa(raw)
          : hrToken(raw);
        if (canonical) values[key] = canonical;
      }
    }
    const keys = Object.keys(values).sort();
    if (keys.length === 0) {
      return { visitor_id: null, visitor_found: false, reason: 'insufficient_resolved_signals', key_version: HIGH_RECALL_PURPOSE_KEY };
    }

    const keyVersion = hrToken(hrSafeGet(source, 'key_version')) || HIGH_RECALL_PURPOSE_KEY;
    if (keyVersion !== HIGH_RECALL_PURPOSE_KEY && keyVersion !== HIGH_RECALL_PRIOR_PURPOSE_KEY) {
      return { visitor_id: null, visitor_found: false, reason: 'unsupported_key_version', key_version: keyVersion };
    }

    // The pepper MUST be supplied explicitly by the caller. There is deliberately no fallback
    // to an untrusted bundle field and no silent default. Any non-empty value is accepted,
    // including the public `instance-local` compatibility/test value: production callers must
    // not use it, but the resolver does not bake that literal into its logic.
    const pepper = hrToken(hrSafeGet(source, 'pepper'));
    if (!pepper) {
      return { visitor_id: null, visitor_found: false, reason: 'missing_trusted_pepper', key_version: keyVersion };
    }

    const seed = keys.map((key) => `${key}=${values[key]}`).join('|');
    const digest = hrHmacSha256(`${keyVersion}\u0000${pepper}`, seed);
    const visitorId = hrBase62(digest, Math.min(HIGH_RECALL_ID_LENGTH, HIGH_RECALL_MAX_ID_LENGTH));
    return {
      visitor_id: visitorId,
      visitor_found: true,
      reason: `derived_from:${keys.join(',')}`,
      key_version: keyVersion,
    };
  } catch {
    return {
      visitor_id: null,
      visitor_found: false,
      reason: 'high_recall_resolution_failed',
      key_version: HIGH_RECALL_PURPOSE_KEY,
    };
  }
}

/**
 * Friction matrix — both signals match -> low; primary misses but HR hint matches ->
 * moderate; neither matches -> new enrollment. A primary match stays authoritative even
 * when the HR hint disagrees, and `blocks` is ALWAYS false: an HR hint is never a sole
 * blocking key.
 */
export function resolveSupplementaryFriction(input: unknown): HighRecallFrictionDecision {
  try {
    const primaryMatch = hrSafeGet(input, 'primaryMatch') === true;
    const highRecallMatch = hrSafeGet(input, 'highRecallMatch') === true;
    if (primaryMatch) {
      return { friction: 'low', blocks: false, reason: 'primary_authoritative_hr_hint_ignored' };
    }
    if (highRecallMatch) {
      return { friction: 'moderate', blocks: false, reason: 'high_recall_hint_only_no_block' };
    }
    return { friction: 'new', blocks: false, reason: 'no_authoritative_or_hint_match_new_enrollment' };
  } catch {
    return { friction: 'new', blocks: false, reason: 'friction_check_failed_new_enrollment' };
  }
}

/** Build the additive sibling object. No `confidence` field is emitted. */
export function asSupplementaryIdentity(
  result: SupplementaryHighRecallResult | null | undefined,
  timestamps?: { first_seen_at?: string; last_seen_at?: string } | null
): SupplementaryHighRecallIdentity {
  const id = hrPlainString(hrSafeGet(result, 'visitor_id'));
  const sibling: SupplementaryHighRecallIdentity = {
    visitor_id: id || null,
    visitor_found: hrSafeGet(result, 'visitor_found') === true && id.length > 0,
  };
  // Confidence is deliberately absent — an HR hint makes no calibrated score claim.
  const first = hrPlainString(hrSafeGet(timestamps, 'first_seen_at'));
  const last = hrPlainString(hrSafeGet(timestamps, 'last_seen_at'));
  if (first) sibling.first_seen_at = first;
  if (last) sibling.last_seen_at = last;
  return sibling;
}

/** Attach the sibling WITHOUT mutating any existing identification field. */
export function withSupplementaryHighRecall<T extends object>(
  identification: T,
  sibling: SupplementaryHighRecallIdentity | null | undefined
): T & { supplementary_high_recall?: SupplementaryHighRecallIdentity } {
  try {
    const base = identification !== null && typeof identification === 'object' ? identification : ({} as T);
    const next = { ...base } as T & { supplementary_high_recall?: SupplementaryHighRecallIdentity };
    if (sibling && sibling.visitor_found && sibling.visitor_id) next.supplementary_high_recall = sibling;
    return next;
  } catch {
    // Even a hostile / non-spreadable identification object must keep its primary id.
    const fallback = identification !== null && typeof identification === 'object' ? identification : {};
    return fallback as T & { supplementary_high_recall?: SupplementaryHighRecallIdentity };
  }
}
