/**
 * networkEdge.ts — additive, SHADOW-ONLY network-edge fingerprint primitives.
 *
 * Design constraints (all deliberate):
 *  - Pure & non-throwing: every exported function is total, including on hostile input
 *    (nulls, wrong types, throwing getters, symbols, malformed digests).
 *  - Zero dependencies: the digests are an in-house, deterministic FNV-1a construction.
 *    No third-party SDK, no WebCrypto, no network calls, no I/O.
 *  - JA4H-STYLE, NEVER JA3/JA4: `ja4hStyleHash` hashes only header metadata an edge can
 *    observe (method, HTTP version, ordered header names, Accept-Language, and the
 *    presence of Cookie/Referer). It is a one-way, non-reversible digest; it never
 *    reconstitutes a client hello and is never labelled or claimed as JA3/JA4.
 *  - No fabricated values: a field that is missing, malformed or explicitly
 *    'unavailable' is reported as the literal string 'unavailable' and contributes a
 *    zero weight. Nothing is invented to fill a gap.
 *
 * Header ORDER is preserved and duplicates are counted: each header name is framed
 * into the digest in arrival order, including repeated names. Length-prefixed framing
 * keeps `['ab','c']` distinct from `['a','bc']`.
 */

/* -------------------------------------------------------------------------- */
/* Public constants & types                                                   */
/* -------------------------------------------------------------------------- */

/** Explicit marker for data that was not observed — never a synthesized value. */
export const UNAVAILABLE = 'unavailable' as const;

/**
 * The only permitted label for the TLS-lite vector. Deliberately NOT a JA3/JA4 claim:
 * these are edge-derived TLS components supplied by the caller, not a handshake fingerprint.
 */
export const EDGE_TLS_LABEL = 'edge-derived TLS components' as const;

export interface Ja4hStyleInput {
  /** HTTP method (normalized to upper case), e.g. 'GET'. */
  method?: string | null;
  /** HTTP version token, e.g. 'HTTP/2'. */
  version?: string | null;
  /** Header names in wire order; duplicates are preserved and counted. */
  headerNames?: string[] | null;
  /** Raw Accept-Language value, if observed. */
  acceptLanguage?: string | null;
  /** Whether a Cookie header was present. */
  cookiePresent?: boolean;
  /** Whether a Referer header was present. */
  refererPresent?: boolean;
}

export interface TlsLiteInput {
  tlsVersion?: string | null;
  /** 40-hex SHA-1 of the cipher list, as supplied by the edge. */
  ciphersSha1?: string | null;
  /** 40-hex SHA-1 of the extension list, as supplied by the edge. */
  extensionsSha1?: string | null;
  /** HTTP/2 (or /3) request priority token, if observed. */
  requestPriority?: string | null;
  /** Transport reported by the edge, e.g. 'TCP' or 'QUIC'. */
  edgeL4?: string | null;
}

export const TLS_FIELDS = [
  'tlsVersion',
  'ciphersSha1',
  'extensionsSha1',
  'requestPriority',
  'edgeL4',
] as const;
export type TlsField = (typeof TLS_FIELDS)[number];

export interface TlsLiteVector {
  /** Always 'edge-derived TLS components' — never a JA3/JA4 label. */
  label: typeof EDGE_TLS_LABEL;
  /** Per-field normalized additive weights in [0,1]; 0 means unavailable. */
  components: Record<TlsField, number>;
  /** Fields the edge actually supplied. */
  available: string[];
  /** Fields that were absent/malformed (no value was invented for them). */
  unavailable: string[];
  /** Mean of the additive component weights, bounded [0,1). */
  score: number;
  /** One-way digest of the vector, or 'unavailable' when no field was observed. */
  digest: string;
}

export interface NetworkLayerInput {
  ja4h?: Ja4hStyleInput | null;
  tls?: TlsLiteInput | null;
}

export interface NetworkLayerDetail {
  /** Combined one-way digest, or the literal 'unavailable' when nothing was observed. */
  hash: string;
  /** The JA4H-style header digest, or 'unavailable'. */
  ja4h: string;
  /** The edge-derived TLS vector (never a JA3/JA4 claim). */
  tls: TlsLiteVector;
  /** True when at least one real component was available. */
  available: boolean;
  /** Names of the layers that were not observed. */
  unavailable: string[];
}

/* -------------------------------------------------------------------------- */
/* Pure FNV-1a core                                                           */
/* -------------------------------------------------------------------------- */

const FNV_OFFSET_BASIS = 0x811c9dc5;
const FNV_PRIME = 0x01000193;
/** Four independent seeds give a 32-hex-character (128-bit-shaped) deterministic digest. */
const DIGEST_SEEDS = [0x811c9dc5, 0x01000193, 0x7f4a7c15, 0x9e3779b9] as const;

function fnv1a32(text: string, seed: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < text.length; i += 1) {
    h = (h ^ (text.charCodeAt(i) & 0xffff)) >>> 0;
    h = Math.imul(h, FNV_PRIME) >>> 0;
  }
  return h >>> 0;
}

function fnvDigest(text: string): string {
  let out = '';
  for (const seed of DIGEST_SEEDS) {
    out += fnv1a32(text, seed).toString(16).padStart(8, '0');
  }
  return out;
}

/** Length-prefixed frame: keeps segment boundaries unambiguous. */
function frame(value: string): string {
  return `${value.length}:${value}`;
}

function round6(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

/* -------------------------------------------------------------------------- */
/* Defensive coercion (never call arbitrary toString / valueOf)               */
/* -------------------------------------------------------------------------- */

function safeString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'boolean') return String(value);
  return '';
}

function isUnavailable(value: unknown): boolean {
  const s = safeString(value).trim().toLowerCase();
  return (
    s === '' ||
    s === UNAVAILABLE ||
    s === 'unknown' ||
    s === 'n/a' ||
    s === 'na' ||
    s === 'null' ||
    s === '-'
  );
}

type CaseMode = 'lower' | 'upper' | 'none';

function normalize(value: unknown, mode: CaseMode): string {
  const s = safeString(value).trim();
  if (isUnavailable(s)) return UNAVAILABLE;
  if (mode === 'lower') return s.toLowerCase();
  if (mode === 'upper') return s.toUpperCase();
  return s;
}

function normalizedSha1(value: unknown): string | null {
  const s = safeString(value).trim().toLowerCase();
  return /^[0-9a-f]{40}$/.test(s) ? s : null;
}

function safeHeaderNames(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    // Keep every slot (including non-strings) so order and duplicate counts are preserved.
    out.push(typeof item === 'string' ? item : '');
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* JA4H-style header fingerprint                                               */
/* -------------------------------------------------------------------------- */

/**
 * Deterministic, non-reversible FNV digest of JA4H-style header metadata.
 *
 * Normalization: method -> upper case, header names -> lower case, version and
 * Accept-Language are trimmed as-is. Absent/unavailable fields use the literal
 * 'unavailable' marker. Header order is preserved and repeated names are counted.
 * This is a JA4H-STYLE digest only — it is not, and must not be described as, JA3/JA4.
 */
export function ja4hStyleHash(input: Ja4hStyleInput): string {
  try {
    const bag = (input && typeof input === 'object' ? input : {}) as Ja4hStyleInput;
    const method = normalize(bag.method, 'upper');
    const version = normalize(bag.version, 'none');
    const acceptLanguage = normalize(bag.acceptLanguage, 'none');
    const names = safeHeaderNames(bag.headerNames).map((name) => normalize(name, 'lower'));
    const cookie = bag.cookiePresent === true ? '1' : '0';
    const referer = bag.refererPresent === true ? '1' : '0';

    const canonical = [
      'ja4h-style:v1',
      frame(method),
      frame(version),
      frame(String(names.length)),
      ...names.map(frame),
      frame(acceptLanguage),
      frame(cookie),
      frame(referer),
    ].join('|');

    return fnvDigest(canonical);
  } catch {
    return UNAVAILABLE;
  }
}

/* -------------------------------------------------------------------------- */
/* TLS-lite additive vector                                                   */
/* -------------------------------------------------------------------------- */

function componentWeight(field: string, value: string): number {
  return fnv1a32(`${field}\u0000${value}`, FNV_OFFSET_BASIS) / 0x1_0000_0000;
}

/**
 * Normalized additive vector built ONLY from edge-supplied TLS components.
 *
 * Each observed field contributes a bounded weight in [0,1); a missing, malformed or
 * explicitly 'unavailable' field contributes exactly 0 and is listed in `unavailable`.
 * `score` is the mean of the additive weights (bounded [0,1)), so it is a conservative
 * lower bound rather than an invented substitution. The label is always
 * 'edge-derived TLS components' — NEVER JA3/JA4.
 */
export function tlsLiteVector(input: TlsLiteInput): TlsLiteVector {
  try {
    const bag = (input && typeof input === 'object' ? input : {}) as TlsLiteInput;
    const components = {} as Record<TlsField, number>;
    const available: string[] = [];
    const unavailable: string[] = [];

    for (const field of TLS_FIELDS) {
      const raw = bag[field];
      const isSha = field === 'ciphersSha1' || field === 'extensionsSha1';
      const value = isSha
        ? normalizedSha1(raw)
        : isUnavailable(raw)
          ? null
          : safeString(raw).trim();

      if (value === null) {
        components[field] = 0;
        unavailable.push(field);
      } else {
        components[field] = round6(componentWeight(field, value));
        available.push(field);
      }
    }

    let sum = 0;
    for (const field of TLS_FIELDS) sum += components[field];
    const score = round6(sum / TLS_FIELDS.length);

    const digest =
      available.length === 0
        ? UNAVAILABLE
        : fnvDigest(
            [
              'tls-lite:v1',
              ...TLS_FIELDS.map((field) => frame(`${field}=${components[field].toFixed(6)}`)),
              frame(available.join(',')),
              frame(unavailable.join(',')),
            ].join('|')
          );

    return {
      label: EDGE_TLS_LABEL,
      components,
      available,
      unavailable,
      score,
      digest,
    };
  } catch {
    // Total fallback: no invented weights, just an all-unavailable vector.
    const components = {} as Record<TlsField, number>;
    for (const field of TLS_FIELDS) components[field] = 0;
    return {
      label: EDGE_TLS_LABEL,
      components,
      available: [],
      unavailable: [...TLS_FIELDS],
      score: 0,
      digest: UNAVAILABLE,
    };
  }
}

/* -------------------------------------------------------------------------- */
/* Combined network-layer digest                                              */
/* -------------------------------------------------------------------------- */

function hasJa4hData(value: unknown): boolean {
  try {
    if (!value || typeof value !== 'object') return false;
    const bag = value as Ja4hStyleInput;
    return (
      !isUnavailable(bag.method) ||
      !isUnavailable(bag.version) ||
      (Array.isArray(bag.headerNames) && bag.headerNames.length > 0) ||
      !isUnavailable(bag.acceptLanguage) ||
      bag.cookiePresent === true ||
      bag.refererPresent === true
    );
  } catch {
    return false;
  }
}

/**
 * Full, transparent breakdown behind `networkLayerHash`.
 *
 * Missing layers are reported as the literal 'unavailable' and are excluded from the
 * combined digest rather than being replaced with made-up values. If no layer at all
 * was observed, `hash` is 'unavailable' — never a digest that implies a fingerprint.
 */
export function networkLayerDetail(input: NetworkLayerInput): NetworkLayerDetail {
  try {
    const bag = (input && typeof input === 'object' ? input : {}) as NetworkLayerInput;

    const ja4h = hasJa4hData(bag.ja4h)
      ? ja4hStyleHash(bag.ja4h as Ja4hStyleInput)
      : UNAVAILABLE;
    const tls = tlsLiteVector((bag.tls ?? {}) as TlsLiteInput);
    const tlsDigest = tls.digest;

    const unavailable: string[] = [];
    if (ja4h === UNAVAILABLE) unavailable.push('ja4h');
    if (tlsDigest === UNAVAILABLE) unavailable.push('tls');
    // "available" means at least one real layer was observed (matches the public contract).
    const available = unavailable.length < 2;

    const hash = !available
      ? UNAVAILABLE
      : fnvDigest(['network-layer:v1', frame(`ja4h=${ja4h}`), frame(`tls=${tlsDigest}`)].join('|'));

    return { hash, ja4h, tls, available, unavailable };
  } catch {
    return {
      hash: UNAVAILABLE,
      ja4h: UNAVAILABLE,
      tls: tlsLiteVector(null as unknown as TlsLiteInput),
      available: false,
      unavailable: ['ja4h', 'tls'],
    };
  }
}

/**
 * Combined, deterministic, non-reversible hash of the available network-edge layers.
 *
 * Returns the literal 'unavailable' when neither a JA4H-style header input nor any
 * edge-derived TLS component was observed — no fabricated fingerprint is emitted.
 */
export function networkLayerHash(input: NetworkLayerInput): string {
  try {
    return networkLayerDetail(input).hash;
  } catch {
    return UNAVAILABLE;
  }
}
