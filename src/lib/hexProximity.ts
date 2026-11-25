/**
 * hexProximity.ts — additive, SHADOW-ONLY hexagonal proximity primitives.
 *
 * Design constraints (all deliberate):
 *  - Pure & non-throwing: every exported function is total, even on hostile input
 *    (NaN coordinates, throwing getters, symbols, malformed tiers/salts).
 *  - Zero dependencies: the hexagonal DGGS math (an H3-equivalent concept) and the
 *    keyed digest are implemented in-house. No third-party SDK, no network calls.
 *  - Privacy: the emitted cell id is a salted, one-way digest of a coarse hex tile.
 *    Raw coordinates (and the tile coordinates themselves) never leave this module.
 *  - No IP fallback: proximity is derived exclusively from an explicit browser
 *    geolocation point. A missing/denied point yields `proximity: null` forever;
 *    no edge header, GeoIP database or geohash-of-IP is ever consulted.
 *
 * `hexCellId` keeps a synchronous string contract, so it uses a deterministic
 * HMAC-style construction built on FNV-1a (the pure fallback). WebCrypto's HMAC is
 * asynchronous by specification; `hexCellIdAsync` uses `crypto.subtle` when the
 * platform exposes it (with real `Uint8Array` BufferSources) and transparently
 * falls back to the same FNV construction when it does not.
 *
 * Longitude is wrapped into [-180,180) and snapped to a whole number of columns
 * around each parallel, with the antimeridian at the centre of column 0, so
 * points on either side of the seam share a cell instead of landing at opposite
 * ends of the projected x axis. Reported accuracy above the largest tier's cap
 * is rejected rather than published with a false `precision_radius`.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

/** A browser-geolocation fix plus its reported accuracy (metres). */
export interface GeoPoint {
  lat: number;
  lon: number;
  accuracyMeters: number;
}

export type PrecisionTier = 0 | 1 | 2 | 3 | 4;

export interface PrecisionTierInfo {
  tier: PrecisionTier;
  radiusMeters: number;
  label: string;
}

/** Shadow-only proximity payload. */
export interface HexProximity {
  id: string;
  precision_radius: number;
  confidence: number;
}

export interface ProximityResult {
  proximity: HexProximity | null;
  reason: string;
}

/* -------------------------------------------------------------------------- */
/* Precision tiers                                                            */
/* -------------------------------------------------------------------------- */

interface TierBand {
  /** Half-open upper bound: accuracy < upperExclusive. */
  readonly upperExclusive: number;
  readonly radiusMeters: number;
  readonly label: string;
}

/**
 * Bands are [0,10) [10,75) [75,200) [200,1000) [1000,+inf). The tier's radius is
 * the closed upper bound of its band; the open-ended tier's radius is a CAP, not
 * a measurement. `proximityFromGeolocation` rejects accuracies above that cap
 * instead of publishing a false `precision_radius` for an unbounded fix.
 */
const TIER_BANDS: readonly TierBand[] = [
  { upperExclusive: 10, radiusMeters: 10, label: 'fine' },
  { upperExclusive: 75, radiusMeters: 75, label: 'high' },
  { upperExclusive: 200, radiusMeters: 200, label: 'medium' },
  { upperExclusive: 1000, radiusMeters: 1000, label: 'coarse' },
  { upperExclusive: Number.POSITIVE_INFINITY, radiusMeters: 5000, label: 'rough' },
];

/** Largest reported accuracy this module is willing to publish as a radius. */
const MAX_REPORTED_ACCURACY_METERS = TIER_BANDS[TIER_BANDS.length - 1].radiusMeters;

const UNKNOWN_LABEL = 'unknown';

/**
 * Maps an accuracy in metres to its precision tier. Invalid/negative/non-finite
 * input degrades to the least precise tier — never to a more confident one.
 */
export function resolvePrecisionTier(accuracyMeters: unknown): PrecisionTierInfo {
  let valid = false;
  let value = Number.POSITIVE_INFINITY;
  try {
    valid =
      typeof accuracyMeters === 'number' &&
      Number.isFinite(accuracyMeters) &&
      accuracyMeters >= 0;
    if (valid) value = accuracyMeters as number;
  } catch {
    valid = false;
  }

  let tier: PrecisionTier = 4;
  for (let i = 0; i < TIER_BANDS.length; i += 1) {
    if (value < TIER_BANDS[i].upperExclusive) {
      tier = i as PrecisionTier;
      break;
    }
  }

  const band = TIER_BANDS[tier];
  return {
    tier,
    radiusMeters: band.radiusMeters,
    label: valid ? band.label : UNKNOWN_LABEL,
  };
}

/* -------------------------------------------------------------------------- */
/* In-house hexagonal DGGS math (H3-equivalent concept)                       */
/* -------------------------------------------------------------------------- */

const EARTH_RADIUS_METERS = 6_371_008.8;
const DEG_TO_RAD = Math.PI / 180;
const SQRT3_OVER_3 = Math.sqrt(3) / 3;

interface HexCoord {
  q: number;
  r: number;
}

/** Cube-coordinate rounding to the nearest pointy-top hex cell. */
function roundAxial(q: number, r: number): HexCoord {
  const x = q;
  const z = r;
  const y = -x - z;
  let rx = Math.round(x);
  let ry = Math.round(y);
  let rz = Math.round(z);
  const dx = Math.abs(rx - x);
  const dy = Math.abs(ry - y);
  const dz = Math.abs(rz - z);
  if (dx > dy && dx > dz) rx = -ry - rz;
  else if (dy > dz) ry = -rx - rz;
  else rz = -rx - ry;
  return { q: rx, r: rz };
}

/** Wraps any longitude into the half-open interval [-180, 180). */
function normalizeLongitude(lon: number): number {
  return (((lon + 180) % 360) + 360) % 360 - 180;
}

/**
 * Local equirectangular metres -> axial hex coordinates for a given cell size.
 *
 * Raw equirectangular x puts +179.999 and -179.999 at opposite ends of the map.
 * Instead, longitude is wrapped into [-180,180) and snapped to the centre of a
 * whole number of columns around the parallel. The seam sits at the centre of
 * column 0, so both sides of the antimeridian collapse to that same column and
 * therefore to the same cell. Column centres also bound x to the circumference,
 * keeping the projection from stretching near the seam.
 */
function axialForPoint(lat: number, lon: number, hexSizeMeters: number): HexCoord {
  const latRad = lat * DEG_TO_RAD;
  const cosLat = Math.cos(latRad);
  const y = latRad * EARTH_RADIUS_METERS;
  const circumference = Math.max(1, 2 * Math.PI * EARTH_RADIUS_METERS * cosLat);
  const columns = Math.max(1, Math.round(circumference / hexSizeMeters));
  const u = (normalizeLongitude(lon) + 180) / 360; // [0, 1)
  const column = ((Math.floor(u * columns + 0.5) % columns) + columns) % columns;
  const seamSafeLon = -180 + ((column + 0.5) * 360) / columns;
  const x = seamSafeLon * DEG_TO_RAD * EARTH_RADIUS_METERS * cosLat;
  const q = (SQRT3_OVER_3 * x - y / 3) / hexSizeMeters;
  const r = ((2 / 3) * y) / hexSizeMeters;
  return roundAxial(q, r);
}

/* -------------------------------------------------------------------------- */
/* Input hardening                                                            */
/* -------------------------------------------------------------------------- */

interface SafePoint {
  lat: number;
  lon: number;
  accuracyMeters: number;
}

function safeFiniteNumber(value: unknown): number | null {
  try {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  } catch {
    return null;
  }
}

/** Reads a point without ever letting a hostile getter throw. */
function readPoint(point: unknown): SafePoint | null {
  try {
    if (!point || typeof point !== 'object') return null;
    const source = point as { lat?: unknown; lon?: unknown; accuracyMeters?: unknown };
    const lat = safeFiniteNumber(source.lat);
    const lon = safeFiniteNumber(source.lon);
    const accuracyMeters = safeFiniteNumber(source.accuracyMeters);
    if (lat === null || lon === null || accuracyMeters === null) return null;
    if (Math.abs(lat) > 90 || Math.abs(lon) > 180 || accuracyMeters < 0) return null;
    return { lat, lon, accuracyMeters };
  } catch {
    return null;
  }
}

function safeSalt(salt: unknown): string {
  try {
    return typeof salt === 'string' ? salt : String(salt);
  } catch {
    return '';
  }
}

function normalizeTier(tier: unknown): PrecisionTier {
  try {
    const numeric = typeof tier === 'number' ? tier : Number(tier);
    if (!Number.isFinite(numeric)) return 4;
    const integer = Math.trunc(numeric);
    if (integer <= 0) return 0;
    if (integer >= 4) return 4;
    return integer as PrecisionTier;
  } catch {
    return 4;
  }
}

/**
 * Canonical, salt-independent description of the coarse hex tile. This is the
 * only value ever fed to the digest; it is never returned or logged.
 */
function cellKey(point: SafePoint | null, tier: PrecisionTier): string {
  if (!point) return `hex|invalid|${tier}`;
  const hexSizeMeters = TIER_BANDS[tier].radiusMeters;
  const { q, r } = axialForPoint(point.lat, point.lon, hexSizeMeters);
  return `hex|${tier}|${q}|${r}`;
}

/* -------------------------------------------------------------------------- */
/* Keyed digest: FNV-1a HMAC (sync) + WebCrypto HMAC-SHA256 (async)            */
/* -------------------------------------------------------------------------- */

const FNV_OFFSET_BASIS = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

function utf8Bytes(input: string): number[] {
  try {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(input));
    }
  } catch {
    // fall through to the ASCII-safe manual encoding
  }
  const bytes: number[] = [];
  for (let i = 0; i < input.length; i += 1) bytes.push(input.charCodeAt(i) & 0xff);
  return bytes;
}

/**
 * WebCrypto accepts only `BufferSource` (ArrayBuffer / typed array), never a
 * plain `number[]`. Produce a real `Uint8Array`; fall back to a manual byte
 * buffer only where `TextEncoder` is unavailable.
 */
function utf8BufferSource(input: string): Uint8Array {
  try {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(input);
  } catch {
    // fall through to the manual encoding
  }
  const bytes = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i += 1) bytes[i] = input.charCodeAt(i) & 0xff;
  return bytes;
}

function fnv1a(bytes: number[]): number {
  let hash = FNV_OFFSET_BASIS >>> 0;
  for (let i = 0; i < bytes.length; i += 1) {
    hash ^= bytes[i];
    hash = Math.imul(hash, FNV_PRIME) >>> 0;
  }
  return hash >>> 0;
}

/** HMAC construction (ipad/opad) keyed by the salt, using FNV-1a as the PRF. */
function hmacFnv32(key: string, message: string): string {
  const keyBytes = utf8Bytes(key);
  const block = new Array<number>(16).fill(0);
  const keyDigest = fnv1a(keyBytes);
  for (let i = 0; i < 4; i += 1) block[i] = (keyDigest >>> (i * 8)) & 0xff;
  for (let i = 0; i < keyBytes.length; i += 1) block[i % 16] ^= keyBytes[i];

  const ipad = block.map((byte) => byte ^ 0x36);
  const opad = block.map((byte) => byte ^ 0x5c);
  const inner = fnv1a([...ipad, ...utf8Bytes(message)]);
  const outer = fnv1a([...opad, ...utf8Bytes(inner.toString(16).padStart(8, '0'))]);
  return outer.toString(16).padStart(8, '0');
}

/** Four domain-separated rounds -> a 128-bit, non-reversible hex digest. */
function hmacFnv128(key: string, message: string): string {
  let digest = '';
  for (let i = 0; i < 4; i += 1) digest += hmacFnv32(key, `${i}:${message}`);
  return digest;
}

function formatId(digest: string): string {
  return `hex_${digest.toLowerCase()}`;
}

/**
 * Deterministic, salt-sensitive, non-reversible cell id. Same point + salt +
 * tier always yields the same id; changing any of them changes it. Raw
 * coordinates are never part of the output.
 */
export function hexCellId(
  point: GeoPoint | null,
  salt: string,
  tier: PrecisionTier | number
): string {
  const normalizedTier = normalizeTier(tier);
  const safe = readPoint(point);
  const key = cellKey(safe, normalizedTier);
  try {
    return formatId(hmacFnv128(safeSalt(salt), key));
  } catch {
    // Absolute last resort: still deterministic, salted and coordinate-free.
    return formatId(hmacFnv128('fallback', `hex|invalid|${normalizedTier}`));
  }
}

interface SubtleCryptoLike {
  importKey(
    format: string,
    keyData: unknown,
    algorithm: unknown,
    extractable: boolean,
    usages: string[]
  ): Promise<unknown>;
  sign(algorithm: string, key: unknown, data: unknown): Promise<ArrayBuffer>;
}

/** True when the platform exposes the asynchronous WebCrypto HMAC API. */
export function isWebCryptoAvailable(): boolean {
  try {
    const candidate = (globalThis as { crypto?: { subtle?: SubtleCryptoLike } }).crypto;
    return Boolean(candidate && candidate.subtle && typeof candidate.subtle.sign === 'function');
  } catch {
    return false;
  }
}

/**
 * WebCrypto-preferring variant. Uses HMAC-SHA-256 when `crypto.subtle` exists and
 * falls back to the exact synchronous `hexCellId` digest when it does not (or if
 * the platform call fails). Note: the two algorithms intentionally produce
 * different (but equally stable) id families.
 */
export async function hexCellIdAsync(
  point: GeoPoint | null,
  salt: string,
  tier: PrecisionTier | number
): Promise<string> {
  const normalizedTier = normalizeTier(tier);
  const safe = readPoint(point);
  const key = cellKey(safe, normalizedTier);
  const saltText = safeSalt(salt);

  if (isWebCryptoAvailable()) {
    try {
      const subtle = (globalThis as { crypto?: { subtle?: SubtleCryptoLike } }).crypto!.subtle!;
      const cryptoKey = await subtle.importKey(
        'raw',
        utf8BufferSource(saltText),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const signature = await subtle.sign('HMAC', cryptoKey, utf8BufferSource(key));
      const digest = Array.from(new Uint8Array(signature))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
      return formatId(digest.slice(0, 32));
    } catch {
      // WebCrypto unavailable for this operation -> pure FNV fallback below.
    }
  }

  return formatId(hmacFnv128(saltText, key));
}

/* -------------------------------------------------------------------------- */
/* Shadow-only proximity builder                                              */
/* -------------------------------------------------------------------------- */

/** Accuracy -> confidence in [0,1]; tighter fixes are more confident. */
function confidenceFromAccuracy(accuracyMeters: number): number {
  const raw = 1 / (1 + accuracyMeters / 1000);
  if (!Number.isFinite(raw)) return 0;
  return Math.min(1, Math.max(0, raw));
}

/**
 * Builds the shadow-only proximity payload from an explicit browser geolocation
 * fix only. A denied/absent/invalid point returns `proximity: null` with an audit
 * reason. This function never performs IP geolocation of any kind.
 */
export function proximityFromGeolocation(
  point: GeoPoint | null,
  salt: string
): ProximityResult {
  const safe = readPoint(point);
  if (!safe) {
    const denied = point === null || point === undefined;
    return {
      proximity: null,
      reason: denied
        ? 'geolocation permission denied or position absent; no IP-geolocation fallback used'
        : 'geolocation position invalid; no IP-geolocation fallback used',
    };
  }

  // An unbounded/implausible accuracy cannot justify any finite radius. Reject
  // the fix outright rather than publishing `precision_radius: 5000` as ±5km.
  if (safe.accuracyMeters > MAX_REPORTED_ACCURACY_METERS) {
    return {
      proximity: null,
      reason: `geolocation accuracy ${safe.accuracyMeters}m exceeds supported maximum ${MAX_REPORTED_ACCURACY_METERS}m; no IP-geolocation fallback used`,
    };
  }

  const tierInfo = resolvePrecisionTier(safe.accuracyMeters);
  try {
    return {
      proximity: {
        id: hexCellId(safe, salt, tierInfo.tier),
        precision_radius: tierInfo.radiusMeters,
        confidence: confidenceFromAccuracy(safe.accuracyMeters),
      },
      reason: `browser geolocation accepted (${tierInfo.label}, tier ${tierInfo.tier}); no IP-geolocation fallback used`,
    };
  } catch {
    return {
      proximity: null,
      reason: 'geolocation processing failed; no IP-geolocation fallback used',
    };
  }
}

/* -------------------------------------------------------------------------- */
/* Shared body-emitter gate                                                    */
/* -------------------------------------------------------------------------- */

/**
 * The exact id encoding emitted by this module: `hex_` + 32 lowercase hex digits.
 * Both `proximityBodyField` emitters use this so no foreign id scheme is published.
 */
export const HEX_PROXIMITY_ID_PATTERN = Object.freeze(/^hex_[0-9a-f]{32}$/);

function safeObject(value: unknown): Record<string, unknown> | null {
  try {
    if (!value || typeof value !== 'object') return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

function safeRead(source: unknown, key: string): unknown {
  const object = safeObject(source);
  if (!object) return undefined;
  try {
    return object[key];
  } catch {
    return undefined;
  }
}

/** A freshly copied, validated proximity ready for an additive API body. */
export interface SanitizedProximityForBody {
  id: string;
  precision_radius: number;
  confidence: number;
  accuracy_m?: number;
}

/**
 * Single validation gate shared by both body emitters. Accepts a raw
 * `HexProximity` (backward-compatible with existing callers) or a result
 * envelope `{ proximity, reason }`; an envelope is published only when its
 * `reason` is EXACTLY `'ok'`. Enforces this module's id scheme, a finite
 * non-negative radius, and `0 <= confidence <= 1`. `requireAccuracy` makes a
 * positive finite `accuracy_m` mandatory (bridge); otherwise it is included
 * only when present and valid (adapter).
 */
export function sanitizeProximityForBody(
  source: unknown,
  requireAccuracy: boolean
): SanitizedProximityForBody | null {
  const envelope = safeObject(source);
  let isEnvelope = false;
  try {
    isEnvelope = Boolean(envelope && ('proximity' in envelope || 'reason' in envelope));
  } catch {
    isEnvelope = false;
  }

  let candidate: unknown = source;
  if (isEnvelope) {
    if (safeRead(envelope, 'reason') !== 'ok') return null;
    candidate = safeRead(envelope, 'proximity');
  }

  const target = safeObject(candidate);
  if (!target) return null;

  const id = safeRead(target, 'id');
  if (typeof id !== 'string' || !HEX_PROXIMITY_ID_PATTERN.test(id)) return null;

  const precisionRadius = safeFiniteNumber(safeRead(target, 'precision_radius'));
  const confidence = safeFiniteNumber(safeRead(target, 'confidence'));
  if (
    precisionRadius === null ||
    precisionRadius < 0 ||
    confidence === null ||
    confidence < 0 ||
    confidence > 1
  ) {
    return null;
  }

  const rawAccuracy = safeFiniteNumber(safeRead(target, 'accuracy_m'));
  if (requireAccuracy && (rawAccuracy === null || rawAccuracy <= 0)) return null;

  const sanitized: SanitizedProximityForBody = {
    id,
    precision_radius: precisionRadius,
    confidence,
  };
  if (rawAccuracy !== null && rawAccuracy > 0) sanitized.accuracy_m = rawAccuracy;
  return sanitized;
}
