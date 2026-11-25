/**
 * proximityAdapter.ts — permission-gated bridge into `hexProximity.ts`.
 *
 * This is a thin, PURE adapter. It performs no I/O: no `fetch`, no DNS, no
 * `navigator.geolocation` call, no IP/GeoIP lookup of any kind. It only reads an
 * already-observed browser-geolocation permission decision plus the position the
 * browser actually returned, and forwards a validated point to
 * `proximityFromGeolocation`. When permission is denied, absent, or merely
 * "prompt", proximity is `null` forever and an auditable reason is returned.
 *
 * Design constraints (mirrors hexProximity.ts):
 *  - Total on hostile input: throwing getters, symbols, bad types never escape.
 *  - Fail closed: an unverified/unknown permission state is treated as denied.
 *  - No IP fallback: the string "no IP-geolocation fallback used" is present in
 *    every reason so the guarantee is machine-checkable in telemetry.
 *  - Additive only: `proximityBodyField` returns an object to spread into an API
 *    v4 body, or `undefined` when nothing may be emitted. It never mutates input.
 *
 * Research-brief compliance note (H3-equivalent grid + salted pseudonyms):
 *  - Grid math and cell encoding are delegated to hexProximity.ts: in-house,
 *    zero-dependency, no npm H3. Face/antimeridian/pole guards are inherited
 *    from its WGS-84 validation (|lat| <= 90, |lon| <= 180) before any digest.
 *  - A raw cell is never published. Only hexProximity's one-way, salted id is
 *    forwarded, and only into the additive v4 field.
 *  - A salted cell is a PSEUDONYM, not identity. The emitted field carries no
 *    proof / match / verified claim and is never a verdict input (shadow only).
 *  - `versionedSalt` domain-separates the PRF key so salt rotation is explicit
 *    and auditable; the suite asserts version changes re-key every id.
 *  - Known delta with the brief's target format: hexProximity's synchronous id
 *    uses an FNV-1a HMAC construction with a `hex_` encoding. Its WebCrypto
 *    variant is real HMAC-SHA256 but async and still `hex_` encoded. The
 *    `v1|` + base64url(16-byte HMAC-SHA256) format therefore needs an upgrade
 *    to hexProximity itself, which is outside this adapter's two-file scope.
 */

import {
  proximityFromGeolocation,
  sanitizeProximityForBody,
  type HexProximity,
  type ProximityResult,
} from './hexProximity';

export type { HexProximity, ProximityResult } from './hexProximity';

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

/** Browser `GeolocationCoordinates` subset this adapter is willing to consume. */
export interface AdapterCoordinates {
  latitude?: number;
  longitude?: number;
  /** Reported accuracy in metres. Never inferred from an IP address. */
  accuracy?: number;
}

/** Browser `GeolocationPosition` subset this adapter is willing to consume. */
export interface AdapterPosition {
  coords?: AdapterCoordinates | null;
  timestamp?: number;
}

/**
 * An already-observed geolocation permission decision plus the browser-supplied
 * position. Both fields are optional because the adapter must survive partially
 * observed / hostile environments; missing data always degrades to `null`.
 */
export interface GeolocationPermissionInput {
  /** Explicit `navigator.permissions` / geolocation permission state. */
  permission?: string;
  /** Only a browser-granted fix; IP-derived coordinates are never accepted. */
  position?: AdapterPosition | null;
}

/**
 * Additive API v4 body field. `hex_proximity` is deliberately namespaced away
 * from the existing IP-derived `proximity` / `location` blocks.
 */
export interface ProximityBodyField {
  /** `accuracy_m` is included whenever the source carries a valid one. */
  hex_proximity: HexProximity & { accuracy_m?: number };
}

/** Shared audit marker present in every reason this module emits. */
export const NO_IP_FALLBACK_MARKER = 'no IP-geolocation fallback used';

/** Default domain-separation version for salted cell ids. */
export const PROXIMITY_SALT_VERSION = 'v1';

/**
 * Domain-separates a caller-held secret so key versions are explicit and
 * rotatable. The `v1|` prefix is applied to the PRF *key* (not to the emitted
 * id, whose encoding is owned by hexProximity). Pass the result as the `salt`
 * argument of `proximityFromPermission`.
 */
export function versionedSalt(
  secret: string,
  version: string = PROXIMITY_SALT_VERSION
): string {
  return `${version}|${secret}`;
}

/* -------------------------------------------------------------------------- */
/* Defensive readers (never throw, even on throwing getters / proxies)         */
/* -------------------------------------------------------------------------- */

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

function safeFiniteNumber(value: unknown): number | null {
  try {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  } catch {
    return null;
  }
}

/** True only for the exact string 'granted' — no trim, case-fold or coercion. */
function isGranted(value: unknown): boolean {
  try {
    return typeof value === 'string' && value === 'granted';
  } catch {
    return false;
  }
}

/** Label for audit reasons only — never used to grant permission. */
function safePermissionLabel(value: unknown): string {
  try {
    if (typeof value === 'string' && value.length > 0) return value;
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  } catch {
    // fall through
  }
  return 'unknown';
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Builds shadow-only proximity from a browser-geolocation permission decision.
 *
 * Returns `{ proximity: null, reason }` whenever the permission is denied,
 * unavailable, not exactly `granted`, or the granted position is unusable. There
 * is deliberately no IP fallback: the only path to a non-null proximity is a
 * `granted` state plus finite latitude/longitude/accuracy, forwarded verbatim to
 * `proximityFromGeolocation`.
 */
export function proximityFromPermission(
  geolocation: GeolocationPermissionInput | null | undefined,
  salt: string
): ProximityResult {
  const record = safeObject(geolocation);
  if (!record) {
    return {
      proximity: null,
      reason: `geolocation permission decision unavailable; ${NO_IP_FALLBACK_MARKER}`,
    };
  }

  const permission = safeRead(record, 'permission');
  if (!isGranted(permission)) {
    return {
      proximity: null,
      reason:
        permission === 'denied'
          ? `geolocation permission denied; ${NO_IP_FALLBACK_MARKER}`
          : `geolocation permission not granted (state=${safePermissionLabel(permission)}); ${NO_IP_FALLBACK_MARKER}`,
    };
  }

  const position = safeRead(record, 'position');
  const coords = safeRead(position, 'coords');
  const latitude = safeFiniteNumber(safeRead(coords, 'latitude'));
  const longitude = safeFiniteNumber(safeRead(coords, 'longitude'));
  const accuracy = safeFiniteNumber(safeRead(coords, 'accuracy'));

  if (latitude === null || longitude === null || accuracy === null) {
    return {
      proximity: null,
      reason: `geolocation granted but position/accuracy invalid; ${NO_IP_FALLBACK_MARKER}`,
    };
  }

  // The single delegation point: hexProximity re-validates WGS-84 ranges and
  // emits the salted, one-way cell id. No other proximity source is consulted.
  const result = proximityFromGeolocation(
    { lat: latitude, lon: longitude, accuracyMeters: accuracy },
    salt
  );
  if (!result.proximity) return result;

  return {
    proximity: result.proximity,
    reason: `geolocation permission granted; ${result.reason}`,
  };
}

/** True only for an explicit API v4 version token (number or string). */
function isApiV4(apiVersion: unknown): boolean {
  if (typeof apiVersion === 'number') return apiVersion === 4;
  if (typeof apiVersion !== 'string') return false;
  let token = '';
  try {
    token = apiVersion.trim().toLowerCase();
  } catch {
    return false;
  }
  return /^v?4(?:\.0+)?$/.test(token);
}

/**
 * Returns the additive API v4 body field for a resolved proximity, or
 * `undefined` when the field may not be emitted:
 *  - the API version is not v4 (defaults to v4 when omitted — same as the bridge),
 *  - an envelope's `reason` is not EXACTLY 'ok', or
 *  - the payload fails the shared id-scheme / radius / confidence gate.
 *
 * Validation is shared with the bridge emitter via `sanitizeProximityForBody`.
 * For backward compatibility a raw gated `HexProximity` (as returned by
 * `proximityFromPermission(...).proximity`) is accepted directly; a result
 * envelope `{ proximity, reason }` is accepted only with `reason === 'ok'`.
 * `accuracy_m` is included whenever the source carries a valid one, matching
 * the bridge emitter. The returned object is a fresh copy; no IP-derived field
 * can be smuggled in.
 */
export function proximityBodyField(
  proximity: HexProximity | ProximityResult | null | undefined,
  apiVersion?: unknown
): ProximityBodyField | undefined {
  // Same default as the bridge: omitting the version means v4; an explicitly
  // passed undefined/null is NOT a v4 token — fail closed.
  const version = arguments.length < 2 ? 4 : apiVersion;
  if (!isApiV4(version)) return undefined;

  const sanitized = sanitizeProximityForBody(proximity, false);
  if (!sanitized) return undefined;

  const hexProximity: HexProximity & { accuracy_m?: number } = {
    id: sanitized.id,
    precision_radius: sanitized.precision_radius,
    confidence: sanitized.confidence,
  };
  if (sanitized.accuracy_m !== undefined) hexProximity.accuracy_m = sanitized.accuracy_m;
  return { hex_proximity: hexProximity };
}
