/**
 * geoProximityBridge.ts — pure, non-throwing permission gate into `hexProximity.ts`.
 *
 * This module is the smallest possible bridge between an already-observed browser
 * geolocation permission decision + fix and the shadow-only hexagonal proximity
 * primitives in `hexProximity.ts`. It performs NO I/O: no fetch, no DNS, no
 * `navigator.geolocation` call, and — critically — no IP / GeoIP lookup.
 *
 * Design constraints (all deliberate):
 *  - Total on hostile input: throwing getters, proxies, symbols and primitives
 *    never escape as exceptions. Every path returns a well-formed result.
 *  - Fail closed: permission must be EXACTLY the string 'granted' (no trimming,
 *    no case folding, no coercion). Anything else is `permission_required`.
 *  - Fix gate: granted permission still needs finite lat/lon and accuracyM > 0.
 *    Anything else is `invalid_fix`.
 *  - NO IP fallback: `ipCity` is part of the input shape only so callers can pass
 *    a whole observation object through. It is NEVER read by `resolveProximity`
 *    (the function body contains no reference to it at all), so it cannot affect
 *    the id, the confidence, the radius, or the emitted body field. A missing or
 *    denied point yields `proximity: null` forever.
 *  - Confidence is derived exclusively from the reported accuracy (delegated to
 *    hexProximity's accuracy-only confidence function). Coordinates never
 *    influence confidence; they influence only the salted cell id.
 *  - Additive only: `proximityBodyField` returns a fresh `hex_proximity` object to
 *    spread into an API v4 body, or `undefined` when nothing may be emitted.
 *    `hex_proximity` is deliberately namespaced away from the IP-derived
 *    `proximity` / `location` blocks.
 */

import {
  proximityFromGeolocation,
  type HexProximity,
} from './hexProximity';

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Input accepted by `resolveProximity`. All fields are typed `unknown` on
 * purpose: observations arrive from hostile/partial environments and must be
 * validated defensively rather than trusted at the type level.
 *
 * `ipCity` is accepted for shape compatibility with a full observation record
 * but is intentionally never consumed. See the module header and the test suite.
 */
export interface ResolveProximityInput {
  permission?: unknown;
  lat?: unknown;
  lon?: unknown;
  /** Reported accuracy in metres. Must be a finite number strictly greater than 0. */
  accuracyM?: unknown;
  /** Ignored. Never used to derive proximity, confidence, radius or id. */
  ipCity?: unknown;
}

/** Shadow-only proximity payload emitted by this bridge (accuracy is additive). */
export interface BridgeProximity {
  id: string;
  precision_radius: number;
  confidence: number;
  accuracy_m: number;
}

export interface ResolveProximityResult {
  proximity: BridgeProximity | null;
  reason: string;
}

/** Additive API v4 body field. */
export interface ProximityBodyField {
  hex_proximity: BridgeProximity;
}

/* -------------------------------------------------------------------------- */
/* Stable reason tokens                                                       */
/* -------------------------------------------------------------------------- */

/** Permission was not exactly 'granted'. */
export const REASON_PERMISSION_REQUIRED = 'permission_required';
/** Permission was granted but the fix was missing, non-finite or non-positive. */
export const REASON_INVALID_FIX = 'invalid_fix';
/** A proximity was successfully resolved from the granted fix. */
export const REASON_OK = 'ok';

/**
 * Domain-separated, internal PRF key. The public `resolveProximity` signature
 * intentionally has no salt argument, so a fixed versioned constant is used;
 * ids remain deterministic, salted, one-way and coordinate-free.
 */
const BRIDGE_SALT = 'geoProximityBridge|v1';

/* -------------------------------------------------------------------------- */
/* Defensive, non-throwing readers                                            */
/* -------------------------------------------------------------------------- */

function safeObject(value: unknown): Record<string, unknown> | null {
  try {
    if (value === null || value === undefined || typeof value !== 'object') return null;
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

/** True only for an explicit API v4 version token (number or string). */
function isApiV4(apiVersion: unknown): boolean {
  if (apiVersion === 4) return true;
  if (typeof apiVersion !== 'string') return false;
  try {
    return /^v?4(?:\.0+)?$/.test(apiVersion.trim().toLowerCase());
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Resolves shadow-only proximity from an EXACT 'granted' permission and a valid
 * browser fix. This function never references `ipCity`; the only path to a
 * non-null proximity is the delegation to `proximityFromGeolocation` with a point
 * built exclusively from the validated `lat` / `lon` / `accuracyM` values.
 *
 * Returns `permission_required` when permission is not exactly 'granted', and
 * `invalid_fix` when the granted fix is missing, non-finite or has accuracyM <= 0.
 */
export function resolveProximity(
  input: ResolveProximityInput | null | undefined
): ResolveProximityResult {
  try {
    const record = safeObject(input);
    if (!isGranted(safeRead(record, 'permission'))) {
      return { proximity: null, reason: REASON_PERMISSION_REQUIRED };
    }

    const lat = safeFiniteNumber(safeRead(record, 'lat'));
    const lon = safeFiniteNumber(safeRead(record, 'lon'));
    const accuracyM = safeFiniteNumber(safeRead(record, 'accuracyM'));
    if (lat === null || lon === null || accuracyM === null || accuracyM <= 0) {
      return { proximity: null, reason: REASON_INVALID_FIX };
    }

    // The single delegation point: hexProximity re-validates WGS-84 ranges and
    // emits the salted, one-way, coordinate-free cell id and accuracy-only
    // confidence. No other proximity source is consulted.
    const delegated = proximityFromGeolocation(
      { lat, lon, accuracyMeters: accuracyM },
      BRIDGE_SALT
    );
    const core: HexProximity | null = delegated.proximity;
    if (!core) {
      return { proximity: null, reason: REASON_INVALID_FIX };
    }

    return {
      proximity: {
        id: core.id,
        precision_radius: core.precision_radius,
        confidence: core.confidence,
        accuracy_m: accuracyM,
      },
      reason: REASON_OK,
    };
  } catch {
    // Absolute fail-closed guard: even an unexpected internal failure is total.
    return { proximity: null, reason: REASON_INVALID_FIX };
  }
}

/**
 * Returns the additive API v4 body field for a resolved proximity, or
 * `undefined` when the field may not be emitted:
 *  - the API version is not v4 (defaults to v4 when omitted),
 *  - the result is missing / structurally unusable, or
 *  - the proximity is absent (permission denied / invalid fix).
 *
 * The returned object is a fresh copy so callers cannot mutate the source. Only
 * the browser-fix-derived `hex_proximity` shape is accepted; no IP-derived field
 * can be smuggled in through this function.
 */
export function proximityBodyField(
  result: ResolveProximityResult | null | undefined,
  apiVersion?: unknown
): ProximityBodyField | undefined {
  // Omitting the version means "v4" (the additive field is a v4 concept). An
  // explicitly passed undefined/null is NOT a v4 token — fail closed.
  const version = arguments.length < 2 ? 4 : apiVersion;
  if (!isApiV4(version)) return undefined;

  const record = safeObject(result);
  if (!record) return undefined;

  const proximity = safeObject(safeRead(record, 'proximity'));
  if (!proximity) return undefined;

  const id = safeRead(proximity, 'id');
  const precisionRadius = safeFiniteNumber(safeRead(proximity, 'precision_radius'));
  const confidence = safeFiniteNumber(safeRead(proximity, 'confidence'));
  const accuracyM = safeFiniteNumber(safeRead(proximity, 'accuracy_m'));
  if (
    typeof id !== 'string' ||
    id.length === 0 ||
    precisionRadius === null ||
    confidence === null ||
    accuracyM === null ||
    accuracyM <= 0
  ) {
    return undefined;
  }

  return {
    hex_proximity: {
      id,
      precision_radius: precisionRadius,
      confidence,
      accuracy_m: accuracyM,
    },
  };
}
