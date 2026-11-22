/**
 * Shadow-only, additive helpers for the Phase 1 VPN-methods "truth gap".
 *
 * This module is intentionally inert: no production caller consumes it yet. Its purpose is to
 * give the canonical, client/server-shared resolver for the `vpnMethods` block a single home so a
 * later consumer can be diffed against the legacy payload without either side re-deriving facts.
 *
 * Guarantees (mirroring `timezone.ts` / `telemetryContract.ts`):
 *  - pure and side-effect free at import time;
 *  - NEVER throws — malformed / legacy payloads degrade to safe defaults or diagnostics;
 *  - `timezone_mismatch` is derived ONLY through `canonicalTimezone` / `timezonesEquivalent`,
 *    never through a raw string `!==` and never through UTC-offset coincidence. `Asia/Calcutta`
 *    and `Asia/Kolkata` are the same identity (false); `Asia/Singapore` and `Asia/Hong_Kong`
 *    are both UTC+8 but different identities (true). An unresolved side is absence of evidence,
 *    so it produces false rather than a manufactured match or mismatch;
 *  - `origin_country` is taken ONLY from the explicit, verified ip-geolocation country param and
 *    is never invented from a timezone string.
 */

import { canonicalTimezone, timezonesEquivalent } from './timezone';

/* -------------------------------------------------------------------------- */
/* Input / output contracts                                                    */
/* -------------------------------------------------------------------------- */

/** Everything needed to resolve the canonical `vpnMethods` block in a shadow pass. */
export interface VpnMethodsInput {
  /** Browser-reported IANA zone (may be a legacy alias such as `Asia/Calcutta`). */
  browserTimezone?: string | null;
  /** IP-geolocation IANA zone (may be the canonical replacement, e.g. `Asia/Kolkata`). */
  ipTimezone?: string | null;
  /**
   * Non-authoritative legacy hint. It is recorded in `reasons` when it disagrees with the
   * canonical resolution, but it is NEVER used to derive `timezone_mismatch`: only the two
   * timezone identities above may do that.
   */
  canonicalMismatch?: boolean | null;
  /** Verified ISO 3166-1 alpha-2 country from IP geolocation — the only origin-country source. */
  ipCountry?: string | null;
  publicVpn?: boolean | null;
  relay?: boolean | null;
  osMismatch?: boolean | null;
  mlPrediction?: boolean | null;
}

/** Shape returned by `resolveVpnMethods`; structurally identical to the server `vpnMethods` block. */
export interface ResolvedVpnMethods {
  timezone_mismatch: boolean;
  public_vpn: boolean;
  relay: boolean;
  os_mismatch: boolean;
  ml_prediction: boolean;
  origin_country: string | null;
  /** Human-readable audit trail for every value above. */
  reasons: string[];
}

/** The comparable subset of a `vpnMethods` block used by the parity diagnostic. */
export interface VpnMethodsParityInput {
  timezone_mismatch?: boolean | null;
  public_vpn?: boolean | null;
  relay?: boolean | null;
  os_mismatch?: boolean | null;
  ml_prediction?: boolean | null;
  origin_country?: string | null;
}

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

const EMPTY_INPUT: VpnMethodsInput = Object.freeze({});
const EMPTY_PARITY: VpnMethodsParityInput = Object.freeze({});

/** Placeholders used by GeoIP providers that are not real ISO alpha-2 countries. */
const INVALID_COUNTRY_CODES: ReadonlySet<string> = new Set(['XX', 'T1']);

function asObject<T extends object>(value: T | null | undefined, fallback: T): T {
  return value !== null && typeof value === 'object' ? value : fallback;
}

/** Only a literal `true` is a fired flag; null / undefined / truthy junk stay false. */
function isTrue(value: boolean | null | undefined): boolean {
  return value === true;
}

/**
 * Accepts only a well-formed ISO alpha-2 code from the verified country param. Never attempts to
 * infer a country from a timezone, a coordinate or a provider name.
 */
function verifiedCountryCode(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const code = value.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return null;
  if (INVALID_COUNTRY_CODES.has(code)) return null;
  return code;
}

function safeDefaults(note: string): ResolvedVpnMethods {
  return {
    timezone_mismatch: false,
    public_vpn: false,
    relay: false,
    os_mismatch: false,
    ml_prediction: false,
    origin_country: null,
    reasons: [note],
  };
}

/* -------------------------------------------------------------------------- */
/* Canonical resolver                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Resolves a shadow `vpnMethods` block from raw evidence.
 *
 * The timezone axis is the whole point of this helper: a mismatch is reported only when BOTH
 * sides resolve to a canonical IANA identity AND those identities differ. That makes alias pairs
 * (`Asia/Calcutta` / `Asia/Kolkata`) resolve to `false` and keeps shared-offset lookalikes
 * (`Asia/Singapore` / `Asia/Hong_Kong`) as a real mismatch without ever consulting an offset.
 *
 * The other methods are simple canonical mirrors of their verified inputs. `canonicalMismatch`
 * is deliberately NOT trusted as a source of truth — it is only surfaced in `reasons` when it
 * disagrees, which is the additive signal a shadow comparison needs.
 */
export function resolveVpnMethods(
  input: VpnMethodsInput | null | undefined,
): ResolvedVpnMethods {
  try {
    const src = asObject(input, EMPTY_INPUT);
    const reasons: string[] = [];

    /* --- timezone_mismatch: canonical identities only ----------------------- */
    const browserTz = typeof src.browserTimezone === 'string' ? src.browserTimezone : null;
    const ipTz = typeof src.ipTimezone === 'string' ? src.ipTimezone : null;
    const canonicalBrowser = canonicalTimezone(browserTz);
    const canonicalIp = canonicalTimezone(ipTz);

    let timezoneMismatch = false;
    if (canonicalBrowser !== null && canonicalIp !== null) {
      // Both sides resolved: equivalence is a canonical name comparison, never raw/offset.
      timezoneMismatch = !timezonesEquivalent(browserTz, ipTz);
      if (timezoneMismatch) {
        reasons.push(
          `timezone_mismatch=true: canonical identities differ (${canonicalBrowser} vs ${canonicalIp})`,
        );
      } else {
        reasons.push(
          `timezone_mismatch=false: ${canonicalBrowser} and ${canonicalIp} resolve to the same canonical identity`,
        );
      }
    } else {
      // Unresolved side => absence of evidence, never a mismatch.
      reasons.push(
        `timezone_mismatch=false: unresolved timezone side (browser=${
          canonicalBrowser ?? 'unresolved'
        }, ip=${canonicalIp ?? 'unresolved'})`,
      );
    }

    // The legacy canonical hint is diagnostic-only: it can never override canonical resolution.
    if (src.canonicalMismatch === true && !timezoneMismatch) {
      reasons.push(
        'canonicalMismatch=true hint ignored: canonical timezone resolution did not confirm a mismatch',
      );
    } else if (src.canonicalMismatch === false && timezoneMismatch) {
      reasons.push(
        'canonicalMismatch=false hint ignored: canonical timezone resolution confirmed a mismatch',
      );
    }

    /* --- concrete tunnel methods ------------------------------------------- */
    const publicVpn = isTrue(src.publicVpn);
    const relay = isTrue(src.relay);
    const osMismatch = isTrue(src.osMismatch);
    const mlPrediction = isTrue(src.mlPrediction);
    if (publicVpn) reasons.push('public_vpn=true from verified publicVpn flag');
    if (relay) reasons.push('relay=true from verified relay flag');
    if (osMismatch) reasons.push('os_mismatch=true from verified osMismatch flag');
    if (mlPrediction) reasons.push('ml_prediction=true from verified mlPrediction flag');

    /* --- origin country: verified param only -------------------------------- */
    const originCountry = verifiedCountryCode(src.ipCountry);
    if (originCountry !== null) {
      reasons.push(`origin_country=${originCountry}: taken from the verified ipCountry param`);
    } else {
      reasons.push('origin_country=null: no verified ipCountry param (never inferred from timezone)');
    }

    return {
      timezone_mismatch: timezoneMismatch,
      public_vpn: publicVpn,
      relay,
      os_mismatch: osMismatch,
      ml_prediction: mlPrediction,
      origin_country: originCountry,
      reasons,
    };
  } catch {
    return safeDefaults('resolveVpnMethods: unexpected input; returning safe defaults');
  }
}

/* -------------------------------------------------------------------------- */
/* Additive parity diagnostic                                                  */
/* -------------------------------------------------------------------------- */

const PARITY_FLAG_KEYS = [
  'timezone_mismatch',
  'public_vpn',
  'relay',
  'os_mismatch',
  'ml_prediction',
] as const;

/**
 * Pure, non-throwing parity check between an existing (legacy) `vpnMethods` block and the
 * freshly `resolveVpnMethods` block. Returns a human-readable issue for every field that
 * diverges; an empty array means the two blocks agree. Missing / malformed values fail closed to
 * `false` (or `null` for the country) so this can be called on partial legacy payloads safely.
 */
export function vpnMethodsParityIssue(
  existing: VpnMethodsParityInput | null | undefined,
  resolved: VpnMethodsParityInput | null | undefined,
): string[] {
  try {
    const issues: string[] = [];
    const ex = asObject(existing, EMPTY_PARITY);
    const res = asObject(resolved, EMPTY_PARITY);

    for (const key of PARITY_FLAG_KEYS) {
      const exValue = isTrue(ex[key]);
      const resValue = isTrue(res[key]);
      if (exValue !== resValue) {
        issues.push(`${key}: existing=${exValue} resolved=${resValue}`);
      }
    }

    const exCountry = verifiedCountryCode(ex.origin_country);
    const resCountry = verifiedCountryCode(res.origin_country);
    if (exCountry !== resCountry) {
      issues.push(
        `origin_country: existing=${exCountry ?? 'null'} resolved=${resCountry ?? 'null'}`,
      );
    }

    return issues;
  } catch {
    return ['vpnMethodsParityIssue: unexpected input; diagnostics unavailable'];
  }
}
