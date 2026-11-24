/**
 * Supplementary high-recall COHORT derivation — additive, shadow-only, zero I/O.
 *
 * This module is deliberately NOT imported by the production server. It is a pure,
 * deterministic reference implementation of a candidate `supplementary_id_high_recall`
 * *cohort* surface. Its output is:
 *
 *   - never a canonical visitor id (there is no `visitor_id` field on the result);
 *   - never a verified device identity (no raw id/fingerprint is read or echoed);
 *   - never a scoring, verdict or matching input — `status` is always the literal 'shadow';
 *   - derived ONLY from the stable structural cohort groups of identityTiers tier 2.
 *
 * WHY TIER 2 ONLY, NOT TIER 3:
 *   `resolveHardwareSimHashProfile` (tier 3) folds screen geometry, color/pixel depth,
 *   system fonts and the IANA timezone NAME into its 512-bit hash. Those signals are out
 *   of scope for this conservative cohort, so tier 3's hash is deliberately NOT an input to
 *   `cohort_key`. Tier 3 is consulted solely as an honesty contract guard (it must keep
 *   reporting `heuristic: true` / `verifiedDeviceIdentity: false`); volatile inputs can
 *   therefore never move the cohort key.
 *
 * TOTAL / NON-THROWING: every hostile input (null, primitives, throwing proxies, hostile
 *   getters) degrades to a deterministic `cohort:unclassified` fail-closed result. No clock,
 *   random, network, storage or mutation is performed.
 */

import {
  resolveHardwareSimHashProfile,
  resolveSupplementaryHighRecall,
} from './identityTiers';

/** Version of this shadow derivation. Bump only alongside a new signed promotion contract. */
export const SUPPLEMENTARY_COHORT_VERSION = '1';

/** The only status this candidate can ever report. Promotion is outside this module. */
export type SupplementaryCohortStatus = 'shadow';

export interface SupplementaryCohortResult {
  /** Namespaced, non-canonical cohort label. NEVER a visitor id. */
  cohort_key: string;
  /** 0..100: how many stable cohort groups were observed. 0 when unclassified. */
  evidence_score: number;
  /** Schema-compatible string version, mirroring `confidence.version` in eventV4. */
  version: string;
  /** Always the literal 'shadow'; this field is tee-and-discard only. */
  status: SupplementaryCohortStatus;
}

/** Stable group prefixes mirrored from identityTiers tier 2. Screen geometry, timezone,
 *  font lists, deviceMemory, platform and every volatile probe are intentionally absent.
 *  The allowlist is explicit so a future tier-2 group cannot silently widen this cohort. */
const COHORT_GROUP_PREFIXES: ReadonlySet<string> = new Set([
  'arch',
  'browser',
  'cores',
  'device-class',
  'engine',
  'gpu-family',
  'gpu-renderer',
  'gpu-vendor',
  'os',
  'os-family',
]);

const UNCLASSIFIED_KEY = 'cohort:unclassified';
const COHORT_KEY_PREFIX = `cohort:v${SUPPLEMENTARY_COHORT_VERSION}:`;
const MAX_GROUP_KEY_LENGTH = 512;

/* Pure FNV-1a, BigInt-only (no crypto, no random, no clock). Two distinct offset bases
 * yield a 32-hex-char digest, mirroring the style of tier 3 without reusing its hash. */
const MASK64 = (1n << 64n) - 1n;
const FNV_PRIME64 = 0x100000001b3n;
const COHORT_HASH_OFFSETS: readonly bigint[] = [
  0xcbf29ce484222325n,
  0x84222325cbf29ce4n,
];

function fnv1a64(input: string, offset: bigint): bigint {
  let hash = offset & MASK64;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= BigInt(input.charCodeAt(i));
    hash = (hash * FNV_PRIME64) & MASK64;
  }
  return hash & MASK64;
}

function cohortDigest(serialized: string): string {
  return COHORT_HASH_OFFSETS.map((offset) =>
    fnv1a64(serialized, offset).toString(16).padStart(16, '0')
  ).join('');
}

/** Deterministic fail-closed result: no evidence, no cohort fingerprint, still shadow. */
function failClosed(): SupplementaryCohortResult {
  return {
    cohort_key: UNCLASSIFIED_KEY,
    evidence_score: 0,
    version: SUPPLEMENTARY_COHORT_VERSION,
    status: 'shadow',
  };
}

/**
 * Derive a shadow-only, namespaced cohort key from stable structural signals.
 *
 * The input is treated as wholly untrusted: it is never mutated, no field is echoed, and
 * any internal failure returns the fail-closed `cohort:unclassified` result instead of
 * throwing. Callers must keep this output out of canonical identity, scoring and verdict
 * paths until the additive-field promotion contract is satisfied.
 */
export function deriveSupplementaryCohort(input: unknown): SupplementaryCohortResult {
  try {
    // Honesty guard only. Tier 3's hash512 is intentionally discarded: it includes screen,
    // timezone and fonts. If the upstream helper ever stopped being a heuristic / claimed a
    // verified device identity, fail closed rather than emit a cohort.
    const profile = resolveHardwareSimHashProfile(input);
    if (
      profile.heuristic !== true ||
      profile.verifiedDeviceIdentity !== false ||
      !/^[0-9a-f]{128}$/.test(profile.hash512)
    ) {
      return failClosed();
    }

    // Tier 2 produces descriptive `grp:<prefix>:<value>` keys from stable groups only.
    // Re-validate against the explicit allowlist so no unapproved group enters the cohort.
    const groups = resolveSupplementaryHighRecall(input);
    const selected: string[] = [];
    for (const key of groups) {
      if (typeof key !== 'string' || key.length === 0 || key.length > MAX_GROUP_KEY_LENGTH) continue;
      if (!key.startsWith('grp:')) continue;
      const rest = key.slice(4);
      const separator = rest.indexOf(':');
      if (separator <= 0) continue;
      const prefix = rest.slice(0, separator);
      const value = rest.slice(separator + 1);
      if (!COHORT_GROUP_PREFIXES.has(prefix) || !value) continue;
      selected.push(key);
    }
    selected.sort();

    if (selected.length === 0) return failClosed();

    const cohort_key = COHORT_KEY_PREFIX + cohortDigest(selected.join('|'));
    const evidence_score = Math.min(
      100,
      Math.max(0, Math.round((selected.length / COHORT_GROUP_PREFIXES.size) * 100))
    );

    return {
      cohort_key,
      evidence_score,
      version: SUPPLEMENTARY_COHORT_VERSION,
      status: 'shadow',
    };
  } catch {
    return failClosed();
  }
}
