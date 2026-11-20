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
}

export interface FuzzyDecisionInput {
  query: bigint;
  candidates: readonly LshCandidate[];
}

export interface FuzzyDecision {
  match: boolean;
  bestHardwareId: string | null;
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
    similarity: best.similarity,
    margin,
    collisionDensity,
    candidateCount,
    reason,
    stage: match ? 'lsh_fuzzy' : 'new_enrollment',
  };
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
}

export interface IdentityResolution {
  stage: IdentityMatchStage;
  matchLabel: string;
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
      collisionRisk: 'low',
      confidenceTier: 'First-Party Continuity Match',
    };
  }

  // 2. Exact hardware + collision guard.
  if (input.exactHardwareId && (input.distinctStorageSeedsCount ?? 0) >= 2) {
    return {
      stage: 'exact_hardware',
      matchLabel: input.exactHardwareId,
      collisionRisk: 'low',
      confidenceTier: 'High-Agreement Hardware Match',
    };
  }

  // 3. LSH fuzzy (only when a query and candidates are supplied).
  if (input.query !== undefined && input.candidates && input.candidates.length > 0) {
    const fuzzy = decideLshFuzzyMatch({ query: input.query, candidates: input.candidates });
    if (fuzzy.match && fuzzy.bestHardwareId) {
      return {
        stage: 'lsh_fuzzy',
        matchLabel: fuzzy.bestHardwareId,
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
      collisionRisk: 'high',
      confidenceTier: 'Privacy-Hardened Profile (Reduced Entropy)',
    };
  }

  // 5. New enrollment.
  return {
    stage: 'new_enrollment',
    matchLabel: '',
    collisionRisk: 'low',
    confidenceTier: 'New Unobserved Profile',
  };
}
