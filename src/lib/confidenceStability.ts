/**
 * Confidence stability — pure, deterministic, non-throwing.
 *
 * A returning identity is identified ONLY by its stable (visitorId, hardwareId) pair.
 * Once that pair is present, its published confidence `score` and `tier` are a pure
 * function of the (normalized) pair plus the caller's stable `rawScore`. Volatile
 * observation channels — bot/automation, audio, privacy and network signals — are
 * NEVER read, so they cannot drift the result, no matter how hostile their values.
 *
 * HONESTY / CALIBRATION BOUNDARY:
 *   This helper owns NO calibration gate and NEVER emits a `calibration_status`. The
 *   only authority for 'calibrated' is `rarityHonesty.calibrationStatusFor` (>= 200
 *   labeled pairs AND held-out ECE <= 0.05). Score stability is NOT calibration and
 *   can never promote a record to 'calibrated'. The returned `tier` is a descriptive
 *   display band derived from the locked `confidenceBandForScore` mapping.
 *
 * No I/O, no clocks, no randomness, no module state. Every call is total: hostile,
 * malformed or partially observed input fails closed to a null-score record.
 */

import { confidenceBandForScore, type NumericConfidenceTier } from './rarityHonesty';

/* -------------------------------------------------------------------------- */
/* Public shapes                                                               */
/* -------------------------------------------------------------------------- */

/** Volatile observation channels. Accepted for API compatibility but NEVER read. */
export interface VolatileConfidenceInputs {
  bot?: unknown;
  audio?: unknown;
  privacy?: unknown;
  network?: unknown;
  [key: string]: unknown;
}

export interface StabilizeConfidenceInput {
  /** Stable first-party visitor identifier. */
  visitorId?: string | null;
  /** Stable hardware anchor identifier. */
  hardwareId?: string | null;
  /** Caller's stable raw confidence signal, expected on a 0..1 scale. */
  rawScore?: number | null;
  /** Deliberately ignored volatile channels (bot/audio/privacy/network). */
  volatileInputs?: VolatileConfidenceInputs | null;
  /** Caller's claimed tier — accepted, but never authoritative for the result. */
  tier?: unknown;
}

export interface StabilizedConfidence {
  /** Stable, quantized confidence in [0,1]; null when no stable pair / no valid score. */
  score: number | null;
  /** Display band derived from the stable score (never a calibration claim). */
  tier: NumericConfidenceTier;
  /** Deterministic key derived from the stable pair only; 'stab:none' when absent. */
  stabilityKey: string;
  /** True when quantization adjusted the caller's raw score. */
  changed: boolean;
  /** Stable, lowercase audit token (no ids, no volatile values). */
  reason: string;
}

/* -------------------------------------------------------------------------- */
/* Locked, documented policy constants                                         */
/* -------------------------------------------------------------------------- */

/** Smallest confidence step that can be published. Absorbs sub-quantum jitter. */
export const STABILITY_QUANTUM = 0.05;
export const NO_PAIR_STABILITY_KEY = 'stab:none';
/** Audit marker: calibration status is exclusively owned by this locked gate. */
export const CALIBRATION_GATE_OWNER = 'rarityHonesty.calibrationStatusFor';

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK64 = (1n << 64n) - 1n;

/* -------------------------------------------------------------------------- */
/* Defensive primitives — all total (never throw)                             */
/* -------------------------------------------------------------------------- */

/** Property read that survives null/undefined, primitives and throwing getters. */
function safeGet(source: unknown, key: string): unknown {
  if (source === null || source === undefined) return undefined;
  const kind = typeof source;
  if (kind !== 'object' && kind !== 'function') return undefined;
  try {
    return (source as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Lowercase, whitespace-collapsed, bounded id token; empty when unusable. */
function asToken(value: unknown): string {
  if (typeof value !== 'string') return '';
  const text = value.trim().toLowerCase().replace(/\s+/g, ' ');
  if (!text) return '';
  return text.length > 256 ? text.slice(0, 256) : text;
}

function finiteOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function round4(value: number): number {
  return Math.round(value * 10000) / 10000;
}

/** Pure 64-bit FNV-1a using BigInt only — no clock, no randomness, no SDK. */
function fnv1a64(input: string): bigint {
  let hash = FNV_OFFSET & MASK64;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= BigInt(input.charCodeAt(i));
    hash = (hash * FNV_PRIME) & MASK64;
  }
  return hash & MASK64;
}

/** 16 lowercase hex chars derived from the normalized pair and nothing else. */
function stabilityKeyFor(visitor: string, hardware: string): string {
  const canonical = `confidence-stability|v1|${visitor}|${hardware}`;
  return `stab:${fnv1a64(canonical).toString(16).padStart(16, '0')}`;
}

function nullResult(stabilityKey: string, reason: string): StabilizedConfidence {
  return { score: null, tier: 'New/Unobserved', stabilityKey, changed: false, reason };
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Freeze a confidence score/tier for a stable (visitorId, hardwareId) pair.
 *
 * Volatile inputs are structurally ignored: they are never read, so bot/audio/
 * privacy/network drift cannot affect the score, tier, key, changed flag or reason.
 * Returns a null-score record when no stable pair (or no finite raw score) exists.
 * Pure and non-throwing; the calibration gate is left untouched in rarityHonesty.
 */
export function stabilizeConfidence(
  input?: StabilizeConfidenceInput | null
): StabilizedConfidence {
  try {
    const source =
      input !== null && input !== undefined && (typeof input === 'object' || typeof input === 'function')
        ? (input as Record<string, unknown>)
        : {};

    // Only the stable pair enters the key. Volatile channels are never read.
    const visitor = asToken(safeGet(source, 'visitorId'));
    const hardware = asToken(safeGet(source, 'hardwareId'));

    if (!visitor && !hardware) return nullResult(NO_PAIR_STABILITY_KEY, 'no_stable_pair');
    if (!visitor) return nullResult(NO_PAIR_STABILITY_KEY, 'no_visitor_id');
    if (!hardware) return nullResult(NO_PAIR_STABILITY_KEY, 'no_hardware_id');

    const stabilityKey = stabilityKeyFor(visitor, hardware);

    const raw = finiteOrNull(safeGet(source, 'rawScore'));
    if (raw === null) return nullResult(stabilityKey, 'no_finite_raw_score');

    const normalized = round4(Math.min(1, Math.max(0, raw)));
    const stabilized = round4(
      Math.min(1, Math.round(normalized / STABILITY_QUANTUM) * STABILITY_QUANTUM)
    );
    const changed = stabilized !== normalized;

    return {
      // The quantized value is published only for display stability. The tier is derived
      // from the caller's RAW score so quantization can never upgrade the meaning:
      // e.g. raw 0.83 is 'Medium-High' and must not become 'High' after snapping to 0.85.
      tier: confidenceBandForScore(raw),
      score: stabilized,
      stabilityKey,
      changed,
      reason: changed ? 'score_quantized_for_stability' : 'score_stable',
    };
  } catch {
    // Hostile/proxy input must never break a response. Fail closed, stay uncalibrated.
    return nullResult(NO_PAIR_STABILITY_KEY, 'hostile_input_failed_closed');
  }
}
