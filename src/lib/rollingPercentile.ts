/**
 * Rolling p98 high-activity threshold — pure-JavaScript nearest-rank fallback (RS6).
 *
 * WHY THIS EXISTS:
 *   SQLite 3.51+ exposes `percentile_cont` / `percentile_disc` only when the library is
 *   compiled with `SQLITE_ENABLE_PERCENTILE`. Durable Objects' embedded SQLite build may
 *   not include that compile flag, so a SQL-side percentile is not portable. This module
 *   is the deterministic, request-time JS fallback: the caller supplies the rolling
 *   observations and the threshold is a pure function of them. No SQL, no stored/stateful
 *   threshold, no `CURRENT_TIMESTAMP`.
 *
 * GUARANTEES (same vocabulary as `velocityThresholds.ts`):
 *   - PURE / NON-THROWING / ZERO SIDE EFFECTS: no clock reads, no alarms, no cron triggers,
 *     no timers, no I/O, no randomness, no module-level mutable state. Hostile input fails
 *     closed to the fixed floor instead of throwing. Caller arrays are never mutated.
 *   - COLD START: fewer than 100 usable samples => `fixed_small_corpus` with the fixed
 *     floor. For N < 50 the nearest-rank p98 degenerates to the maximum (ceil(0.98*N) === N),
 *     which carries no signal; that condition is reported in `reasons`.
 *   - BOUNDED WINDOW: at most 1000 observations are considered. The window is anchored to
 *     the data — the last N observations by position, or by caller-supplied timestamps —
 *     never to wall-clock time.
 *
 * ADDITIVE: this module is not imported by the production server today; it is an isolated
 * reference implementation and is safe to call from any request path.
 */

/** Fixed high-activity floor for a small / cold corpus. */
export const DEFAULT_FLOOR = 16;
/** Default minimum number of usable samples before an adaptive p98 is trusted. */
export const DEFAULT_MIN_SAMPLES = 100;
/** Hard upper bound on the number of observations considered. */
export const MAX_ROLLING_WINDOW = 1000;
/** Percentile rank used by the adaptive regime. */
export const PERCENTILE_P98 = 0.98;
/** Below this many samples, nearest-rank p98 === max and is meaningless. */
export const DEGENERATE_MAX_N = 50;

export type HighActivityMode = 'fixed_small_corpus' | 'adaptive_p98';

export interface ResolveHighActivityThresholdInput {
  /** Rolling observations (counts). The last `windowSize` are considered. */
  observations?: readonly number[] | null;
  /** Minimum threshold guard / cold-start fallback. Defaults to 16. */
  floor?: number;
  /** Usable samples required before adaptive mode. Defaults to 100. */
  minSamples?: number;
  /** Optional window length, clamped to [1, 1000]. Defaults to 1000. */
  windowSize?: number;
  /**
   * Optional caller-supplied timestamps aligned with `observations`. When usable, the
   * window is the last `windowSize` observations in timestamp order. These are plain
   * numbers supplied by the caller — no clock is ever read internally.
   */
  timestamps?: readonly number[] | null;
}

export interface ResolvedHighActivityThreshold {
  mode: HighActivityMode;
  threshold: number;
  /** Number of usable observations actually used from the window. */
  n: number;
  floor: number;
  /** Stable, lowercase audit tokens explaining the decision. */
  reasons: string[];
}

/* -------------------------------------------------------------------------- */
/* Defensive primitives — total (never throw)                                  */
/* -------------------------------------------------------------------------- */

/** Finite numbers pass through; everything else (NaN, ±Infinity, wrong types) becomes null. */
function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Positive finite integer, or `fallback` when hostile. Optionally clamped to `max`. */
function positiveInt(value: unknown, fallback: number, max?: number): number {
  const parsed = finiteNumber(value);
  if (parsed === null || !Number.isInteger(parsed) || parsed < 1) return fallback;
  return max === undefined ? parsed : Math.min(parsed, max);
}

/** Non-negative finite floor, or the default floor when hostile. */
function resolveFloor(value: unknown): number {
  const parsed = finiteNumber(value);
  return parsed !== null && parsed >= 0 ? parsed : DEFAULT_FLOOR;
}

function failClosed(reason: string): ResolvedHighActivityThreshold {
  return {
    mode: 'fixed_small_corpus',
    threshold: DEFAULT_FLOOR,
    n: 0,
    floor: DEFAULT_FLOOR,
    reasons: [reason],
  };
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Nearest-rank percentile: rank = ceil(p * N) over sanitized, ascending values (1-indexed).
 *
 * Pure and deterministic: a sorted copy is used, so the caller's array is never mutated.
 * Returns `null` (never throws) for non-array input, no finite numeric values, or an
 * out-of-range / non-finite `p`. Negative values are kept (this is a generic helper); the
 * threshold resolver below filters them out before calling this function.
 */
export function nearestRankPercentile(values: unknown, p: unknown): number | null {
  try {
    const rankFraction = finiteNumber(p);
    if (rankFraction === null || rankFraction <= 0 || rankFraction > 1) return null;
    if (!Array.isArray(values)) return null;

    const clean: number[] = [];
    for (const entry of values as unknown[]) {
      const value = finiteNumber(entry);
      if (value !== null) clean.push(value);
    }
    if (clean.length === 0) return null;

    clean.sort((a, b) => a - b);
    const rank = Math.max(1, Math.min(clean.length, Math.ceil(rankFraction * clean.length)));
    return clean[rank - 1];
  } catch {
    return null;
  }
}

/**
 * Resolve the high-activity threshold from caller-supplied rolling observations only.
 *
 *  - `n < minSamples` (default 100)  -> `fixed_small_corpus`, threshold = floor.
 *  - otherwise                       -> `adaptive_p98`, threshold = max(floor, p98).
 *
 * The window is the last `windowSize` observations (max 1000), anchored by position or by
 * caller-supplied `timestamps`. Nothing is scheduled, persisted or read from a clock.
 * Every return path is total and the caller's inputs are never mutated.
 */
export function resolveHighActivityThreshold(
  input?: ResolveHighActivityThresholdInput | null
): ResolvedHighActivityThreshold {
  try {
    const source: Record<string, unknown> =
      input !== null && input !== undefined && typeof input === 'object'
        ? (input as Record<string, unknown>)
        : {};

    const floor = resolveFloor(source['floor']);
    const minSamples = positiveInt(source['minSamples'], DEFAULT_MIN_SAMPLES);
    const windowSize = Math.min(positiveInt(source['windowSize'], MAX_ROLLING_WINDOW), MAX_ROLLING_WINDOW);

    const rawObservations = source['observations'];
    const observations: unknown[] = Array.isArray(rawObservations)
      ? (rawObservations as unknown[])
      : [];
    const reasons: string[] = [];

    /* ---- Anchor the bounded window to the data (never to wall-clock time). ---- */
    let window: unknown[];
    const timestamps = source['timestamps'];
    if (Array.isArray(timestamps)) {
      if (timestamps.length !== observations.length) {
        window = observations.slice(-windowSize);
        reasons.push('timestamps_ignored_length_mismatch');
        reasons.push('window_anchored_to_last_observations');
      } else {
        const pairs: Array<{ value: unknown; ts: number }> = [];
        let usable = true;
        for (let i = 0; i < observations.length; i += 1) {
          const ts = finiteNumber(timestamps[i]);
          if (ts === null) {
            usable = false;
            break;
          }
          pairs.push({ value: observations[i], ts });
        }
        if (usable) {
          pairs.sort((a, b) => a.ts - b.ts);
          window = pairs.slice(-windowSize).map((pair) => pair.value);
          reasons.push('window_anchored_by_supplied_timestamps');
        } else {
          window = observations.slice(-windowSize);
          reasons.push('timestamps_unusable_window_anchored_to_tail');
          reasons.push('window_anchored_to_last_observations');
        }
      }
    } else {
      window = observations.slice(-windowSize);
      if (observations.length > 0) reasons.push('window_anchored_to_last_observations');
    }

    if (observations.length > window.length) {
      reasons.push(
        windowSize < MAX_ROLLING_WINDOW ? 'window_truncated_to_requested_size' : 'window_capped_at_1000'
      );
    }

    /* ---- Sanitize: finite, non-negative counts only. ---- */
    const values: number[] = [];
    for (const entry of window) {
      const value = finiteNumber(entry);
      if (value !== null && value >= 0) values.push(value);
    }
    if (values.length < window.length) reasons.push('hostile_observations_discarded');

    const n = values.length;
    const counted = { n, floor };

    if (n === 0) {
      return {
        ...counted,
        mode: 'fixed_small_corpus',
        threshold: floor,
        reasons: [...reasons, 'no_usable_observations', 'fixed_floor_applied'],
      };
    }

    // ceil(0.98 * N) === N for N < 50, i.e. the percentile is just the maximum.
    if (n < DEGENERATE_MAX_N) reasons.push('p98_degenerates_to_max_below_50');

    if (n < minSamples) {
      return {
        ...counted,
        mode: 'fixed_small_corpus',
        threshold: floor,
        reasons: [...reasons, 'cold_start_n_lt_min_samples', 'fixed_floor_applied'],
      };
    }

    const p98 = nearestRankPercentile(values, PERCENTILE_P98);
    if (p98 === null) {
      return {
        ...counted,
        mode: 'fixed_small_corpus',
        threshold: floor,
        reasons: [...reasons, 'percentile_unavailable', 'fixed_floor_applied'],
      };
    }

    return {
      ...counted,
      mode: 'adaptive_p98',
      threshold: Math.max(floor, p98),
      reasons: [...reasons, 'adaptive_p98_of_rolling_window'],
    };
  } catch {
    return failClosed('hostile_input_failed_closed');
  }
}
