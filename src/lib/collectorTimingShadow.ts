/**
 * Additive collector-timing shadow — pure, deterministic, zero I/O.
 *
 * WHY THIS EXISTS:
 *   The identify payload already emits `load_get_timing` from timings the orchestrator
 *   actually recorded (`signals.meta.timingsMs`). This module adds an OPTIONAL, flag-gated
 *   shadow summary of those same timings for diagnostics only. It never reads a clock,
 *   never touches a timer/fallback, and is never consulted by any verdict, rank, digest or
 *   scoring path. When the diagnostics flag is off the caller does not call any of these
 *   functions at all, so the default path allocates nothing and stays byte-identical.
 *
 * GUARANTEES (same vocabulary as `rollingPercentile.ts`):
 *   - PURE / NON-THROWING / ZERO SIDE EFFECTS: no clock reads, no alarms, no timers, no I/O,
 *     no randomness, no module-level mutable state. Hostile input fails closed to neutral
 *     values instead of throwing. Caller objects are never mutated.
 *   - Percentiles are the existing `nearestRankPercentile` helper — imported, never forked.
 *   - Every return path is total and deterministic for a given input.
 */
import { nearestRankPercentile } from './rollingPercentile';

/** Descriptive p50 budget for collected timings, in milliseconds. */
export const P50_BUDGET_MS = 250;
/** Descriptive p95 budget for collected timings, in milliseconds. */
export const P95_BUDGET_MS = 800;

export interface CollectorTimingStats {
  /** Number of finite numeric timing observations that were usable. */
  count: number;
  /** Nearest-rank p50, or 0 when there are no usable observations. */
  p50: number;
  /** Nearest-rank p95, or 0 when there are no usable observations. */
  p95: number;
}

export interface CollectorBudgetEvaluation {
  /** True only when usable data exists and p50 is within P50_BUDGET_MS. */
  p50Within250: boolean;
  /** True only when usable data exists and p95 is within P95_BUDGET_MS. */
  p95Within800: boolean;
}

export interface CollectorTimingShadow extends CollectorTimingStats {
  budget: CollectorBudgetEvaluation;
}

/* -------------------------------------------------------------------------- */
/* Defensive primitives — total (never throw)                                  */
/* -------------------------------------------------------------------------- */

function neutralStats(): CollectorTimingStats {
  return { count: 0, p50: 0, p95: 0 };
}

function neutralBudget(): CollectorBudgetEvaluation {
  return { p50Within250: false, p95Within800: false };
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Nearest-rank p50 / p95 over the finite numeric values of `timingsMs`.
 *
 * Pure and deterministic: only finite numbers are considered, string keys are enumerated
 * in insertion order but the resulting values are sorted by the imported helper, and the
 * caller's object is never mutated. Null, non-object, array or fully-hostile input returns
 * the neutral `{ count: 0, p50: 0, p95: 0 }` rather than throwing.
 */
export function percentilesFromTimings(timingsMs: Record<string, number>): CollectorTimingStats {
  try {
    if (
      timingsMs === null ||
      timingsMs === undefined ||
      typeof timingsMs !== 'object' ||
      Array.isArray(timingsMs)
    ) {
      return neutralStats();
    }

    const values: number[] = [];
    const record = timingsMs as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      const value = record[key];
      if (typeof value === 'number' && Number.isFinite(value)) values.push(value);
    }
    if (values.length === 0) return neutralStats();

    return {
      count: values.length,
      p50: nearestRankPercentile(values, 0.5) ?? 0,
      p95: nearestRankPercentile(values, 0.95) ?? 0,
    };
  } catch {
    return neutralStats();
  }
}

/**
 * Descriptive budget readout for a stats record. Both flags stay false unless there is
 * usable data (`count > 0`) AND a finite percentile within the descriptive budget, so an
 * empty / hostile record never falsely claims to be "within budget". Never throws.
 */
export function evaluateCollectorBudget(stats: CollectorTimingStats): CollectorBudgetEvaluation {
  try {
    if (stats === null || stats === undefined || typeof stats !== 'object') return neutralBudget();
    const record = stats as unknown as Record<string, unknown>;
    const count = record['count'];
    const p50 = record['p50'];
    const p95 = record['p95'];
    const usable = typeof count === 'number' && Number.isFinite(count) && count > 0;
    return {
      p50Within250:
        usable && typeof p50 === 'number' && Number.isFinite(p50) && p50 <= P50_BUDGET_MS,
      p95Within800:
        usable && typeof p95 === 'number' && Number.isFinite(p95) && p95 <= P95_BUDGET_MS,
    };
  } catch {
    return neutralBudget();
  }
}

/**
 * Compose the complete shadow field from raw recorded timings. Total and deterministic;
 * accepts `unknown` so a missing/null `signals.meta.timingsMs` fails closed to neutral
 * values without ever throwing. This is the single helper the flag-gated caller invokes.
 */
export function buildTimingShadow(timingsMs: unknown): CollectorTimingShadow {
  const stats = percentilesFromTimings(timingsMs as Record<string, number>);
  return { ...stats, budget: evaluateCollectorBudget(stats) };
}
