/**
 * Shadow-only velocity / rarity threshold helpers.
 *
 * ADDITIVE: this module is not imported by the production server today. It mirrors the
 * vocabulary used by `server.ts` (`fixed_small_corpus`, p98, Clopper-Pearson rarity gates,
 * 5m/1h/24h velocity windows) as an isolated, side-effect-free reference implementation.
 *
 * PURE / NON-THROWING / ZERO SIDE EFFECTS:
 *  - no Durable Object alarms, cron triggers, timers or scheduling of any kind;
 *  - no database / storage reads or writes, no network calls, no clock or random reads;
 *  - hostile input is coerced or fail-closed to a safe default instead of throwing;
 *  - caller-owned arrays are never mutated, and repeated calls with the same inputs return
 *    the same result.
 */

/** Fixed high-activity floor used for a small daily corpus. */
export const FIXED_HIGH_ACTIVITY_FLOOR = 16;
/** Daily-active-visitor boundary between the fixed and adaptive regimes. */
export const SMALL_CORPUS_LIMIT = 100;
/** Hard cap applied to distinct-value velocity counts. */
export const VELOCITY_DISTINCT_CAP = 10_000;
/** Minimum 14-day corpus before rarity may be asserted (Clopper-Pearson cold-start gate). */
export const COLD_START_MIN_TOTAL = 200;

/** The three velocity windows carried by the server's VelocitySignals. */
const WINDOW_KEYS = ['5_minutes', '1_hour', '24_hours'] as const;
type WindowKey = (typeof WINDOW_KEYS)[number];

/* -------------------------------------------------------------------------- */
/* Shared defensive coercions                                                  */
/* -------------------------------------------------------------------------- */

/** Finite, non-negative numbers pass through; everything else becomes 0. */
function finiteNonNegative(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

/* -------------------------------------------------------------------------- */
/* 1. High-activity threshold mode                                             */
/* -------------------------------------------------------------------------- */

export interface HighActivityThreshold {
  /** Mirrors the server's `high_activity_threshold_mode` vocabulary, with the explicit
   *  adaptive label `adaptive_p98` instead of the server's short `p98`. */
  mode: 'fixed_small_corpus' | 'adaptive_p98';
  threshold: number;
  reason: string;
}

/**
 * Select the high-activity regime from the size of the daily-active visitor corpus.
 *
 *  - `dailyActiveVisitors < 100` → `fixed_small_corpus` with the fixed floor of 16, even when a
 *    distribution is supplied (a small corpus has no stable percentile).
 *  - `dailyActiveVisitors >= 100` → `adaptive_p98`: the 98th percentile of the optional supplied
 *    sorted distribution. With no usable distribution, fail closed to the same floor of 16 while
 *    still reporting the adaptive mode.
 *
 * Never schedules anything and never mutates `distribution`.
 */
export function highActivityThreshold(
  dailyActiveVisitors: number,
  distribution?: number[]
): HighActivityThreshold {
  try {
    const visitors = finiteNonNegative(dailyActiveVisitors);
    if (visitors < SMALL_CORPUS_LIMIT) {
      return {
        mode: 'fixed_small_corpus',
        threshold: FIXED_HIGH_ACTIVITY_FLOOR,
        reason: 'fixed_small_corpus: daily_active_visitors<100; no stable p98; floor 16 applied',
      };
    }

    // Large corpus → adaptive. Sort a sanitized copy so the caller's array is never mutated and
    // hostile / unsorted input cannot skew the percentile or throw.
    const raw: unknown[] = Array.isArray(distribution) ? (distribution as unknown[]) : [];
    const values = raw
      .map((entry) => finiteNonNegative(entry))
      .filter((value) => value > 0)
      .slice()
      .sort((a, b) => a - b);

    if (values.length === 0) {
      return {
        mode: 'adaptive_p98',
        threshold: FIXED_HIGH_ACTIVITY_FLOOR,
        reason:
          'adaptive_p98: corpus>=100 but no usable distribution supplied; defensive floor 16 applied',
      };
    }

    const index = Math.max(0, Math.min(values.length - 1, Math.ceil(values.length * 0.98) - 1));
    return {
      mode: 'adaptive_p98',
      threshold: Math.max(1, values[index]),
      reason: 'adaptive_p98: corpus>=100; p98 of supplied sorted daily-event distribution',
    };
  } catch {
    return {
      mode: 'fixed_small_corpus',
      threshold: FIXED_HIGH_ACTIVITY_FLOOR,
      reason: 'fixed_small_corpus: hostile input; defensive floor 16 applied',
    };
  }
}

/* -------------------------------------------------------------------------- */
/* 2. Velocity distinct-value cap                                              */
/* -------------------------------------------------------------------------- */

export interface VelocityWindowCounts {
  '5_minutes'?: number;
  '1_hour'?: number;
  '24_hours'?: number;
}

/**
 * Counts accepted by `velocityCap`. Each field is intentionally `unknown` so malformed input can
 * be exercised directly: `distinct` may be a single window map or a map of named distinct signals
 * (e.g. distinct_ip / distinct_linked_id), while `events` / `ip_events` may be a window map or a
 * bare 24h number. Events are kept exact and are never capped.
 */
export interface VelocityCapInput {
  distinct?: unknown;
  events?: unknown;
  ip_events?: unknown;
}

export interface VelocityCapResult {
  /** True once any distinct-value window exceeds 10000: suppress the 5m and 1h windows. */
  omitShortWindows: boolean;
  /** 24h distinct count capped at 10000. */
  capped24h: number;
  /** Exact, uncapped 24h event count. */
  eventsExact: number;
  /** Exact, uncapped 24h per-IP event count. */
  ipEventsExact: number;
}

type SafeWindowCounts = Required<VelocityWindowCounts>;

function readWindowMap(value: unknown): SafeWindowCounts {
  const out: SafeWindowCounts = { '5_minutes': 0, '1_hour': 0, '24_hours': 0 };
  if (typeof value === 'number') {
    out['24_hours'] = finiteNonNegative(value);
    return out;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  const record = value as Record<string, unknown>;
  for (const key of WINDOW_KEYS as readonly WindowKey[]) {
    out[key] = finiteNonNegative(record[key]);
  }
  return out;
}

/** Aggregate a single window map or a map of named distinct signals into one worst-case view. */
function readDistinct(value: unknown): SafeWindowCounts {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    const isWindowMap = WINDOW_KEYS.some((key) => typeof record[key] === 'number');
    if (isWindowMap) return readWindowMap(record);

    const aggregate: SafeWindowCounts = { '5_minutes': 0, '1_hour': 0, '24_hours': 0 };
    for (const key of Object.keys(record)) {
      const window = readWindowMap(record[key]);
      for (const wk of WINDOW_KEYS as readonly WindowKey[]) {
        aggregate[wk] = Math.max(aggregate[wk], window[wk]);
      }
    }
    return aggregate;
  }
  return readWindowMap(value);
}

/**
 * Cap distinct velocity values at 10000. Above the cap, the 5m/1h windows are omitted and the
 * 24h distinct count is capped, while event and per-IP event counts stay exact.
 */
export function velocityCap(counts: VelocityCapInput): VelocityCapResult {
  try {
    const source: VelocityCapInput =
      counts && typeof counts === 'object' && !Array.isArray(counts) ? counts : {};
    const distinct = readDistinct(source.distinct);
    const events = readWindowMap(source.events);
    const ipEvents = readWindowMap(source.ip_events);

    const maxDistinct = Math.max(
      distinct['5_minutes'],
      distinct['1_hour'],
      distinct['24_hours']
    );

    return {
      omitShortWindows: maxDistinct > VELOCITY_DISTINCT_CAP,
      capped24h: Math.min(distinct['24_hours'], VELOCITY_DISTINCT_CAP),
      eventsExact: events['24_hours'],
      ipEventsExact: ipEvents['24_hours'],
    };
  } catch {
    return { omitShortWindows: false, capped24h: 0, eventsExact: 0, ipEventsExact: 0 };
  }
}

/* -------------------------------------------------------------------------- */
/* 3. 14-day rarity bucket                                                    */
/* -------------------------------------------------------------------------- */

export type RarityBucket =
  | 'insufficient_data'
  | 'unobserved'
  | 'common'
  | 'uncommon'
  | 'rare_p95'
  | 'very_rare_p99';

export interface RarityBucketResult {
  bucket: RarityBucket;
  rare: boolean;
  reason: string;
}

/** Exact one-sided Clopper-Pearson upper bound (mirrors telemetryContract.ts). */
function clopperPearsonUpperBound(k: number, n: number, alpha = 0.05): number {
  if (n <= 0) return 1;
  const successes = Math.max(0, Math.min(n, Math.floor(k)));
  const cdf = (p: number): number => {
    if (p <= 0) return 0;
    if (p >= 1) return 1;
    let term = Math.exp(n * Math.log1p(-p));
    let sum = term;
    for (let i = 1; i <= successes; i += 1) {
      term *= ((n - i + 1) / i) * (p / (1 - p));
      sum += term;
      if (sum > 1) return 1;
    }
    return Math.min(1, sum);
  };
  let low = 0;
  let high = 1;
  for (let i = 0; i < 80; i += 1) {
    const mid = (low + high) / 2;
    if (cdf(mid) > alpha) low = mid;
    else high = mid;
  }
  return Math.min(1, Math.max(0, (low + high) / 2));
}

function isObservedFlag(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) && value > 0;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return normalized.length > 0 && normalized !== 'false' && normalized !== '0';
  }
  return false;
}

/**
 * Classify 14-day configuration rarity into one of six buckets.
 *
 * Cold-start gating requires `total14d >= 200` before `rare` may ever be true, and a missing /
 * falsy `observed` flag never asserts rarity. With a sufficient corpus, the bucket is derived
 * from the exact Clopper-Pearson 95% upper bound, mirroring the server's p95 / p99_plus gates.
 */
export function rarityBucket(
  frequency14d: unknown,
  total14d: unknown,
  observed: unknown
): RarityBucketResult {
  try {
    const frequency = finiteNonNegative(frequency14d);
    const total = finiteNonNegative(total14d);

    if (!isObservedFlag(observed)) {
      return {
        bucket: 'unobserved',
        rare: false,
        reason: 'no_observation: observed=false; rarity not asserted',
      };
    }
    if (total < COLD_START_MIN_TOTAL) {
      return {
        bucket: 'insufficient_data',
        rare: false,
        reason: 'cold_start_gate: total14d<200; rarity not asserted',
      };
    }

    const upper = clopperPearsonUpperBound(Math.min(frequency, total), total, 0.05);
    if (upper <= 0.01) {
      return {
        bucket: 'very_rare_p99',
        rare: true,
        reason: 'clopper_pearson_upper<=0.01; corpus>=200; p99_plus',
      };
    }
    if (upper <= 0.05) {
      return {
        bucket: 'rare_p95',
        rare: true,
        reason: 'clopper_pearson_upper<=0.05; corpus>=200; p95',
      };
    }
    if (upper <= 0.20) {
      return { bucket: 'uncommon', rare: false, reason: 'clopper_pearson_upper<=0.20; not rare' };
    }
    return { bucket: 'common', rare: false, reason: 'clopper_pearson_upper>0.20; common' };
  } catch {
    return {
      bucket: 'insufficient_data',
      rare: false,
      reason: 'hostile input; cold-start gate; rarity not asserted',
    };
  }
}
