/**
 * Rare-signal cold-start statistics — lazy, pure and SDK-free.
 *
 * Research basis (RS7):
 *  - Clopper–Pearson exact one-sided upper bound:
 *      p_upper = BetaInv(1 - alpha, k + 1, n - k)
 *    where BetaInv is the inverse regularised incomplete beta (the Beta(k+1, n-k)
 *    quantile at level 1-alpha). Closed forms: k = 0 -> 1 - alpha^(1/n);
 *    k = n -> 1. The "rule of three" (3/n, n > 30) is a rough alpha~0.05
 *    approximation of the k=0 closed form, NOT a substitute for it.
 *  - A "rare at p*" claim is made ONLY when p_upper < p*; never from raw k/n.
 *  - Zero-hit sample floor: n >= -ln(alpha)/p* (alpha=0.05, p*=0.01 -> ~300),
 *    with a hard floor n_min (default 30) below which nothing is inferred.
 *  - Multiplicity across devices uses Bonferroni (adjustedAlpha = alpha/deviceCount);
 *    Holm would need the full ordered family, which a single decision does not have.
 *  - No alarms/crons: the 14-day window is recomputed lazily at read time from dated
 *    buckets; partial first days are never extrapolated into full-day counts.
 *
 * Everything here is a pure, non-throwing function. No timers, no I/O, no randomness.
 */

/* -------------------------------------------------------------------------- */
/* 1. oneSidedUpper — Clopper–Pearson one-sided upper bound                    */
/* -------------------------------------------------------------------------- */

/** Lanczos coefficients (g = 7, n = 9): log-gamma to ~1e-14 relative accuracy. */
const LANCZOS: readonly number[] = [
  0.99999999999980993,
  676.5203681218851,
  -1259.1392167224028,
  771.32342877765313,
  -176.61502916214059,
  12.507343278686905,
  -0.13857109526572012,
  9.9843695780195716e-6,
  1.5056327351493116e-7,
];

function logGamma(z: number): number {
  if (z < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * z)) - logGamma(1 - z);
  }
  const shifted = z - 1;
  let x = LANCZOS[0];
  for (let i = 1; i < LANCZOS.length; i += 1) {
    x += LANCZOS[i] / (shifted + i);
  }
  const t = shifted + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (shifted + 0.5) * Math.log(t) - t + Math.log(x);
}

/** Continued fraction for the incomplete beta (Lentz's method, Numerical Recipes). */
function betaContinuedFraction(a: number, b: number, x: number): number {
  const MAX_ITERATIONS = 200;
  const EPSILON = 3e-14;
  const FPMIN = 1e-300;
  const qab = a + b;
  const qap = a + 1;
  const qam = a - 1;
  let c = 1;
  let d = 1 - (qab * x) / qap;
  if (Math.abs(d) < FPMIN) d = FPMIN;
  d = 1 / d;
  let h = d;
  for (let m = 1; m <= MAX_ITERATIONS; m += 1) {
    const m2 = 2 * m;
    let aa = (m * (b - m) * x) / ((qam + m2) * (a + m2));
    d = 1 + aa * d;
    if (Math.abs(d) < FPMIN) d = FPMIN;
    c = 1 + aa / c;
    if (Math.abs(c) < FPMIN) c = FPMIN;
    d = 1 / d;
    h *= d * c;
    aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2));
    d = 1 + aa * d;
    if (Math.abs(d) < FPMIN) d = FPMIN;
    c = 1 + aa / c;
    if (Math.abs(c) < FPMIN) c = FPMIN;
    d = 1 / d;
    const delta = d * c;
    h *= delta;
    if (Math.abs(delta - 1) < EPSILON) break;
  }
  return h;
}

/** Regularised incomplete beta I_x(a,b), computed symmetrically for stability. */
function regularizedIncompleteBeta(a: number, b: number, x: number): number {
  if (!(x > 0)) return 0;
  if (!(x < 1)) return 1;
  const front =
    Math.exp(
      logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log1p(-x)
    );
  if (x < (a + 1) / (a + b + 2)) {
    return (front * betaContinuedFraction(a, b, x)) / a;
  }
  return 1 - (front * betaContinuedFraction(b, a, 1 - x)) / b;
}

/** Invert I_x(a,b) = target by bisection (monotone in x). */
function betaInverse(target: number, a: number, b: number): number {
  let low = 0;
  let high = 1;
  for (let i = 0; i < 100; i += 1) {
    const mid = (low + high) / 2;
    if (regularizedIncompleteBeta(a, b, mid) < target) low = mid;
    else high = mid;
  }
  return (low + high) / 2;
}

function normalizeAlpha(alpha: unknown): number {
  if (typeof alpha !== 'number' || !Number.isFinite(alpha)) return 0.05;
  return Math.max(0, Math.min(1, alpha));
}

/**
 * Exact-ish Clopper–Pearson one-sided upper confidence bound for `k` hits in `n`
 * observations at significance `alpha` (default 0.05).
 *
 * Closed forms:
 *   k = 0 -> 1 - alpha^(1/n)   (evaluated as -expm1(log(alpha)/n) for precision)
 *   k = n -> 1
 *   n <= 0 -> 1                 (no data can never bound prevalence)
 *
 * For 0 < k < n the bound is the Beta(k+1, n-k) quantile at 1-alpha, computed by
 * a Lanczos log-gamma + continued-fraction incomplete beta + bisection inversion.
 *
 * Approximation limits: the log-gamma is accurate to ~1e-14, the continued fraction
 * to ~3e-14, and bisection is capped at 100 steps (~1e-30, far below double precision).
 * Extremely large n, k near 0/n, or alpha at 0/1 can lose a few digits to cancellation;
 * the result is therefore clamped to [0,1]. It is a numerical approximation of an exact
 * frequentist bound, not a Bayesian posterior and not a raw k/n estimate.
 */
export function oneSidedUpper(k: unknown, n: unknown, alpha: unknown = 0.05): number {
  const a = normalizeAlpha(alpha);
  if (typeof k !== 'number' || !Number.isFinite(k)) return 1;
  if (typeof n !== 'number' || !Number.isFinite(n) || n <= 0) return 1;
  if (a <= 0) return 1;
  if (a >= 1) return 0;

  const trials = Math.floor(n);
  if (trials <= 0) return 1;
  const hits = Math.max(0, Math.min(trials, Math.floor(k)));
  if (hits === 0) return -Math.expm1(Math.log(a) / trials);
  if (hits === trials) return 1;

  const result = betaInverse(1 - a, hits + 1, trials - hits);
  if (!Number.isFinite(result)) return 1;
  return Math.max(0, Math.min(1, result));
}

/** Rough alpha~0.05, k=0 shortcut (rule of three); only meaningful for n > 30. */
export function ruleOfThreeUpper(n: unknown): number {
  if (typeof n !== 'number' || !Number.isFinite(n) || n <= 30) return 1;
  return Math.min(1, 3 / Math.floor(n));
}

/* -------------------------------------------------------------------------- */
/* 2. rarityDecision — honest "rare at p*" gating                              */
/* -------------------------------------------------------------------------- */

export const DEFAULT_ALPHA = 0.05;
export const DEFAULT_RARE_THRESHOLD = 0.01;
export const DEFAULT_MIN_SAMPLES = 30;
export const P95_THRESHOLD = 0.05;
export const P99_THRESHOLD = 0.01;
export const P999_THRESHOLD = 0.001;

export type RarityBucket = 'insufficient_data' | 'not_seen' | 'p99.9+' | 'p99' | 'p95' | 'common';

export interface RarityDecisionInput {
  hits?: number | null;
  total?: number | null;
  /** p* — claim "rare" only when the upper bound is strictly below this. */
  rareThreshold?: number | null;
  alpha?: number | null;
  /** Hard floor; totals below this are insufficient_data. */
  minSamples?: number | null;
  /** Number of devices tested; Bonferroni divisor for alpha. */
  deviceCount?: number | null;
}

export interface RarityDecisionResult {
  bucket: RarityBucket;
  rare: boolean;
  /** null when there is not enough data to form any bound. */
  p_upper: number | null;
  adjustedAlpha: number;
  reasons: string[];
}

function normalizePositiveNumber(value: unknown, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return fallback;
  return value;
}

function normalizeCount(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null;
  return Math.floor(value);
}

function bucketForUpper(pUpper: number): RarityBucket {
  if (pUpper < P999_THRESHOLD) return 'p99.9+';
  if (pUpper < P99_THRESHOLD) return 'p99';
  if (pUpper < P95_THRESHOLD) return 'p95';
  return 'common';
}

/**
 * Decide whether an observed signal is honestly "rare at p*".
 *
 * The `bucket` names are anchored to fixed reference prevalence levels
 * (p95 = 5%, p99 = 1%, p99.9+ = 0.1%). The `rare` boolean answers the caller's
 * own `rareThreshold` question and is true only when a Bonferroni-adjusted
 * Clopper–Pearson upper bound is strictly below that threshold, after both the
 * hard sample floor and the zero-hit sample floor have been cleared.
 */
export function rarityDecision(input: RarityDecisionInput | null | undefined): RarityDecisionResult {
  const source: RarityDecisionInput =
    input && typeof input === 'object' ? input : ({} as RarityDecisionInput);

  const alpha = normalizeAlpha(source.alpha);
  const deviceCount = Math.max(1, Math.floor(normalizePositiveNumber(source.deviceCount, 1)));
  const adjustedAlpha = Math.max(0, Math.min(1, alpha / deviceCount));
  const rareThreshold = normalizePositiveNumber(source.rareThreshold, DEFAULT_RARE_THRESHOLD);
  const minSamples = Math.max(1, Math.floor(normalizePositiveNumber(source.minSamples, DEFAULT_MIN_SAMPLES)));

  const baseReasons: string[] = [];
  if (deviceCount > 1) baseReasons.push(`bonferroni_device_multiplicity:x${deviceCount}`);

  const rawHits = normalizeCount(source.hits);
  const rawTotal = normalizeCount(source.total);
  if (rawHits === null || rawTotal === null || rawTotal === 0) {
    return {
      bucket: 'insufficient_data',
      rare: false,
      p_upper: null,
      adjustedAlpha,
      reasons: [...baseReasons, 'missing_or_hostile_counts'],
    };
  }

  const total = rawTotal;
  const hits = Math.min(rawHits, total);

  if (total < minSamples) {
    return {
      bucket: 'insufficient_data',
      rare: false,
      p_upper: null,
      adjustedAlpha,
      reasons: [...baseReasons, `below_hard_sample_floor:${total}<${minSamples}`],
    };
  }

  const pUpper = oneSidedUpper(hits, total, adjustedAlpha);

  // Zero hits need a window long enough that even zero observations would be
  // informative: n >= -ln(alphaAdjusted)/p*. Otherwise label "not_seen" — absence
  // of evidence is not evidence of rarity, and we never inflate n by back-filling.
  if (hits === 0 && adjustedAlpha > 0) {
    const zeroHitFloor = Math.ceil(-Math.log(adjustedAlpha) / rareThreshold);
    if (total < zeroHitFloor) {
      return {
        bucket: 'not_seen',
        rare: false,
        p_upper: pUpper,
        adjustedAlpha,
        reasons: [
          ...baseReasons,
          'zero_hits_below_sample_floor',
          `need_total>=${Number.isFinite(zeroHitFloor) ? zeroHitFloor : 'Infinity'}`,
        ],
      };
    }
  } else if (hits === 0) {
    // alpha <= 0 gives an infinite floor; zero hits can never support a claim.
    return {
      bucket: 'not_seen',
      rare: false,
      p_upper: pUpper,
      adjustedAlpha,
      reasons: [...baseReasons, 'zero_hits_zero_confidence'],
    };
  }

  const bucket = bucketForUpper(pUpper);
  const rare = bucket !== 'common' && pUpper < rareThreshold;
  const reasons = [...baseReasons];
  reasons.push(
    rare
      ? `p_upper_below_rare_threshold:${pUpper.toExponential(3)}<${rareThreshold}`
      : `p_upper_at_or_above_rare_threshold:${pUpper.toExponential(3)}>=${rareThreshold}`
  );
  if (hits > 0) reasons.push('nonzero_hits_use_beta_inverse_bound');

  return { bucket, rare, p_upper: pUpper, adjustedAlpha, reasons };
}

/* -------------------------------------------------------------------------- */
/* 3. rollingFrequency — lazy 14-day window, no timers                         */
/* -------------------------------------------------------------------------- */

export const DEFAULT_WINDOW_DAYS = 14;
export const MS_PER_DAY = 86_400_000;

export interface DailyObservation {
  /** Unique visitor / session / event id — the dedupe key across all buckets. */
  id: string | number;
  /** Whether this observation carried the rare signal. */
  hit?: boolean | number | null;
}

export interface DailyCount {
  /** Timestamp (ms), ISO date string, or Date object for this bucket. */
  day?: number | string | Date | null;
  hits?: number | null;
  total?: number | null;
  /** Alias for total when a bucket stores a single count. */
  count?: number | null;
  /**
   * Optional raw observations. When present, these take precedence over hits/total
   * and are deduplicated globally by id (first occurrence wins).
   */
  observations?: readonly DailyObservation[] | null;
}

export type CountsByDay =
  | Record<string, DailyCount | number | null>
  | readonly (DailyCount | number | null)[]
  | null
  | undefined;

export interface RollingFrequency {
  total: number;
  hits: number;
}

function parseBucketTime(day: unknown): number {
  if (typeof day === 'number') return Number.isFinite(day) ? day : Number.NaN;
  if (day instanceof Date) {
    const t = day.getTime();
    return Number.isFinite(t) ? t : Number.NaN;
  }
  if (typeof day === 'string') {
    const trimmed = day.trim();
    if (!trimmed) return Number.NaN;
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric)) return numeric;
    return Date.parse(trimmed);
  }
  return Number.NaN;
}

function nonNegativeCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return 0;
  return Math.floor(value);
}

/**
 * Recompute (total, hits) over the last `windowDays` ending at `nowMs`, lazily at
 * read time. Only buckets carrying a parseable timestamp strictly inside the window
 * contribute; missing days contribute zero, and no partial first bucket is ever
 * extrapolated into a full-day count. This is why a short history cannot inflate n.
 *
 * Duplicate observations are counted once across all buckets by their id. Pure and
 * deterministic: inputs are never mutated and no timer, clock read or schedule is used.
 */
export function rollingFrequency(
  countsByDay: CountsByDay,
  nowMs: unknown,
  windowDays: unknown = DEFAULT_WINDOW_DAYS
): RollingFrequency {
  if (typeof countsByDay !== 'object' || countsByDay === null) return { total: 0, hits: 0 };
  if (typeof nowMs !== 'number' || !Number.isFinite(nowMs)) return { total: 0, hits: 0 };

  const days = normalizePositiveNumber(windowDays, DEFAULT_WINDOW_DAYS);
  const cutoff = nowMs - days * MS_PER_DAY;
  const seenIds = new Set<string>();
  let total = 0;
  let hits = 0;

  const isArray = Array.isArray(countsByDay);
  const keys = isArray
    ? (countsByDay as readonly unknown[]).map((_, i) => String(i))
    : Object.keys(countsByDay as Record<string, unknown>);

  for (const key of keys) {
    const raw = isArray
      ? (countsByDay as readonly unknown[])[Number(key)]
      : (countsByDay as Record<string, unknown>)[key];
    const bucket: DailyCount =
      typeof raw === 'number'
        ? { total: raw }
        : raw && typeof raw === 'object'
          ? (raw as DailyCount)
          : {};

    const time = parseBucketTime(bucket.day ?? (isArray ? undefined : key));
    if (!Number.isFinite(time) || time < cutoff || time > nowMs) continue;

    const observations = Array.isArray(bucket.observations) ? bucket.observations : null;
    if (observations) {
      for (const observation of observations) {
        if (!observation || typeof observation !== 'object') continue;
        if (observation.id === undefined || observation.id === null) continue;
        const id = String(observation.id);
        if (seenIds.has(id)) continue;
        seenIds.add(id);
        total += 1;
        if (observation.hit === true || observation.hit === 1) hits += 1;
      }
    } else {
      const bucketTotal = nonNegativeCount(bucket.total ?? bucket.count);
      total += bucketTotal;
      hits += Math.min(nonNegativeCount(bucket.hits), bucketTotal);
    }
  }

  return { total, hits: Math.min(hits, total) };
}
