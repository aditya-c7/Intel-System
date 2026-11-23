/**
 * Benchmark statistics for paired A/B evaluation — RS8 evidence rules.
 *
 * Pure, deterministic, non-throwing. No I/O, no clocks, no ambient randomness, no
 * module state. Every exported helper is total: hostile, malformed or partially
 * observed input fails closed to an explicit null / uninformative / zero-evidence
 * result instead of throwing or fabricating a favourable number.
 *
 * Evidence policy implemented here:
 *   - Paired 2x2: b = A correct / B wrong, c = A wrong / B correct. Diagonals carry
 *     no evidence and are not accepted. McNemar chi2 = (b-c)^2 / (b+c).
 *   - b+c < 6  -> uninformative (no statistic, no p-value).
 *   - 6 <= b+c < 25 -> exact two-sided binomial mid-P (chi2 retained as statistic).
 *   - b+c >= 25 -> asymptotic chi-square(1).
 *   - Proportions use Wilson intervals (never Wald).
 *   - MCC is preferred over accuracy under class imbalance, with a deterministic
 *     seeded bootstrap percentile interval available below.
 *   - ECE uses pre-registered bins; Brier score is reported alongside it.
 *   - Coverage/abstention must be compared at matched coverage (AURC helper).
 *   - A claim of 'A outperforms B' requires paired significance after multiplicity
 *     adjustment AND an adjusted CI lower bound above the pre-registered delta AND
 *     stability across strata/seeds AND an acceptable not-evaluable rate.
 */

/* -------------------------------------------------------------------------- */
/* Public shapes                                                               */
/* -------------------------------------------------------------------------- */

export type McNemarTest = 'asymptotic' | 'exact_midp' | 'uninformative';

export interface McNemarInput {
  /** A correct, B wrong (discordant). */
  b: number;
  /** A wrong, B correct (discordant). */
  c: number;
  /** Two-sided significance level; defaults to 0.05 when missing/invalid. */
  alpha?: number;
}

export interface McNemarResult {
  test: McNemarTest;
  /** (b-c)^2/(b+c) whenever the test is informative; null otherwise. */
  statistic: number | null;
  /** Two-sided p-value; null only for the uninformative branch. */
  p: number | null;
  /** b + c (diagonal pairs are deliberately excluded). */
  discordant: number;
  /** Stable, lowercase audit token explaining the branch. */
  reason: string;
}

export interface IntervalResult {
  lower: number;
  upper: number;
  /** The point proportion successes/n (0 when n is unusable). */
  p: number;
}

export interface CalibrationRecord {
  /** Confidence in [0,1]; out-of-range values are clamped, non-finite are skipped. */
  score: number;
  /** Ground-truth correctness; non-boolean values are skipped. */
  correct: boolean;
}

export interface EceResult {
  ece: number;
  brier: number;
  /** Observed count in each pre-registered bin, in bin order. */
  binCounts: number[];
}

export interface ClaimGateInput {
  /** Multiplicity-adjusted paired p-value (e.g. after Holm/BH). */
  pAdjusted: number;
  /** Lower bound of the multiplicity-adjusted effect-size CI. */
  ciLower: number;
  /** Pre-registered minimum meaningful effect size (must be strictly exceeded). */
  delta: number;
  /** True only when the effect survives every pre-registered stratum/seed. */
  stable: boolean;
  /** Fraction of items that could not be evaluated (abstention / no verdict). */
  notEvaluableRate: number;
  /** Optional alpha override; defaults to 0.05. */
  alpha?: number;
  /** Optional matched-coverage guard override; defaults to 0.20. */
  maxNotEvaluableRate?: number;
}

export interface ClaimGateResult {
  claim: 'A_outperforms_B' | 'no_claim';
  /** Audit trail: satisfied conditions on success, every failed condition otherwise. */
  reasons: string[];
}

export interface BootstrapMccInput {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  alpha?: number;
  replicates?: number;
  /** Integer seed; the same seed always yields the same interval. */
  seed?: number;
}

export interface BootstrapMccResult {
  point: number | null;
  lower: number | null;
  upper: number | null;
  replicates: number;
}

/* -------------------------------------------------------------------------- */
/* Locked, documented policy constants                                         */
/* -------------------------------------------------------------------------- */

/** Default two-sided significance level. */
export const DEFAULT_ALPHA = 0.05;
/** Below this many discordant pairs a McNemar test is uninformative. */
export const MCNEMAR_MIN_DISCORDANT = 6;
/** At/above this many discordant pairs the asymptotic chi-square is used. */
export const MCNEMAR_ASYMPTOTIC_MIN_DISCORDANT = 25;
/** Default number of equal-width pre-registered ECE bins. */
export const DEFAULT_ECE_BINS = 10;
/** Matched-coverage guard: abstention above this blocks a superiority claim. */
export const MAX_NOT_EVALUABLE_RATE = 0.2;

/* -------------------------------------------------------------------------- */
/* Defensive primitives — all total                                            */
/* -------------------------------------------------------------------------- */

function finiteOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function clamp(value: number, low: number, high: number): number {
  return value < low ? low : value > high ? high : value;
}

function clamp01(value: number): number {
  return clamp(value, 0, 1);
}

/** Non-negative integer count; non-finite, negative and fractional inputs fail low. */
function safeCount(value: unknown): number {
  const v = finiteOrNull(value);
  if (v === null || v <= 0) return 0;
  return Math.floor(v);
}

function safeAlpha(value: unknown): number {
  const v = finiteOrNull(value);
  if (v === null || v <= 0 || v >= 1) return DEFAULT_ALPHA;
  return v;
}

function round6(value: number): number {
  return Math.round(value * 1e6) / 1e6;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object'
    ? (value as Record<string, unknown>)
    : {};
}

/* -------------------------------------------------------------------------- */
/* Numerical kernels                                                           */
/* -------------------------------------------------------------------------- */

/** Abramowitz & Stegun 7.1.26 error function, clamped to [-1,1]. */
function erf(x: number): number {
  const sign = x < 0 ? -1 : 1;
  const ax = Math.abs(x);
  const t = 1 / (1 + 0.3275911 * ax);
  const poly =
    ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t +
      0.254829592) * t;
  return sign * clamp(1 - poly * Math.exp(-ax * ax), -1, 1);
}

/** Complementary error function; used for the chi-square(1) tail. */
function erfc(x: number): number {
  return clamp01(1 - erf(x));
}

function horner(coefficients: readonly number[], x: number): number {
  let acc = 0;
  for (const coefficient of coefficients) acc = acc * x + coefficient;
  return acc;
}

const NQ_A = [
  -3.969683028665376e1, 2.209460984245205e2, -2.759285104469687e2,
  1.383577518672690e2, -3.066479806614716e1, 2.506628277459239e0,
] as const;
const NQ_B = [
  -5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2,
  6.680131188771972e1, -1.328068155288572e1,
] as const;
const NQ_C = [
  -7.784894002430293e-3, -3.223964580411365e-1, -2.400758277161838e0,
  -2.549732539343734e0, 4.374664141464968e0, 2.938163982698783e0,
] as const;
const NQ_D = [
  7.784695709041462e-3, 3.224671290700398e-1,
  2.445134137142996e0, 3.754408661907416e0,
] as const;
const NQ_LOW = 0.02425;

/** Peter Acklam's inverse standard-normal CDF (relative error ~1e-9). */
function normalQuantile(p: number): number {
  const q = clamp01(p);
  if (q <= 0) return Number.NEGATIVE_INFINITY;
  if (q >= 1) return Number.POSITIVE_INFINITY;
  if (q < NQ_LOW) {
    const t = Math.sqrt(-2 * Math.log(q));
    return horner(NQ_C, t) / (horner(NQ_D, t) * t + 1);
  }
  if (q <= 1 - NQ_LOW) {
    const r = q - 0.5;
    const s = r * r;
    return (horner(NQ_A, s) * r) / (horner(NQ_B, s) * s + 1);
  }
  const t = Math.sqrt(-2 * Math.log(1 - q));
  return -horner(NQ_C, t) / (horner(NQ_D, t) * t + 1);
}

/* -------------------------------------------------------------------------- */
/* 1. Paired McNemar test                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Two-sided paired McNemar test on discordant counts only. The chi-square
 * statistic is reported for the exact branch as well (it is still a valid
 * discrepancy measure), but its p-value comes from the exact mid-P binomial.
 */
export function mcnemar(input: McNemarInput): McNemarResult {
  const source = asRecord(input);
  const b = safeCount(source.b);
  const c = safeCount(source.c);
  const alpha = safeAlpha(source.alpha);
  const discordant = b + c;

  if (discordant < MCNEMAR_MIN_DISCORDANT) {
    return {
      test: 'uninformative',
      statistic: null,
      p: null,
      discordant,
      reason: `uninformative: discordant b+c=${discordant} < ${MCNEMAR_MIN_DISCORDANT}; diagonals carry no evidence`,
    };
  }

  const statistic = ((b - c) * (b - c)) / discordant;

  if (discordant >= MCNEMAR_ASYMPTOTIC_MIN_DISCORDANT) {
    return {
      test: 'asymptotic',
      statistic,
      p: erfc(Math.sqrt(statistic / 2)),
      discordant,
      reason: `asymptotic chi-square(1) at alpha=${alpha}; discordant b+c=${discordant} >= ${MCNEMAR_ASYMPTOTIC_MIN_DISCORDANT}`,
    };
  }

  // Exact two-sided mid-P: P(X < k) + 0.5*P(X = k), doubled, where X~Bin(n, 0.5).
  const n = discordant;
  const k = Math.min(b, c);
  const scale = Math.pow(0.5, n);
  let combinations = 1; // C(n, 0)
  let below = 0;
  let atK = 0;
  for (let i = 0; i <= k; i += 1) {
    const probability = combinations * scale;
    if (i < k) below += probability;
    else atK = probability;
    combinations = (combinations * (n - i)) / (i + 1);
  }
  return {
    test: 'exact_midp',
    statistic,
    p: clamp01(2 * (below + 0.5 * atK)),
    discordant,
    reason: `exact binomial mid-P (two-sided) at alpha=${alpha}; discordant b+c=${n} < ${MCNEMAR_ASYMPTOTIC_MIN_DISCORDANT}`,
  };
}

/* -------------------------------------------------------------------------- */
/* 2. Wilson proportion interval                                               */
/* -------------------------------------------------------------------------- */

/** Wilson score interval (never Wald), clamped to [0,1]. */
export function wilsonInterval(successes: number, n: number, alpha?: number): IntervalResult {
  const sample = finiteOrNull(n);
  const level = safeAlpha(alpha);
  if (sample === null || sample <= 0) return { lower: 0, upper: 1, p: 0 };

  const count = clamp(finiteOrNull(successes) ?? 0, 0, sample);
  const p = count / sample;
  const z = normalQuantile(1 - level / 2);
  const z2 = z * z;
  const denominator = 1 + z2 / sample;
  const center = (p + z2 / (2 * sample)) / denominator;
  const margin =
    (z / denominator) *
    Math.sqrt(Math.max(0, (p * (1 - p)) / sample + z2 / (4 * sample * sample)));

  return { lower: clamp01(center - margin), upper: clamp01(center + margin), p };
}

/* -------------------------------------------------------------------------- */
/* 3. Matthews correlation coefficient                                         */
/* -------------------------------------------------------------------------- */

/** MCC in [-1,1]; null when the confusion matrix has a zero marginal. */
export function mcc(tp: number, fp: number, fn: number, tn: number): number | null {
  const t = safeCount(tp);
  const f = safeCount(fp);
  const n = safeCount(fn);
  const s = safeCount(tn);
  const denominator = Math.sqrt((t + f) * (t + n) * (s + f) * (s + n));
  if (!Number.isFinite(denominator) || denominator <= 0) return null;
  const value = (t * s - f * n) / denominator;
  if (!Number.isFinite(value)) return null;
  return clamp(value, -1, 1);
}

/* -------------------------------------------------------------------------- */
/* 4. Calibration: pre-registered-bin ECE + Brier                              */
/* -------------------------------------------------------------------------- */

function normalizeBins(bins: unknown): number[] | null {
  if (typeof bins === 'number' && Number.isFinite(bins)) {
    const count = clamp(Math.floor(bins), 1, 100);
    const edges: number[] = [];
    for (let i = 0; i <= count; i += 1) edges.push(i / count);
    return edges;
  }
  if (Array.isArray(bins)) {
    const edges: number[] = [];
    for (const candidate of bins) {
      const value = finiteOrNull(candidate);
      if (value === null) return null;
      edges.push(value);
    }
    if (edges.length >= 2) {
      for (let i = 1; i < edges.length; i += 1) {
        if (edges[i] <= edges[i - 1]) return null;
      }
      return edges;
    }
  }
  return null;
}

function binIndex(edges: readonly number[], score: number, binCount: number): number {
  if (score <= edges[0]) return 0;
  for (let i = 0; i < binCount; i += 1) {
    if (score < edges[i + 1]) return i;
  }
  return binCount - 1;
}

/**
 * Expected calibration error over fixed bins, with Brier score alongside.
 * Invalid records are skipped rather than silently scored as wrong; an empty
 * or fully invalid input yields zero evidence (all-zero counts, ece=0, brier=0).
 */
export function ece(
  records: readonly CalibrationRecord[],
  bins: number | readonly number[] = DEFAULT_ECE_BINS,
): EceResult {
  const edges = normalizeBins(bins) ?? normalizeBins(DEFAULT_ECE_BINS)!;
  const binCount = edges.length - 1;
  const counts = new Array<number>(binCount).fill(0);
  const correctSums = new Array<number>(binCount).fill(0);
  const scoreSums = new Array<number>(binCount).fill(0);
  let brierSum = 0;
  let valid = 0;

  const list = Array.isArray(records) ? records : [];
  for (const entry of list) {
    const record = asRecord(entry);
    const rawScore = finiteOrNull(record.score);
    if (rawScore === null || typeof record.correct !== 'boolean') continue;
    const score = clamp01(rawScore);
    const outcome = record.correct ? 1 : 0;
    const index = binIndex(edges, score, binCount);
    counts[index] += 1;
    correctSums[index] += outcome;
    scoreSums[index] += score;
    brierSum += (score - outcome) * (score - outcome);
    valid += 1;
  }

  if (valid === 0) return { ece: 0, brier: 0, binCounts: counts };

  let error = 0;
  for (let i = 0; i < binCount; i += 1) {
    if (counts[i] === 0) continue;
    const accuracy = correctSums[i] / counts[i];
    const confidence = scoreSums[i] / counts[i];
    error += (counts[i] / valid) * Math.abs(accuracy - confidence);
  }
  return { ece: clamp01(error), brier: Math.max(0, brierSum / valid), binCounts: counts };
}

/* -------------------------------------------------------------------------- */
/* 5. Superiority claim gate                                                   */
/* -------------------------------------------------------------------------- */

/** Fails closed: any missing/ hostile gate input produces 'no_claim'. */
export function claimGate(input: ClaimGateInput): ClaimGateResult {
  const source = asRecord(input);
  const alpha = safeAlpha(source.alpha ?? DEFAULT_ALPHA);
  const guardRaw = finiteOrNull(source.maxNotEvaluableRate);
  const guard =
    guardRaw !== null && guardRaw >= 0 && guardRaw <= 1
      ? guardRaw
      : MAX_NOT_EVALUABLE_RATE;
  const reasons: string[] = [];
  let eligible = true;

  const p = finiteOrNull(source.pAdjusted);
  if (p === null || p < 0 || p > 1) {
    reasons.push('pAdjusted missing or outside [0,1]: no paired significance');
    eligible = false;
  } else if (p > alpha) {
    reasons.push(`paired adjusted p=${round6(p)} > alpha=${alpha}`);
    eligible = false;
  } else {
    reasons.push(`paired adjusted p=${round6(p)} <= alpha=${alpha}`);
  }

  const lower = finiteOrNull(source.ciLower);
  const deltaRaw = finiteOrNull(source.delta);
  const delta = deltaRaw !== null && deltaRaw >= 0 ? deltaRaw : 0;
  if (lower === null) {
    reasons.push('ciLower missing or non-finite: adjusted CI lower bound unavailable');
    eligible = false;
  } else if (!(lower > delta)) {
    reasons.push(`adjusted CI lower=${round6(lower)} <= delta=${round6(delta)}`);
    eligible = false;
  } else {
    reasons.push(`adjusted CI lower=${round6(lower)} > delta=${round6(delta)}`);
  }

  if (source.stable !== true) {
    reasons.push('effect not stable across strata/seeds');
    eligible = false;
  } else {
    reasons.push('effect stable across strata/seeds');
  }

  const rateRaw = finiteOrNull(source.notEvaluableRate);
  const rate = rateRaw === null ? 1 : clamp01(rateRaw);
  if (rate > guard) {
    reasons.push(`not-evaluable rate=${round6(rate)} > matched-coverage guard ${round6(guard)}`);
    eligible = false;
  } else {
    reasons.push(`not-evaluable rate=${round6(rate)} <= matched-coverage guard ${round6(guard)}`);
  }

  return { claim: eligible ? 'A_outperforms_B' : 'no_claim', reasons };
}

/* -------------------------------------------------------------------------- */
/* 6. Multiplicity adjustment                                                  */
/* -------------------------------------------------------------------------- */

/** Sanitised p-values: non-finite / out-of-range values become 1. */
function safePValues(pValues: readonly number[]): number[] {
  if (!Array.isArray(pValues)) return [];
  return pValues.map((value) => {
    const p = finiteOrNull(value);
    // Invalid p-values are conservative (1), never significant (0).
    return p === null || p < 0 || p > 1 ? 1 : p;
  });
}

/** Holm step-down adjusted p-values, returned in the original input order. */
export function holmAdjust(pValues: readonly number[]): number[] {
  const values = safePValues(pValues);
  const m = values.length;
  if (m === 0) return [];
  const order = values.map((value, index) => ({ value, index })).sort((a, b) => a.value - b.value);
  const adjusted = new Array<number>(m).fill(1);
  let running = 0;
  for (let rank = 0; rank < m; rank += 1) {
    running = Math.max(running, (m - rank) * order[rank].value);
    adjusted[order[rank].index] = clamp01(running);
  }
  return adjusted;
}

/** Benjamini-Hochberg step-up adjusted p-values, in the original input order. */
export function bhAdjust(pValues: readonly number[]): number[] {
  const values = safePValues(pValues);
  const m = values.length;
  if (m === 0) return [];
  const order = values.map((value, index) => ({ value, index })).sort((a, b) => a.value - b.value);
  const adjusted = new Array<number>(m).fill(1);
  let running = 1;
  for (let rank = m - 1; rank >= 0; rank -= 1) {
    running = Math.min(running, (m / (rank + 1)) * order[rank].value);
    adjusted[order[rank].index] = clamp01(running);
  }
  return adjusted;
}

/* -------------------------------------------------------------------------- */
/* 7. Coverage / abstention and deterministic MCC bootstrap                    */
/* -------------------------------------------------------------------------- */

/**
 * Area under the risk-coverage curve (lower is better). Records are ranked by
 * descending confidence; risk at each prefix is the observed error rate. Equal
 * scores keep their input order, so the result is deterministic.
 */
export function aurc(records: readonly CalibrationRecord[]): number {
  const list = Array.isArray(records) ? records : [];
  const valid: Array<{ score: number; correct: boolean; index: number }> = [];
  for (let index = 0; index < list.length; index += 1) {
    const record = asRecord(list[index]);
    const score = finiteOrNull(record.score);
    if (score === null || typeof record.correct !== 'boolean') continue;
    valid.push({ score, correct: record.correct, index });
  }
  if (valid.length === 0) return 0;
  valid.sort((a, b) => b.score - a.score || a.index - b.index);
  let errors = 0;
  let area = 0;
  for (let i = 0; i < valid.length; i += 1) {
    if (!valid[i].correct) errors += 1;
    area += errors / (i + 1);
  }
  return clamp01(area / valid.length);
}

/** Deterministic 32-bit PRNG (mulberry32). */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Deterministic seeded bootstrap percentile CI for MCC. */
export function bootstrapMccConfidenceInterval(input: BootstrapMccInput): BootstrapMccResult {
  const source = asRecord(input);
  const point = mcc(
    finiteOrNull(source.tp) ?? 0,
    finiteOrNull(source.fp) ?? 0,
    finiteOrNull(source.fn) ?? 0,
    finiteOrNull(source.tn) ?? 0,
  );
  const level = safeAlpha(source.alpha);
  const replicatesRaw = finiteOrNull(source.replicates);
  const replicates = replicatesRaw === null ? 1000 : clamp(Math.floor(replicatesRaw), 1, 2000);
  const seedRaw = finiteOrNull(source.seed);
  const seed = seedRaw === null ? 1 : Math.floor(seedRaw);
  if (point === null) return { point: null, lower: null, upper: null, replicates };

  const counts = [
    safeCount(source.tp),
    safeCount(source.fp),
    safeCount(source.fn),
    safeCount(source.tn),
  ];
  const total = counts[0] + counts[1] + counts[2] + counts[3];
  const cumulative = [0, 0, 0, 0];
  let acc = 0;
  for (let i = 0; i < 4; i += 1) {
    acc += counts[i] / total;
    cumulative[i] = acc;
  }
  const random = mulberry32(seed);
  const samples: number[] = [];
  for (let r = 0; r < replicates; r += 1) {
    let b = 0;
    let f = 0;
    let n = 0;
    let s = 0;
    for (let draw = 0; draw < total; draw += 1) {
      const u = random();
      if (u < cumulative[0]) b += 1;
      else if (u < cumulative[1]) f += 1;
      else if (u < cumulative[2]) n += 1;
      else s += 1;
    }
    const value = mcc(b, f, n, s);
    if (value !== null) samples.push(value);
  }
  if (samples.length === 0) return { point, lower: null, upper: null, replicates };
  samples.sort((a, b) => a - b);
  const lowerIndex = Math.floor((samples.length - 1) * (level / 2));
  const upperIndex = Math.floor((samples.length - 1) * (1 - level / 2));
  return {
    point,
    lower: samples[lowerIndex],
    upper: samples[upperIndex],
    replicates: samples.length,
  };
}
