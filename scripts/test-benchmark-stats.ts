/**
 * Benchmark-statistics regression suite — RS8 evidence rules.
 *
 *   npx tsx scripts/test-benchmark-stats.ts
 *
 * Pins the paired McNemar branches, Wilson (never Wald) intervals, MCC,
 * pre-registered-bin ECE/Brier, the superiority claim gate, multiplicity
 * adjustment, risk-coverage AURC and the deterministic MCC bootstrap. All
 * helpers are pure and non-throwing; hostile inputs are exercised explicitly.
 * No I/O, no network, no timers, no ambient randomness.
 */
import assert from 'node:assert/strict';

import {
  aurc,
  bhAdjust,
  bootstrapMccConfidenceInterval,
  claimGate,
  ece,
  holmAdjust,
  mcc,
  mcnemar,
  wilsonInterval,
  DEFAULT_ALPHA,
  DEFAULT_ECE_BINS,
  MCNEMAR_ASYMPTOTIC_MIN_DISCORDANT,
  MCNEMAR_MIN_DISCORDANT,
  MAX_NOT_EVALUABLE_RATE,
  type CalibrationRecord,
  type ClaimGateInput,
  type McNemarInput,
} from '../src/lib/benchmarkStats';

let checks = 0;
let assertions = 0;
const failures: string[] = [];

function ok(condition: unknown, message?: string): void {
  assertions += 1;
  assert.ok(condition, message);
}
function eq(actual: unknown, expected: unknown, message?: string): void {
  assertions += 1;
  assert.strictEqual(actual, expected, message);
}
function deepEq(actual: unknown, expected: unknown, message?: string): void {
  assertions += 1;
  assert.deepStrictEqual(actual, expected, message);
}
function close(actual: number, expected: number, tolerance: number, message?: string): void {
  assertions += 1;
  const difference = Math.abs(actual - expected);
  assert.ok(
    Number.isFinite(actual) && difference <= tolerance,
    `${message ?? ''} expected ${actual} to be within ${tolerance} of ${expected} (diff ${difference})`,
  );
}
function notThrow(operation: () => unknown, message?: string): void {
  assertions += 1;
  assert.doesNotThrow(operation, message);
}

function check(name: string, verify: () => void): void {
  try {
    verify();
    checks += 1;
    console.log(`  PASS  ${name}`);
  } catch (error) {
    failures.push(name);
    console.error(`  FAIL  ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}
function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* 1. McNemar                                                                  */
/* -------------------------------------------------------------------------- */

section('1. Paired McNemar — discordance branches');

check('policy constants are locked', () => {
  eq(DEFAULT_ALPHA, 0.05);
  eq(MCNEMAR_MIN_DISCORDANT, 6);
  eq(MCNEMAR_ASYMPTOTIC_MIN_DISCORDANT, 25);
  eq(DEFAULT_ECE_BINS, 10);
  eq(MAX_NOT_EVALUABLE_RATE, 0.2);
});

check('both discordant cells empty is uninformative', () => {
  const result = mcnemar({ b: 0, c: 0 });
  eq(result.test, 'uninformative');
  eq(result.statistic, null);
  eq(result.p, null);
  eq(result.discordant, 0);
  ok(result.reason.includes('uninformative'), result.reason);
});

check('b+c<6 is uninformative even with a one-sided sweep', () => {
  for (const [b, c] of [[5, 0], [4, 1], [2, 2], [0, 5]] as const) {
    const result = mcnemar({ b, c });
    eq(result.test, 'uninformative', `b=${b} c=${c}`);
    eq(result.statistic, null, `b=${b} c=${c}`);
    eq(result.p, null, `b=${b} c=${c}`);
    eq(result.discordant, b + c, `b=${b} c=${c}`);
  }
});

check('b+c===6 enters the exact mid-P branch', () => {
  const result = mcnemar({ b: 5, c: 1 });
  eq(result.test, 'exact_midp');
  eq(result.discordant, 6);
  close(result.statistic ?? Number.NaN, 16 / 6, 1e-12, 'chi2');
  close(result.p ?? Number.NaN, 0.125, 1e-12, 'mid-P');
  ok(result.reason.includes('exact'), result.reason);
});

check('exact mid-P is two-sided and symmetric in b/c', () => {
  const forward = mcnemar({ b: 4, c: 2 });
  const reversed = mcnemar({ b: 2, c: 4 });
  eq(forward.test, 'exact_midp');
  close(forward.p ?? Number.NaN, 0.453125, 1e-12);
  eq(reversed.p, forward.p, 'swapping discordant cells must not change p');
  eq(reversed.statistic, forward.statistic, 'chi2 is squared, so also symmetric');
});

check('perfect discordant balance yields p===1 in the exact branch', () => {
  const result = mcnemar({ b: 3, c: 3 });
  eq(result.test, 'exact_midp');
  eq(result.statistic, 0);
  close(result.p ?? Number.NaN, 1, 1e-12);
});

check('b+c===24 is still exact; b+c===25 flips to asymptotic', () => {
  const below = mcnemar({ b: 12, c: 12 });
  const at = mcnemar({ b: 13, c: 12 });
  eq(below.test, 'exact_midp');
  eq(below.discordant, 24);
  eq(at.test, 'asymptotic');
  eq(at.discordant, 25);
});

check('asymptotic chi2 uses the uncorrected (b-c)^2/(b+c) formula', () => {
  const result = mcnemar({ b: 20, c: 5 });
  eq(result.test, 'asymptotic');
  close(result.statistic ?? Number.NaN, 9, 1e-12, '225/25');
  close(result.p ?? Number.NaN, 0.0026998, 1e-6, 'chi-square(1) tail');
});

check('chi-square(1) reference point chi2===1 gives p~0.3173', () => {
  const result = mcnemar({ b: 15, c: 10 });
  close(result.statistic ?? Number.NaN, 1, 1e-12);
  close(result.p ?? Number.NaN, 0.3173105, 1e-6);
  eq(mcnemar({ b: 10, c: 15 }).p, result.p);
});

check('large imbalance is significant, small imbalance is not', () => {
  const large = mcnemar({ b: 30, c: 5 });
  const small = mcnemar({ b: 18, c: 12 });
  eq(large.test, 'asymptotic');
  ok((large.p ?? 1) < 0.001, `p=${large.p}`);
  ok((small.p ?? 0) > 0.05, `p=${small.p}`);
});

check('hostile counts never throw and fail closed to zero evidence', () => {
  const hostile = [
    { b: Number.NaN, c: 3 },
    { b: Number.POSITIVE_INFINITY, c: 3 },
    { b: -7, c: 3 },
    { b: 3.9, c: 2.9 },
    { b: Number.NaN, c: Number.NaN },
  ] as unknown as McNemarInput[];
  for (const input of hostile) notThrow(() => mcnemar(input));
  eq(mcnemar(hostile[0]).discordant, 3, 'NaN -> 0');
  eq(mcnemar(hostile[1]).discordant, 3, 'Infinity -> 0');
  eq(mcnemar(hostile[2]).discordant, 3, 'negative -> 0');
  eq(mcnemar(hostile[3]).discordant, 5, 'fractional counts are floored');
  eq(mcnemar(hostile[4]).test, 'uninformative');
});

check('null / primitive / missing input is total', () => {
  notThrow(() => mcnemar(null as unknown as McNemarInput));
  notThrow(() => mcnemar(42 as unknown as McNemarInput));
  notThrow(() => mcnemar({} as unknown as McNemarInput));
  eq(mcnemar(null as unknown as McNemarInput).test, 'uninformative');
  eq(mcnemar({} as unknown as McNemarInput).discordant, 0);
  eq(mcnemar({ b: 10, c: 5, alpha: Number.NaN }).test, 'exact_midp');
  ok(mcnemar({ b: 10, c: 5, alpha: Number.NaN }).reason.includes('alpha=0.05'));
});

/* -------------------------------------------------------------------------- */
/* 2. Wilson intervals                                                         */
/* -------------------------------------------------------------------------- */

section('2. Wilson proportion intervals (never Wald)');

check('50/100 matches the published Wilson interval', () => {
  const result = wilsonInterval(50, 100);
  eq(result.p, 0.5);
  close(result.lower, 0.4038315, 1e-6);
  close(result.upper, 0.5961685, 1e-6);
  ok(result.lower < 0.5 && result.upper > 0.5);
});

check('extreme proportions stay inside [0,1] and touch one boundary', () => {
  const zero = wilsonInterval(0, 10);
  const full = wilsonInterval(10, 10);
  eq(zero.p, 0);
  eq(zero.lower, 0);
  close(zero.upper, 0.2775322, 1e-6);
  eq(full.p, 1);
  eq(full.upper, 1);
  close(full.lower, 0.7224678, 1e-6);
});

check('Wilson intervals are narrower than Wald at the boundary', () => {
  const wilson = wilsonInterval(0, 10);
  const waldUpper = 0 + 1.959963984540054 * Math.sqrt(0 / 10); // Wald gives exactly 0
  ok(wilson.upper > waldUpper, 'Wilson upper must exceed the degenerate Wald upper');
  ok(wilson.upper < 0.3, 'but not by much');
});

check('wider alpha yields a strictly wider interval', () => {
  const wide = wilsonInterval(40, 100, 0.01);
  const narrow = wilsonInterval(40, 100, 0.05);
  ok(wide.lower < narrow.lower, `${wide.lower} < ${narrow.lower}`);
  ok(wide.upper > narrow.upper, `${wide.upper} > ${narrow.upper}`);
});

check('intervals are monotone in the success count', () => {
  const low = wilsonInterval(20, 100);
  const mid = wilsonInterval(50, 100);
  const high = wilsonInterval(80, 100);
  ok(low.lower < mid.lower && mid.lower < high.lower);
  ok(low.upper < mid.upper && mid.upper < high.upper);
  eq(low.p, 0.2);
  eq(mid.p, 0.5);
  eq(high.p, 0.8);
});

check('unusable n returns a full, zero-evidence interval', () => {
  for (const n of [0, -5, Number.NaN, Number.POSITIVE_INFINITY]) {
    const result = wilsonInterval(3, n);
    deepEq(result, { lower: 0, upper: 1, p: 0 }, `n=${n}`);
  }
});

check('out-of-range and hostile success counts are clamped', () => {
  const negative = wilsonInterval(-5, 10);
  eq(negative.p, 0);
  eq(negative.lower, 0);
  const over = wilsonInterval(25, 10);
  eq(over.p, 1);
  eq(over.upper, 1);
  const nan = wilsonInterval(Number.NaN, 10);
  eq(nan.p, 0);
  ok(nan.upper > 0);
  const fractional = wilsonInterval(2, 4.5);
  close(fractional.p, 2 / 4.5, 1e-12);
  ok(Number.isFinite(fractional.lower) && Number.isFinite(fractional.upper));
});

/* -------------------------------------------------------------------------- */
/* 3. MCC                                                                      */
/* -------------------------------------------------------------------------- */

section('3. Matthews correlation coefficient');

check('perfect and perfectly inverted matrices give +1 / -1', () => {
  eq(mcc(10, 0, 0, 10), 1);
  eq(mcc(0, 10, 10, 0), -1);
});

check('mixed matrix gives the exact closed-form value', () => {
  const value = mcc(50, 5, 5, 40);
  close(value ?? Number.NaN, 1975 / 2475, 1e-12);
  ok((value ?? 0) > 0.79 && (value ?? 0) < 0.8);
});

check('zero marginal is undefined, not zero', () => {
  eq(mcc(0, 0, 10, 20), null);
  eq(mcc(0, 0, 0, 0), null);
  eq(mcc(10, 0, 10, 0), null);
});

check('sign follows the dominant diagonal', () => {
  ok((mcc(30, 5, 10, 20) ?? 0) > 0);
  ok((mcc(10, 20, 20, 5) ?? 0) < 0);
});

check('hostile inputs never throw and return null or a finite bounded value', () => {
  const inputs: Array<[number, number, number, number]> = [
    [Number.NaN, 0, 0, 10],
    [Number.POSITIVE_INFINITY, 0, 0, 10],
    [-5, 0, 0, 10],
    [10.9, 0.9, 0.9, 10.9],
  ];
  for (const args of inputs) {
    notThrow(() => mcc(...args));
    const value = mcc(...args);
    ok(value === null || (Number.isFinite(value) && value >= -1 && value <= 1));
  }
  eq(mcc(2.9, 0, 0, 2.9), 1, 'fractional counts are floored');
});

/* -------------------------------------------------------------------------- */
/* 4. Calibration                                                              */
/* -------------------------------------------------------------------------- */

section('4. Pre-registered ECE bins + Brier');

const record = (score: number, correct: boolean): CalibrationRecord => ({ score, correct });

check('confidently-correct records give ECE=|1-conf| and Brier=(1-conf)^2', () => {
  const result = ece([record(0.9, true), record(0.9, true)]);
  close(result.ece, 0.1, 1e-12);
  close(result.brier, 0.01, 1e-12);
  eq(result.binCounts.length, DEFAULT_ECE_BINS);
  eq(result.binCounts[9], 2);
});

check('confidently-wrong records give ECE=conf and Brier=conf^2', () => {
  const result = ece([record(0.5, false), record(0.5, false)]);
  close(result.ece, 0.5, 1e-12);
  close(result.brier, 0.25, 1e-12);
  eq(result.binCounts[5], 2);
});

check('a perfectly calibrated 2-bin predictor has ECE=0', () => {
  const result = ece([record(0, false), record(1, true)]);
  eq(result.ece, 0);
  eq(result.brier, 0);
  eq(result.binCounts[0], 1);
  eq(result.binCounts[9], 1);
});

check('within-bin confidence spread still contributes to ECE', () => {
  const result = ece([record(0.1, false), record(0.9, true)]);
  close(result.ece, 0.1, 1e-12);
  close(result.brier, 0.01, 1e-12);
});

check('sharp but random 0.5 predictions are calibrated yet have non-zero Brier', () => {
  const result = ece([record(0.5, true), record(0.5, false)]);
  eq(result.ece, 0);
  close(result.brier, 0.25, 1e-12);
});

check('custom pre-registered edges are honoured', () => {
  const result = ece([record(0.6, true), record(0.4, false)], [0, 0.5, 1]);
  deepEq(result.binCounts, [1, 1]);
  close(result.ece, 0.4, 1e-12);
  close(result.brier, 0.16, 1e-12);
});

check('scores exactly on an edge land in the upper bin', () => {
  const result = ece([record(0.5, true)], [0, 0.5, 1]);
  deepEq(result.binCounts, [0, 1]);
});

check('invalid records are skipped, not silently scored', () => {
  const input = [
    null,
    { score: 'high', correct: true },
    { score: 0.5, correct: 'yes' },
    { score: Number.NaN, correct: true },
    { score: Number.POSITIVE_INFINITY, correct: false },
  ] as unknown as CalibrationRecord[];
  notThrow(() => ece(input));
  const result = ece(input);
  eq(result.ece, 0);
  eq(result.brier, 0);
  deepEq(result.binCounts, new Array(DEFAULT_ECE_BINS).fill(0));
});

check('out-of-range scores are clamped into the first/last bin', () => {
  const result = ece([record(2, true), record(-1, false)], [0, 0.5, 1]);
  close(result.ece, 0, 1e-12);
  close(result.brier, 0, 1e-12);
  deepEq(result.binCounts, [1, 1]);
});

check('empty input and malformed bin specs fail closed to a valid shape', () => {
  deepEq(ece([]), { ece: 0, brier: 0, binCounts: new Array(DEFAULT_ECE_BINS).fill(0) });
  eq(ece([], 0).binCounts.length, 1, 'bins clamped to >=1');
  eq(ece([], 999).binCounts.length, 100, 'bins clamped to <=100');
  eq(ece([], Number.NaN).binCounts.length, DEFAULT_ECE_BINS);
  eq(ece([], [0.5, 0]).binCounts.length, DEFAULT_ECE_BINS, 'non-increasing edges rejected');
  eq(ece([], [0, 0.25, 0.5, 0.75, 1]).binCounts.length, 4);
});

/* -------------------------------------------------------------------------- */
/* 5. Claim gate                                                               */
/* -------------------------------------------------------------------------- */

section('5. Superiority claim gate');

const PASS: ClaimGateInput = {
  pAdjusted: 0.01,
  ciLower: 0.02,
  delta: 0.01,
  stable: true,
  notEvaluableRate: 0.05,
};

check('all pre-registered conditions satisfied => A_outperforms_B', () => {
  const result = claimGate(PASS);
  eq(result.claim, 'A_outperforms_B');
  eq(result.reasons.length, 4, 'one audit line per gate');
  ok(result.reasons.some((line) => line.includes('paired adjusted p')));
  ok(result.reasons.some((line) => line.includes('CI lower')));
});

check('adjusted p above alpha blocks the claim', () => {
  const result = claimGate({ ...PASS, pAdjusted: 0.06 });
  eq(result.claim, 'no_claim');
  ok(result.reasons.some((line) => line.includes('> alpha')));
});

check('CI lower bound must strictly exceed delta', () => {
  eq(claimGate({ ...PASS, ciLower: 0.01 }).claim, 'no_claim', 'equality is not enough');
  eq(claimGate({ ...PASS, ciLower: 0.009 }).claim, 'no_claim');
  eq(claimGate({ ...PASS, ciLower: 0.0100001 }).claim, 'A_outperforms_B');
});

check('instability across strata/seeds blocks the claim', () => {
  const result = claimGate({ ...PASS, stable: false });
  eq(result.claim, 'no_claim');
  ok(result.reasons.some((line) => line.includes('not stable')));
});

check('high not-evaluable rate blocks the matched-coverage claim', () => {
  const result = claimGate({ ...PASS, notEvaluableRate: 0.25 });
  eq(result.claim, 'no_claim');
  ok(result.reasons.some((line) => line.includes('matched-coverage guard')));
  eq(claimGate({ ...PASS, notEvaluableRate: 0.2 }).claim, 'A_outperforms_B', 'boundary is inclusive');
});

check('hostile gate input fails closed with every reason reported', () => {
  notThrow(() => claimGate(null as unknown as ClaimGateInput));
  const result = claimGate(null as unknown as ClaimGateInput);
  eq(result.claim, 'no_claim');
  eq(result.reasons.length, 4);
  const nan = claimGate({ ...PASS, pAdjusted: Number.NaN, ciLower: Number.NaN });
  eq(nan.claim, 'no_claim');
  ok(nan.reasons.some((line) => line.includes('pAdjusted missing')));
  ok(nan.reasons.some((line) => line.includes('ciLower missing')));
  eq(claimGate({ ...PASS, notEvaluableRate: Number.NaN }).claim, 'no_claim');
});

check('alpha and coverage-guard overrides are respected', () => {
  eq(claimGate({ ...PASS, pAdjusted: 0.02, alpha: 0.01 }).claim, 'no_claim');
  eq(claimGate({ ...PASS, pAdjusted: 0.005, alpha: 0.01 }).claim, 'A_outperforms_B');
  eq(
    claimGate({ ...PASS, notEvaluableRate: 0.25, maxNotEvaluableRate: 0.3 }).claim,
    'A_outperforms_B',
  );
});

check('out-of-range p, negative delta and bad overrides are sanitised', () => {
  eq(claimGate({ ...PASS, pAdjusted: 2 }).claim, 'no_claim');
  eq(claimGate({ ...PASS, pAdjusted: -0.1 }).claim, 'no_claim', 'negative p fails closed');
  eq(claimGate({ ...PASS, delta: -1 }).claim, 'A_outperforms_B');
  eq(claimGate({ ...PASS, alpha: 2 }).claim, 'A_outperforms_B', 'bad alpha -> 0.05');
  eq(claimGate({ ...PASS, maxNotEvaluableRate: Number.NaN }).claim, 'A_outperforms_B');
});

/* -------------------------------------------------------------------------- */
/* 6. Multiplicity, coverage, bootstrap                                        */
/* -------------------------------------------------------------------------- */

section('6. Multiplicity adjustment, AURC, deterministic bootstrap');

check('Holm step-down matches the hand-computed adjusted values', () => {
  deepEq(holmAdjust([0.01, 0.04, 0.03]), [0.03, 0.06, 0.06]);
  deepEq(holmAdjust([0.01, 0.8]), [0.02, 0.8]);
  deepEq(holmAdjust([]), []);
});

check('BH step-up matches the hand-computed adjusted values', () => {
  deepEq(bhAdjust([0.01, 0.04, 0.03]), [0.03, 0.04, 0.04]);
  deepEq(bhAdjust([0.01]), [0.01]);
  deepEq(bhAdjust([]), []);
});

check('multiplicity adjustment never throws on hostile p-values', () => {
  notThrow(() => holmAdjust([Number.NaN, -1, 2, 0.5]));
  notThrow(() => bhAdjust([Number.NaN, -1, 2, 0.5]));
  deepEq(holmAdjust([Number.NaN, -1, 2, 0.5]), [1, 1, 1, 1]);
  eq(bhAdjust([Number.NaN, -1, 2, 0.5]).length, 4);
});

check('AURC rewards ranking correct answers first', () => {
  const good = eceRecords(1, true, 5).concat(eceRecords(0, false, 5));
  const bad = eceRecords(1, false, 5).concat(eceRecords(0, true, 5));
  close(aurc(good), 0.17718254, 1e-8);
  close(aurc(bad), 0.82281746, 1e-8);
  eq(aurc(eceRecords(0.7, true, 8)), 0);
});

check('AURC skips hostile records and handles empty input', () => {
  notThrow(() => aurc(null as unknown as CalibrationRecord[]));
  eq(aurc(null as unknown as CalibrationRecord[]), 0);
  eq(aurc([]), 0);
  eq(aurc([{ score: Number.NaN, correct: true }] as CalibrationRecord[]), 0);
});

check('bootstrap CI is deterministic for a fixed seed and brackets the point', () => {
  const input = { tp: 50, fp: 5, fn: 5, tn: 40, seed: 7, replicates: 300 };
  const first = bootstrapMccConfidenceInterval(input);
  const second = bootstrapMccConfidenceInterval(input);
  deepEq(first, second);
  close(first.point ?? Number.NaN, 1975 / 2475, 1e-12);
  eq(first.replicates, 300);
  ok((first.lower ?? 1) <= (first.point ?? 0), `${first.lower} <= ${first.point}`);
  ok((first.upper ?? 0) >= (first.point ?? 1), `${first.upper} >= ${first.point}`);
});

check('bootstrap CI is non-throwing and fails closed on undefined MCC', () => {
  notThrow(() => bootstrapMccConfidenceInterval({ tp: 0, fp: 0, fn: 10, tn: 20 }));
  const undefinedPoint = bootstrapMccConfidenceInterval({ tp: 0, fp: 0, fn: 10, tn: 20 });
  eq(undefinedPoint.point, null);
  eq(undefinedPoint.lower, null);
  eq(undefinedPoint.upper, null);
  notThrow(() =>
    bootstrapMccConfidenceInterval(null as unknown as Parameters<typeof bootstrapMccConfidenceInterval>[0]),
  );
  const hostile = bootstrapMccConfidenceInterval({
    tp: Number.NaN,
    fp: 0,
    fn: 0,
    tn: 10,
    replicates: Number.NaN,
    seed: Number.NaN,
  });
  eq(hostile.point, null);
});

function eceRecords(score: number, correct: boolean, count: number): CalibrationRecord[] {
  const result: CalibrationRecord[] = [];
  for (let i = 0; i < count; i += 1) result.push({ score, correct });
  return result;
}

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${checks} passed, ${failures.length} failed, ${assertions} assertions`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}
