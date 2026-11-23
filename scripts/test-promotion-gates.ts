/**
 * Shadow-only tests for `src/lib/promotionGates.ts`.
 *
 * Covers the inclusive pre-registered thresholds (error +1pp, p99 +20%, quality -5, coverage
 * floor 0.80), concurrent-control coverage parity, signed-audit gating, the canary ladder,
 * additive-field contract evidence, hostile input, purity and determinism.
 *
 *   npx tsx scripts/test-promotion-gates.ts
 *
 * Exits non-zero when any assertion fails. Nothing here writes state or schedules work.
 */
import {
  evaluatePromotionStage,
  additiveFieldContract,
  PROMOTION_STAGES,
  PROMOTION_THRESHOLDS,
  MAX_ERROR_DELTA_PCT,
  MAX_P99_DELTA_PCT,
  MIN_QUALITY_DELTA,
  COVERAGE_FLOOR,
  type PromotionStageInput,
  type AdditiveFieldContractInput,
} from '../src/lib/promotionGates';

let assertions = 0;
let failures = 0;

function check(name: string, condition: boolean, detail?: unknown): void {
  assertions += 1;
  if (condition) {
    console.log(`ok   ${name}`);
    return;
  }
  failures += 1;
  console.error(`FAIL ${name}`);
  if (detail !== undefined) console.error('     ', detail);
}

/** Assert that a thunk returns without throwing. */
function doesNotThrow(name: string, fn: () => unknown): void {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  check(name, !threw);
}

/** A clean canary_5 stage; every test overrides only what it needs to probe. */
function cleanStage(overrides: Partial<PromotionStageInput> = {}): PromotionStageInput {
  return {
    stage: 'canary_5',
    coverage: 0.95,
    errorDeltaPct: 0,
    p99DeltaPct: 0,
    qualityDelta: 0,
    baselineCoverage: 0.94,
    auditPresent: true,
    ...overrides,
  };
}

/** A fully evidenced additive-field contract; tests flip one pre-condition at a time. */
function cleanContract(
  overrides: Partial<AdditiveFieldContractInput> = {}
): AdditiveFieldContractInput {
  return {
    fieldPresent: true,
    oldProducer: true,
    oldConsumer: true,
    noBehaviorChangeProof: true,
    tolerantReader: true,
    flagOffParity: true,
    ...overrides,
  };
}

/* -------------------------------------------------------------------------- */
/* 1. evaluatePromotionStage — pass cases and inclusive boundaries            */
/* -------------------------------------------------------------------------- */

const pass = evaluatePromotionStage(cleanStage());
check('E1 clean canary_5 advances', pass.advance === true && pass.rollback === false, pass);
check('E2 pass reason names the next rung', /canary_25/.test(pass.reasons.join(' ')), pass);

const shadow = evaluatePromotionStage(cleanStage({ stage: 'shadow' }));
check(
  'E3 shadow stage advances to canary_1',
  shadow.advance === true && /canary_1/.test(shadow.reasons.join(' ')),
  shadow
);

const boundaries = evaluatePromotionStage(
  cleanStage({
    errorDeltaPct: MAX_ERROR_DELTA_PCT,
    p99DeltaPct: MAX_P99_DELTA_PCT,
    qualityDelta: MIN_QUALITY_DELTA,
    coverage: COVERAGE_FLOOR,
    baselineCoverage: COVERAGE_FLOOR,
  })
);
check(
  'E4 inclusive thresholds (+1pp / +20% / -5 / 0.80) still advance',
  boundaries.advance === true && boundaries.rollback === false,
  boundaries
);

const improvements = evaluatePromotionStage(
  cleanStage({ errorDeltaPct: -0.5, p99DeltaPct: -10, qualityDelta: 2 })
);
check(
  'E5 one-sided gates: improvements never block promotion',
  improvements.advance === true && improvements.rollback === false,
  improvements
);

const terminal = evaluatePromotionStage(cleanStage({ stage: 'canary_100' }));
check(
  'E6 terminal canary_100 pass completes the promotion',
  terminal.advance === true && /promotion complete/.test(terminal.reasons.join(' ')),
  terminal
);

/* -------------------------------------------------------------------------- */
/* 2. evaluatePromotionStage — gate breaches trigger rollback                 */
/* -------------------------------------------------------------------------- */

const errorBreach = evaluatePromotionStage(cleanStage({ errorDeltaPct: 1.001 }));
check(
  'E7 error above +1pp rolls back',
  errorBreach.rollback === true && errorBreach.advance === false && /error regression/.test(errorBreach.reasons.join(' ')),
  errorBreach
);

const p99Breach = evaluatePromotionStage(cleanStage({ p99DeltaPct: 20.5 }));
check(
  'E8 p99 above +20% rolls back',
  p99Breach.rollback === true && /p99 regression/.test(p99Breach.reasons.join(' ')),
  p99Breach
);

const qualityBreach = evaluatePromotionStage(cleanStage({ qualityDelta: -5.5 }));
check(
  'E9 quality below -5 rolls back',
  qualityBreach.rollback === true && /quality regression/.test(qualityBreach.reasons.join(' ')),
  qualityBreach
);

const coverageBreach = evaluatePromotionStage(
  cleanStage({ coverage: 0.79, baselineCoverage: 0.7 })
);
check(
  'E10 coverage below 0.80 floor rolls back',
  coverageBreach.rollback === true && /coverage floor/.test(coverageBreach.reasons.join(' ')),
  coverageBreach
);

const controlBreach = evaluatePromotionStage(
  cleanStage({ coverage: 0.85, baselineCoverage: 0.95 })
);
check(
  'E11 coverage below concurrent control rolls back',
  controlBreach.rollback === true && /concurrent control/.test(controlBreach.reasons.join(' ')),
  controlBreach
);

const multiBreach = evaluatePromotionStage(
  cleanStage({ errorDeltaPct: 3, p99DeltaPct: 55, qualityDelta: -12, coverage: 0.2, auditPresent: false })
);
check(
  'E12 all four metric breaches plus missing audit are all reported',
  multiBreach.rollback === true &&
    multiBreach.advance === false &&
    ['error regression', 'p99 regression', 'quality regression', 'coverage', 'audit'].every((token) =>
      multiBreach.reasons.join(' ').includes(token)
    ),
  multiBreach
);

/* -------------------------------------------------------------------------- */
/* 3. evaluatePromotionStage — audit, stage validity, hostile input, purity    */
/* -------------------------------------------------------------------------- */

const unaudited = evaluatePromotionStage(cleanStage({ auditPresent: false }));
check(
  'E13 missing signed audit blocks advance without ordering rollback',
  unaudited.advance === false && unaudited.rollback === false && /audit/.test(unaudited.reasons.join(' ')),
  unaudited
);

const auditTruthy = evaluatePromotionStage(
  cleanStage({ auditPresent: 'true' as unknown as boolean })
);
check(
  'E14 truthy non-boolean audit evidence does not count',
  auditTruthy.advance === false && /audit/.test(auditTruthy.reasons.join(' ')),
  auditTruthy
);

const badStage = evaluatePromotionStage(cleanStage({ stage: 'canary_7' as 'canary_5' }));
check(
  'E15 unknown stage fails closed',
  badStage.advance === false && /invalid stage/.test(badStage.reasons.join(' ')),
  badStage
);

check('E16 ladder has six ordered rungs', PROMOTION_STAGES.length === 6 && PROMOTION_STAGES[0] === 'shadow' && PROMOTION_STAGES[5] === 'canary_100');
check(
  'E17 ladder contains the 1/5/25/50/100 canary steps',
  ['canary_1', 'canary_5', 'canary_25', 'canary_50', 'canary_100'].every((s) =>
    (PROMOTION_STAGES as readonly string[]).includes(s)
  )
);
check(
  'E18 constants carry the pre-registered values',
  MAX_ERROR_DELTA_PCT === 1 &&
    MAX_P99_DELTA_PCT === 20 &&
    MIN_QUALITY_DELTA === -5 &&
    COVERAGE_FLOOR === 0.8 &&
    PROMOTION_THRESHOLDS.requireSignedAudit === true
);

const immutableInput = cleanStage();
const immutableSnapshot = JSON.stringify(immutableInput);
const repeatA = evaluatePromotionStage(immutableInput);
const repeatB = evaluatePromotionStage(immutableInput);
check('E19 determinism: identical inputs yield identical results', JSON.stringify(repeatA) === JSON.stringify(repeatB), { repeatA, repeatB });
check('E20 purity: the caller input object is not mutated', JSON.stringify(immutableInput) === immutableSnapshot, immutableInput);

doesNotThrow('E21 hostile null input does not throw', () =>
  evaluatePromotionStage(null as unknown as PromotionStageInput)
);
doesNotThrow('E22 hostile string input does not throw', () =>
  evaluatePromotionStage('garbage' as unknown as PromotionStageInput)
);
doesNotThrow('E23 hostile array input does not throw', () =>
  evaluatePromotionStage([] as unknown as PromotionStageInput)
);

const nullResult = evaluatePromotionStage(null as unknown as PromotionStageInput);
check(
  'E24 null input fails closed with a diagnostic reason',
  nullResult.advance === false && nullResult.rollback === false && nullResult.reasons.length === 1,
  nullResult
);

const poisoned = evaluatePromotionStage(
  cleanStage({
    errorDeltaPct: Number.NaN,
    p99DeltaPct: Number.POSITIVE_INFINITY,
    qualityDelta: 'x' as unknown as number,
  })
);
check(
  'E25 poisoned numeric values are rejected, not normalized',
  poisoned.advance === false &&
    poisoned.rollback === false &&
    (poisoned.reasons.join(' ').match(/must be a finite number/g) ?? []).length === 3,
  poisoned
);

const badCoverage = evaluatePromotionStage(
  cleanStage({ coverage: 1.5, baselineCoverage: -0.1 })
);
check(
  'E26 out-of-range coverage fractions fail closed',
  badCoverage.advance === false && /\[0,1\]/.test(badCoverage.reasons.join(' ')),
  badCoverage
);

const hostileGetter = {
  get stage(): PromotionStageInput['stage'] {
    throw new Error('hostile getter');
  },
};
doesNotThrow('E27 hostile throwing getter does not throw', () =>
  evaluatePromotionStage(hostileGetter as unknown as PromotionStageInput)
);
check(
  'E28 hostile getter degrades to a diagnostic result',
  evaluatePromotionStage(hostileGetter as unknown as PromotionStageInput).advance === false
);

/* -------------------------------------------------------------------------- */
/* 4. additiveFieldContract                                                    */
/* -------------------------------------------------------------------------- */

const contractPass = additiveFieldContract(cleanContract());
check('F1 fully evidenced additive field is safe', contractPass.safe === true && contractPass.issues.length === 0, contractPass);

const missingField = additiveFieldContract(cleanContract({ fieldPresent: false }));
check(
  'F2 field not observed is unsafe',
  missingField.safe === false && /fieldPresent/.test(missingField.issues.join(' ')),
  missingField
);

const noOldProducer = additiveFieldContract(cleanContract({ oldProducer: false }));
check(
  'F3 no old producer is unsafe',
  noOldProducer.safe === false && /oldProducer/.test(noOldProducer.issues.join(' ')),
  noOldProducer
);

const noOldConsumer = additiveFieldContract(cleanContract({ oldConsumer: false }));
check(
  'F4 no old consumer is unsafe',
  noOldConsumer.safe === false && /oldConsumer/.test(noOldConsumer.issues.join(' ')),
  noOldConsumer
);

const noProof = additiveFieldContract(cleanContract({ noBehaviorChangeProof: false }));
check(
  'F5 missing no-behavior-change proof is unsafe',
  noProof.safe === false && /noBehaviorChangeProof|replay/.test(noProof.issues.join(' ')),
  noProof
);

const noTolerantReader = additiveFieldContract(cleanContract({ tolerantReader: false }));
check(
  'F6 missing tolerant reader is unsafe',
  noTolerantReader.safe === false && /tolerantReader/.test(noTolerantReader.issues.join(' ')),
  noTolerantReader
);

const noFlagParity = additiveFieldContract(cleanContract({ flagOffParity: false }));
check(
  'F7 missing flag-off parity is unsafe',
  noFlagParity.safe === false && /flagOffParity/.test(noFlagParity.issues.join(' ')),
  noFlagParity
);

const allFalse = additiveFieldContract(
  cleanContract({
    fieldPresent: false,
    oldProducer: false,
    oldConsumer: false,
    noBehaviorChangeProof: false,
    tolerantReader: false,
    flagOffParity: false,
  })
);
check(
  'F8 every missing pre-condition is reported separately',
  allFalse.safe === false && allFalse.issues.length === 6,
  allFalse
);

const truthyNonBooleans = additiveFieldContract({
  fieldPresent: 1,
  oldProducer: 'true',
  oldConsumer: [],
  noBehaviorChangeProof: {},
  tolerantReader: 1,
  flagOffParity: 'yes',
} as unknown as AdditiveFieldContractInput);
check(
  'F9 truthy non-boolean evidence never satisfies a contract',
  truthyNonBooleans.safe === false && truthyNonBooleans.issues.length === 6,
  truthyNonBooleans
);

doesNotThrow('F10 hostile null input does not throw', () =>
  additiveFieldContract(null as unknown as AdditiveFieldContractInput)
);
doesNotThrow('F11 hostile string input does not throw', () =>
  additiveFieldContract('nope' as unknown as AdditiveFieldContractInput)
);
doesNotThrow('F12 hostile throwing getter does not throw', () =>
  additiveFieldContract({
    get fieldPresent(): boolean {
      throw new Error('hostile getter');
    },
  } as unknown as AdditiveFieldContractInput)
);

const nullContract = additiveFieldContract(null as unknown as AdditiveFieldContractInput);
check(
  'F13 null contract fails closed with a diagnostic issue',
  nullContract.safe === false && nullContract.issues.length === 1,
  nullContract
);

const contractInput = cleanContract();
const contractSnapshot = JSON.stringify(contractInput);
const contractRepeatA = additiveFieldContract(contractInput);
const contractRepeatB = additiveFieldContract(contractInput);
check('F14 determinism: identical contracts yield identical results', JSON.stringify(contractRepeatA) === JSON.stringify(contractRepeatB));
check('F15 purity: the caller contract object is not mutated', JSON.stringify(contractInput) === contractSnapshot, contractInput);

/* -------------------------------------------------------------------------- */

console.log(
  `\npromotion gates: ${assertions - failures}/${assertions} assertions passed` +
    (failures ? `, ${failures} FAILED` : '')
);
if (failures > 0) process.exitCode = 1;
