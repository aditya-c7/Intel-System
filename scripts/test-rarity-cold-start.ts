/**
 * Shadow-only tests for `src/lib/rarityColdStart.ts` (RS7).
 *
 * Covers closed forms, beta-inverse bounds, Clopper–Pearson rarity gating, zero-hit
 * sample floors, Bonferroni device multiplicity, lazy 14-day windows (no timers),
 * cross-bucket id dedupe, hostile input, purity and determinism.
 *
 *   npx tsx scripts/test-rarity-cold-start.ts
 *
 * Exits non-zero when any assertion fails. Nothing here writes state or schedules work.
 */
import {
  oneSidedUpper,
  ruleOfThreeUpper,
  rarityDecision,
  rollingFrequency,
  DEFAULT_ALPHA,
  DEFAULT_RARE_THRESHOLD,
  DEFAULT_MIN_SAMPLES,
  MS_PER_DAY,
  type RarityDecisionInput,
  type CountsByDay,
} from '../src/lib/rarityColdStart';

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

function doesNotThrow(name: string, fn: () => unknown): void {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  check(name, !threw);
}

function near(actual: number, expected: number, tolerance = 1e-6): boolean {
  return Number.isFinite(actual) && Math.abs(actual - expected) <= tolerance;
}

/* -------------------------------------------------------------------------- */
/* 1. oneSidedUpper                                                            */
/* -------------------------------------------------------------------------- */

const u0n300 = oneSidedUpper(0, 300, 0.05);
check('U1 k=0 uses closed form 1-alpha^(1/n)', near(u0n300, -Math.expm1(Math.log(0.05) / 300)), u0n300);
check('U2 k=0 n=300 clears p*=0.01 only by the bound', u0n300 < 0.01 && near(u0n300, 0.009936, 1e-5), u0n300);
check(
  'U3 zero-hit bound shrinks with n',
  oneSidedUpper(0, 100, 0.05) > oneSidedUpper(0, 300, 0.05) &&
    oneSidedUpper(0, 300, 0.05) > oneSidedUpper(0, 3000, 0.05)
);
check('U4 k=n collapses to 1', oneSidedUpper(10, 10, 0.05) === 1 && oneSidedUpper(1, 1, 0.05) === 1);
check('U5 n=0 collapses to 1', oneSidedUpper(0, 0, 0.05) === 1 && oneSidedUpper(5, 0, 0.05) === 1);
check('U6 k=0 n=1 gives exactly 1-alpha', near(oneSidedUpper(0, 1, 0.05), 0.95), oneSidedUpper(0, 1, 0.05));
check('U7 alpha=1 -> 0 and alpha=0 -> 1', oneSidedUpper(3, 10, 1) === 0 && oneSidedUpper(3, 10, 0) === 1);
check(
  'U8 hostile k/n/alpha fail closed to 1 without throwing',
  oneSidedUpper(NaN, 100, 0.05) === 1 &&
    oneSidedUpper(1, -5, 0.05) === 1 &&
    oneSidedUpper('x', 100, 0.05) === 1 &&
    oneSidedUpper(1, 100, 'bad') === 0.05 * 0 + oneSidedUpper(1, 100, 0.05)
);
check('U9 hits clamped to [0,n]', oneSidedUpper(999, 10, 0.05) === 1 && oneSidedUpper(-3, 10, 0.05) === u0n300 * 0 + oneSidedUpper(0, 10, 0.05));
const u1n100 = oneSidedUpper(1, 100, 0.05);
check('U10 1/100 raw=0.01 but bound ~0.047 (never raw k/n)', u1n100 > 0.04 && u1n100 < 0.06, u1n100);
const u5n100 = oneSidedUpper(5, 100, 0.05);
check('U11 beta-inverse bound for k=5,n=100 lands in [0.10,0.14]', u5n100 > 0.10 && u5n100 < 0.14, u5n100);
check('U12 larger alpha gives a smaller bound', oneSidedUpper(1, 100, 0.10) < oneSidedUpper(1, 100, 0.05));
check(
  'U13 determinism',
  oneSidedUpper(7, 250, 0.05) === oneSidedUpper(7, 250, 0.05)
);
check('U14 rule of three is 3/n for n>30 and 1 otherwise', ruleOfThreeUpper(100) === 0.03 && ruleOfThreeUpper(30) === 1);
check(
  'U15 rule of three approximates the k=0 closed form for n>30',
  Math.abs(ruleOfThreeUpper(300) - oneSidedUpper(0, 300, 0.05)) < 0.002
);
doesNotThrow('U16 hostile object arguments do not throw', () => oneSidedUpper({} as unknown as number, {} as unknown as number));

/* -------------------------------------------------------------------------- */
/* 2. rarityDecision                                                          */
/* -------------------------------------------------------------------------- */

check('D1 constants: alpha=0.05, p*=0.01, hard floor=30', DEFAULT_ALPHA === 0.05 && DEFAULT_RARE_THRESHOLD === 0.01 && DEFAULT_MIN_SAMPLES === 30);

const cold = rarityDecision({ hits: 1, total: 29 });
check('D2 total 29 -> insufficient_data, no bound, not rare', cold.bucket === 'insufficient_data' && cold.p_upper === null && cold.rare === false, cold);
check('D3 insufficient reason names the hard floor', cold.reasons.some((r) => r.startsWith('below_hard_sample_floor')), cold);

const notSeen = rarityDecision({ hits: 0, total: 100 });
check('D4 zero hits at n=100 -> not_seen, not rare', notSeen.bucket === 'not_seen' && notSeen.rare === false, notSeen);
check('D5 not_seen still reports the closed-form bound', notSeen.p_upper !== null && near(notSeen.p_upper as number, oneSidedUpper(0, 100, 0.05)), notSeen);
check('D6 zero-hit floor boundary 299 -> not_seen', rarityDecision({ hits: 0, total: 299 }).bucket === 'not_seen');
const zeroAtFloor = rarityDecision({ hits: 0, total: 300 });
check('D7 zero hits at n=300 -> p99, rare=true', zeroAtFloor.bucket === 'p99' && zeroAtFloor.rare === true, zeroAtFloor);
check('D8 p99.9+ at n=3000 with zero hits', rarityDecision({ hits: 0, total: 3000 }).bucket === 'p99.9+');
const p95 = rarityDecision({ hits: 1, total: 100 });
check('D9 1/100 -> p95 bucket, rare=false', p95.bucket === 'p95' && p95.rare === false, p95);
const common = rarityDecision({ hits: 5, total: 100 });
check('D10 frequent signal -> common, rare=false', common.bucket === 'common' && common.rare === false, common);
check('D11 raw k/n equal to p* is NOT a rare claim', p95.p_upper !== null && (p95.p_upper as number) >= 0.01 && p95.rare === false, p95);
const multi = rarityDecision({ hits: 0, total: 300, deviceCount: 5 });
check('D12 Bonferroni adjustedAlpha = alpha/deviceCount', near(multi.adjustedAlpha, 0.01), multi);
check('D13 device multiplicity pushes n=300 back to not_seen', multi.bucket === 'not_seen' && multi.rare === false, multi);
check('D14 multiplicity reason is recorded', rarityDecision({ hits: 1, total: 100, deviceCount: 2 }).reasons.some((r) => r.includes('multiplicity')));
const strict = rarityDecision({ hits: 1, total: 5000, rareThreshold: 0.0001 });
check('D15 custom p*=0.0001 keeps p99.9+ bucket but rare=false', strict.bucket === 'p99.9+' && strict.rare === false, strict);
check(
  'D15b a stricter p* raises the zero-hit sample floor',
  rarityDecision({ hits: 0, total: 3000, rareThreshold: 0.0001 }).bucket === 'not_seen'
);

doesNotThrow('D16 null input does not throw', () => rarityDecision(null));
doesNotThrow('D17 hostile string input does not throw', () => rarityDecision('bad' as unknown as RarityDecisionInput));
const hostile = rarityDecision({ hits: NaN, total: -4, alpha: Infinity, deviceCount: NaN });
check('D18 hostile fields fail closed to insufficient_data', hostile.bucket === 'insufficient_data' && hostile.rare === false && hostile.p_upper === null, hostile);
const inputs: RarityDecisionInput = { hits: 2, total: 500, deviceCount: 3 };
const snapshot = JSON.stringify(inputs);
rarityDecision(inputs);
check('D19 purity: input object is not mutated', JSON.stringify(inputs) === snapshot);
check('D20 determinism: identical inputs yield identical results', JSON.stringify(rarityDecision({ hits: 2, total: 500 })) === JSON.stringify(rarityDecision({ hits: 2, total: 500 })));
check('D21 every decision carries a non-empty reason list', [cold, notSeen, zeroAtFloor, p95, common, multi, strict].every((r) => r.reasons.length > 0));
check('D22 rare=true always implies p_upper < rareThreshold', [zeroAtFloor, rarityDecision({ hits: 0, total: 3000 })].every((r) => r.rare && r.p_upper !== null && (r.p_upper as number) < 0.01));

/* -------------------------------------------------------------------------- */
/* 3. rollingFrequency                                                        */
/* -------------------------------------------------------------------------- */

const NOW = Date.UTC(2026, 10, 23);
const day = (offset: number): number => NOW - offset * MS_PER_DAY;

const buckets: CountsByDay = {
  [day(13)]: { hits: 1, total: 10 },
  [day(1)]: { hits: 2, total: 20 },
  [day(0)]: { hits: 0, total: 5 },
  [day(15)]: { hits: 100, total: 1000 },
  [day(-1)]: { hits: 1000, total: 1000 },
};
const rolled = rollingFrequency(buckets, NOW);
check('F1 lazy 14-day aggregation sums in-window buckets', rolled.total === 35 && rolled.hits === 3, rolled);
check('F2 buckets older than the window are excluded', rollingFrequency({ [day(15)]: { total: 100 } }, NOW).total === 0);
check('F3 future buckets are excluded', rollingFrequency({ [day(-1)]: { total: 100 } }, NOW).total === 0);
check('F4 exact cutoff bucket is included', rollingFrequency({ [day(14)]: { total: 7 } }, NOW).total === 7);
check(
  'F5 partial first bucket is never extrapolated into n',
  rollingFrequency({ [day(13)]: { hits: 1, total: 5 } }, NOW).total === 5
);
check('F6 bare numeric buckets count as total with zero hits', (() => {
  const r = rollingFrequency({ [day(2)]: 12 }, NOW);
  return r.total === 12 && r.hits === 0;
})());

const deduped = rollingFrequency(
  {
    [day(2)]: {
      observations: [
        { id: 'a', hit: true },
        { id: 'b', hit: false },
        { id: 'c', hit: true },
      ],
    },
    [day(1)]: {
      hits: 999,
      total: 999,
      observations: [
        { id: 'c', hit: true },
        { id: 'd', hit: true },
      ],
    },
  },
  NOW
);
check('F7 observations dedupe by unique id across buckets', deduped.total === 4 && deduped.hits === 3, deduped);
check('F8 custom windowDays=7 drops day-13 data', rollingFrequency(buckets, NOW, 7).total === 25, rollingFrequency(buckets, NOW, 7));
check('F9 hits are clamped to total', (() => {
  const r = rollingFrequency({ [day(1)]: { hits: 50, total: 5 } }, NOW);
  return r.total === 5 && r.hits === 5;
})());

const rollSnapshot = JSON.stringify(buckets);
rollingFrequency(buckets, NOW);
check('F10 purity: countsByDay is not mutated', JSON.stringify(buckets) === rollSnapshot);
check('F11 determinism', JSON.stringify(rollingFrequency(buckets, NOW)) === JSON.stringify(rollingFrequency(buckets, NOW)));

const arrayBuckets: CountsByDay = [
  { day: day(3), hits: 1, total: 2 },
  { day: day(2), hits: 2, total: 3 },
];
check('F12 array-shaped dated buckets are supported', (() => {
  const r = rollingFrequency(arrayBuckets, NOW);
  return r.total === 5 && r.hits === 3;
})());
check('F13 invalid nowMs fails closed to zeros', (() => {
  const r = rollingFrequency(buckets, NaN);
  return r.total === 0 && r.hits === 0;
})());
doesNotThrow('F14 hostile countsByDay does not throw', () => rollingFrequency('garbage' as unknown as CountsByDay, NOW));
doesNotThrow('F15 hostile null countsByDay does not throw', () => rollingFrequency(null, NOW));
check('F16 missing/unparseable day is excluded, not guessed', rollingFrequency({ mystery: { total: 99 } }, NOW).total === 0);
check('F17 poisoned observation ids still count deterministically', (() => {
  const r = rollingFrequency({ [day(1)]: { observations: [{ id: '', hit: 1 }, { id: 0, hit: true }, { hit: true }] } } as CountsByDay, NOW);
  return r.total === 2 && r.hits === 2;
})());

/* -------------------------------------------------------------------------- */

console.log(
  `\nrarity cold start: ${assertions - failures}/${assertions} assertions passed` +
    (failures ? `, ${failures} FAILED` : '')
);
if (failures > 0) process.exitCode = 1;
