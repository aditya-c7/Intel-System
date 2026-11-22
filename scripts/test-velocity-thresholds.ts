/**
 * Shadow-only tests for `src/lib/velocityThresholds.ts`.
 *
 * Covers the fixed/adaptive threshold boundary (99/100), the 10000 distinct-value cap,
 * Clopper-Pearson cold-start gating (total < 200), hostile input, and purity/determinism.
 *
 *   npx tsx scripts/test-velocity-thresholds.ts
 *
 * Exits non-zero when any assertion fails. Nothing here writes state or schedules work.
 */
import {
  highActivityThreshold,
  velocityCap,
  rarityBucket,
  FIXED_HIGH_ACTIVITY_FLOOR,
  SMALL_CORPUS_LIMIT,
  VELOCITY_DISTINCT_CAP,
  COLD_START_MIN_TOTAL,
  type VelocityCapInput,
} from '../src/lib/velocityThresholds';

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

/* -------------------------------------------------------------------------- */
/* 1. highActivityThreshold                                                    */
/* -------------------------------------------------------------------------- */

const small = highActivityThreshold(99);
check(
  'H1 boundary 99 → fixed_small_corpus',
  small.mode === 'fixed_small_corpus',
  small
);
check('H2 fixed floor is 16', small.threshold === FIXED_HIGH_ACTIVITY_FLOOR && small.threshold === 16, small);
check('H3 fixed reason is non-empty', small.reason.length > 0, small);

const zero = highActivityThreshold(0);
check('H4 zero visitors stays fixed', zero.mode === 'fixed_small_corpus' && zero.threshold === 16, zero);

const smallWithDistribution = highActivityThreshold(99, [1, 2, 3, 4, 5, 999]);
check(
  'H5 small corpus with distribution stays fixed (no percentile)',
  smallWithDistribution.mode === 'fixed_small_corpus' && smallWithDistribution.threshold === 16,
  smallWithDistribution
);

const largeNoDist = highActivityThreshold(100);
check(
  'H6 boundary 100 → adaptive_p98',
  largeNoDist.mode === 'adaptive_p98',
  largeNoDist
);
check(
  'H7 adaptive without distribution fails closed to floor 16',
  largeNoDist.threshold === 16,
  largeNoDist
);

const ascending = Array.from({ length: 100 }, (_, i) => i + 1); // sorted 1..100
const largeWithDist = highActivityThreshold(100, ascending);
check(
  'H8 adaptive p98 of 1..100 is 98',
  largeWithDist.mode === 'adaptive_p98' && largeWithDist.threshold === 98,
  largeWithDist
);

const unsortedInput = [100, 1, 50, 2, 99, 3, 98, 4];
const unsortedSnapshot = unsortedInput.slice();
const unsortedResult = highActivityThreshold(250, unsortedInput);
check(
  'H9 defensive sort: unsorted input still yields a positive p98',
  unsortedResult.threshold >= 1 && Number.isFinite(unsortedResult.threshold),
  unsortedResult
);
check(
  'H10 purity: caller distribution is not mutated',
  JSON.stringify(unsortedInput) === JSON.stringify(unsortedSnapshot),
  unsortedInput
);

const repeatA = highActivityThreshold(100, ascending);
const repeatB = highActivityThreshold(100, ascending);
check(
  'H11 determinism: identical inputs yield identical results',
  JSON.stringify(repeatA) === JSON.stringify(repeatB),
  { repeatA, repeatB }
);

const zeros = highActivityThreshold(500, [0, 0, 0, 0]);
check(
  'H12 all-zero distribution never produces a zero threshold',
  zeros.mode === 'adaptive_p98' && zeros.threshold >= 1,
  zeros
);

check('H13 hostile NaN visitors does not throw', (() => {
  const r = highActivityThreshold(Number.NaN);
  return r.mode === 'fixed_small_corpus' && r.threshold === 16;
})(), highActivityThreshold(Number.NaN));

doesNotThrow('H14 hostile distribution (string) does not throw', () =>
  highActivityThreshold(100, 'not-an-array' as unknown as number[])
);
doesNotThrow('H15 hostile distribution (null) does not throw', () =>
  highActivityThreshold(100, null as unknown as number[])
);

const poisoned = highActivityThreshold(100, [NaN, -5, Infinity, 'x', null, 7] as unknown as number[]);
check(
  'H16 poisoned distribution values are filtered, result still safe',
  poisoned.mode === 'adaptive_p98' && poisoned.threshold === 7,
  poisoned
);

check('H17 corpus limit constant is 100', SMALL_CORPUS_LIMIT === 100);

/* -------------------------------------------------------------------------- */
/* 2. velocityCap                                                              */
/* -------------------------------------------------------------------------- */

const underCap = velocityCap({
  distinct: { '5_minutes': 10, '1_hour': 50, '24_hours': 9999 },
  events: { '24_hours': 4242 },
  ip_events: { '24_hours': 77 },
});
check(
  'V1 9999 distinct: short windows kept, no capping',
  underCap.omitShortWindows === false && underCap.capped24h === 9999,
  underCap
);
check(
  'V2 events / ip_events reported exact below cap',
  underCap.eventsExact === 4242 && underCap.ipEventsExact === 77,
  underCap
);

const atCap = velocityCap({
  distinct: { '5_minutes': 1, '1_hour': 2, '24_hours': VELOCITY_DISTINCT_CAP },
});
check(
  'V3 exactly 10000 is not above the cap',
  atCap.omitShortWindows === false && atCap.capped24h === 10000,
  atCap
);

const aboveCap = velocityCap({
  distinct: { '5_minutes': 100, '1_hour': 500, '24_hours': 10001 },
  events: 999999,
  ip_events: 1234567,
});
check(
  'V4 10001 distinct: omit short windows, cap 24h at 10000',
  aboveCap.omitShortWindows === true && aboveCap.capped24h === VELOCITY_DISTINCT_CAP,
  aboveCap
);
check(
  'V5 events / ip_events stay exact above the cap',
  aboveCap.eventsExact === 999999 && aboveCap.ipEventsExact === 1234567,
  aboveCap
);

const shortWindowSpike = velocityCap({
  distinct: { '5_minutes': 20000, '1_hour': 0, '24_hours': 500 },
});
check(
  'V6 short-window spike triggers omission but does not inflate capped24h',
  shortWindowSpike.omitShortWindows === true && shortWindowSpike.capped24h === 500,
  shortWindowSpike
);

const namedSignals = velocityCap({
  distinct: {
    distinct_ip: { '5_minutes': 5, '1_hour': 9, '24_hours': 15000 },
    distinct_linked_id: { '5_minutes': 2, '1_hour': 3, '24_hours': 4 },
  },
});
check(
  'V7 named distinct signals aggregate to worst value per window',
  namedSignals.omitShortWindows === true && namedSignals.capped24h === 10000,
  namedSignals
);

doesNotThrow('V8 hostile null counts does not throw', () =>
  velocityCap(null as unknown as VelocityCapInput)
);
doesNotThrow('V9 hostile string counts does not throw', () =>
  velocityCap('garbage' as unknown as VelocityCapInput)
);

const hostileCounts = velocityCap({ distinct: 'bad', events: NaN, ip_events: -9 });
check(
  'V10 hostile field values fail closed to zeros',
  hostileCounts.omitShortWindows === false &&
    hostileCounts.capped24h === 0 &&
    hostileCounts.eventsExact === 0 &&
    hostileCounts.ipEventsExact === 0,
  hostileCounts
);

const capInput = { distinct: { '24_hours': 10001 }, events: { '24_hours': 3 } };
const capSnapshot = JSON.stringify(capInput);
velocityCap(capInput);
check('V11 purity: velocityCap does not mutate its input', JSON.stringify(capInput) === capSnapshot);
check('V12 cap constant is 10000', VELOCITY_DISTINCT_CAP === 10000);

/* -------------------------------------------------------------------------- */
/* 3. rarityBucket                                                             */
/* -------------------------------------------------------------------------- */

const cold = rarityBucket(1, COLD_START_MIN_TOTAL - 1, true);
check(
  'R1 total 199 → insufficient_data, never rare',
  cold.bucket === 'insufficient_data' && cold.rare === false,
  cold
);
check('R2 cold-start reason mentions the gate', /cold_start_gate|total14d<200/.test(cold.reason), cold);

const atColdBoundary = rarityBucket(1, COLD_START_MIN_TOTAL, true);
check(
  'R3 total 200 with one observation → rare_p95, rare=true',
  atColdBoundary.bucket === 'rare_p95' && atColdBoundary.rare === true,
  atColdBoundary
);

const p99 = rarityBucket(1, 1000, true);
check(
  'R4 total 1000 with one observation → very_rare_p99',
  p99.bucket === 'very_rare_p99' && p99.rare === true,
  p99
);

const common = rarityBucket(100, 200, true);
check(
  'R5 frequent configuration → common, rare=false',
  common.bucket === 'common' && common.rare === false,
  common
);

const notObserved = rarityBucket(1, 1000, false);
check(
  'R6 observed=false → unobserved, never rare',
  notObserved.bucket === 'unobserved' && notObserved.rare === false,
  notObserved
);

const unobservedZero = rarityBucket(1, 1000, 0);
check(
  'R7 observed=0 → unobserved, never rare',
  unobservedZero.bucket === 'unobserved' && unobservedZero.rare === false,
  unobservedZero
);

check(
  'R8 low total never asserts rare even with frequency 0',
  rarityBucket(0, 199, true).rare === false
);

doesNotThrow('R9 hostile string arguments do not throw', () =>
  rarityBucket('x', 'y', 'z')
);
doesNotThrow('R10 hostile null arguments do not throw', () =>
  rarityBucket(null, null, null)
);

const hostileRarity = rarityBucket(NaN, -5, 'false');
check(
  'R11 hostile rarity input fails closed',
  hostileRarity.rare === false && hostileRarity.reason.length > 0,
  hostileRarity
);

const buckets = new Set<string>([
  cold.bucket,
  atColdBoundary.bucket,
  p99.bucket,
  common.bucket,
  notObserved.bucket,
  rarityBucket(20, 200, true).bucket,
]);
check('R12 exactly six distinct buckets are reachable', buckets.size === 6, [...buckets]);

const allReasons = [
  cold,
  atColdBoundary,
  p99,
  common,
  notObserved,
  rarityBucket(20, 200, true),
];
check('R13 every bucket returns a non-empty reason', allReasons.every((r) => r.reason.length > 0));

check('R14 cold-start constant is 200', COLD_START_MIN_TOTAL === 200);

/* -------------------------------------------------------------------------- */

console.log(
  `\nvelocity thresholds: ${assertions - failures}/${assertions} assertions passed` +
    (failures ? `, ${failures} FAILED` : '')
);
if (failures > 0) process.exitCode = 1;
