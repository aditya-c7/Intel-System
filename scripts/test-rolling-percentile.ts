/**
 * RS6 regression suite for `src/lib/rollingPercentile.ts`.
 *
 *   npx tsx scripts/test-rolling-percentile.ts
 *
 * Covers the pure nearest-rank p98 fallback, cold start (N<100), the N=99/100 regime
 * boundary, the N<50 degenerate-max note, the bounded 1000-observation window, timestamp
 * anchoring, hostile input, determinism and explicit absence of clock/timer use.
 * Exits non-zero on any failure. Nothing here writes state or schedules work.
 */
import assert from 'node:assert/strict';

import {
  DEFAULT_FLOOR,
  DEFAULT_MIN_SAMPLES,
  DEGENERATE_MAX_N,
  MAX_ROLLING_WINDOW,
  PERCENTILE_P98,
  nearestRankPercentile,
  resolveHighActivityThreshold,
  type ResolvedHighActivityThreshold,
} from '../src/lib/rollingPercentile';

let passed = 0;
const failures: string[] = [];

function check(name: string, verify: () => void): void {
  try {
    verify();
    passed += 1;
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

const ascending = (n: number): number[] => Array.from({ length: n }, (_, i) => i + 1);
const hasReason = (result: ResolvedHighActivityThreshold, token: string): boolean =>
  result.reasons.includes(token);

/* -------------------------------------------------------------------------- */
/* 1. Constants + nearestRankPercentile                                        */
/* -------------------------------------------------------------------------- */

section('1. Constants and nearest-rank percentile');

check('RS6 constants are locked', () => {
  assert.equal(DEFAULT_FLOOR, 16);
  assert.equal(DEFAULT_MIN_SAMPLES, 100);
  assert.equal(MAX_ROLLING_WINDOW, 1000);
  assert.equal(PERCENTILE_P98, 0.98);
  assert.equal(DEGENERATE_MAX_N, 50);
});

check('nearest rank over an unsorted array sorts a copy (p=0.5 → 2, p=1 → 3)', () => {
  assert.equal(nearestRankPercentile([3, 1, 2], 0.5), 2);
  assert.equal(nearestRankPercentile([3, 1, 2], 1), 3);
});

check('nearest-rank p98 of 1..100 is 98 (ceil(98)=98)', () => {
  assert.equal(nearestRankPercentile(ascending(100), 0.98), 98);
});

check('p98 degenerates to max for N=49 but not for N=50', () => {
  assert.equal(nearestRankPercentile(ascending(49), 0.98), 49);
  assert.equal(nearestRankPercentile(ascending(50), 0.98), 49);
  assert.equal(nearestRankPercentile(ascending(50), 1), 50);
});

check('empty / non-array input returns null', () => {
  assert.equal(nearestRankPercentile([], 0.98), null);
  assert.equal(nearestRankPercentile(null, 0.98), null);
  assert.equal(nearestRankPercentile('12345', 0.98), null);
  assert.equal(nearestRankPercentile({ 0: 1, length: 1 }, 0.98), null);
});

check('invalid percentile returns null without throwing', () => {
  for (const p of [0, -0.5, 1.1, Number.NaN, Infinity, -Infinity, '0.98', null]) {
    assert.equal(nearestRankPercentile([1, 2, 3], p), null, `p=${String(p)}`);
  }
});

check('hostile entries are discarded; finite values still produce a result', () => {
  const result = nearestRankPercentile(
    [Number.NaN, Infinity, -Infinity, 'x', null, undefined, {}, [], 7, 3, 5],
    0.98
  );
  assert.equal(result, 7);
});

check('nearestRankPercentile does not mutate the caller array', () => {
  const input = [9, 4, 7, 1];
  const snapshot = input.slice();
  nearestRankPercentile(input, 0.98);
  assert.deepEqual(input, snapshot);
});

check('nearestRankPercentile is deterministic', () => {
  const input = [5, 2, 9, 1, 7, 3];
  assert.equal(nearestRankPercentile(input, 0.98), nearestRankPercentile(input, 0.98));
});

check('a throwing array proxy returns null instead of throwing', () => {
  const hostile = new Proxy([], {
    get() {
      throw new Error('hostile array access');
    },
  });
  let result: number | null = 1;
  assert.doesNotThrow(() => {
    result = nearestRankPercentile(hostile, 0.98);
  });
  assert.equal(result, null);
});

/* -------------------------------------------------------------------------- */
/* 2. Cold start and the 99/100 regime boundary                                */
/* -------------------------------------------------------------------------- */

section('2. Cold start and regime boundary');

check('N=0 → fixed_small_corpus, threshold=floor, n=0', () => {
  const result = resolveHighActivityThreshold({ observations: [] });
  assert.equal(result.mode, 'fixed_small_corpus');
  assert.equal(result.threshold, DEFAULT_FLOOR);
  assert.equal(result.n, 0);
  assert.ok(hasReason(result, 'no_usable_observations'));
  assert.ok(hasReason(result, 'fixed_floor_applied'));
});

check('N=1 → fixed floor and degenerate-max reason', () => {
  const result = resolveHighActivityThreshold({ observations: [9999] });
  assert.equal(result.mode, 'fixed_small_corpus');
  assert.equal(result.threshold, 16);
  assert.equal(result.n, 1);
  assert.ok(hasReason(result, 'p98_degenerates_to_max_below_50'));
});

check('N=49 → fixed floor; N=50 with default minSamples → still fixed', () => {
  const at49 = resolveHighActivityThreshold({ observations: ascending(49) });
  const at50 = resolveHighActivityThreshold({ observations: ascending(50) });
  assert.equal(at49.mode, 'fixed_small_corpus');
  assert.equal(at50.mode, 'fixed_small_corpus');
  assert.equal(at50.threshold, 16);
  assert.ok(hasReason(at49, 'p98_degenerates_to_max_below_50'));
  assert.ok(hasReason(at50, 'cold_start_n_lt_min_samples'));
});

check('BOUNDARY N=99 → fixed_small_corpus with cold-start reason', () => {
  const result = resolveHighActivityThreshold({ observations: ascending(99) });
  assert.equal(result.mode, 'fixed_small_corpus');
  assert.equal(result.threshold, 16);
  assert.equal(result.n, 99);
  assert.ok(hasReason(result, 'cold_start_n_lt_min_samples'));
  assert.ok(!hasReason(result, 'adaptive_p98_of_rolling_window'));
});

check('BOUNDARY N=100 → adaptive_p98, threshold=98, n=100', () => {
  const result = resolveHighActivityThreshold({ observations: ascending(100) });
  assert.equal(result.mode, 'adaptive_p98');
  assert.equal(result.threshold, 98);
  assert.equal(result.n, 100);
  assert.ok(hasReason(result, 'adaptive_p98_of_rolling_window'));
  assert.ok(!hasReason(result, 'cold_start_n_lt_min_samples'));
});

check('a distribution supplied in the cold region never becomes adaptive', () => {
  const result = resolveHighActivityThreshold({ observations: [1, 2, 3, 4, 100000] });
  assert.equal(result.mode, 'fixed_small_corpus');
  assert.equal(result.threshold, 16);
});

check('custom floor is used in the fixed regime', () => {
  const result = resolveHighActivityThreshold({ observations: ascending(50), floor: 42 });
  assert.equal(result.floor, 42);
  assert.equal(result.threshold, 42);
});

check('custom floor is a hard lower bound in the adaptive regime', () => {
  const result = resolveHighActivityThreshold({ observations: ascending(100), floor: 200 });
  assert.equal(result.mode, 'adaptive_p98');
  assert.equal(result.threshold, 200);
});

check('custom minSamples=49 enables adaptive at N=49 with degeneracy note; N=50 is not degenerate', () => {
  const at49 = resolveHighActivityThreshold({ observations: ascending(49), minSamples: 49 });
  assert.equal(at49.mode, 'adaptive_p98');
  assert.equal(at49.threshold, 49);
  assert.equal(at49.n, 49);
  assert.ok(hasReason(at49, 'p98_degenerates_to_max_below_50'));

  // ceil(0.98 * 50) === 49, so at N=50 p98 is the second-largest value, not the max.
  const at50 = resolveHighActivityThreshold({ observations: ascending(50), minSamples: 50 });
  assert.equal(at50.threshold, 49);
  assert.ok(!hasReason(at50, 'p98_degenerates_to_max_below_50'));
});

check('hostile observations lower n and can force the fixed regime', () => {
  const dirty = ascending(100).map((value, i) => (i < 6 ? Number.NaN : value));
  const result = resolveHighActivityThreshold({ observations: dirty });
  assert.equal(result.n, 94);
  assert.equal(result.mode, 'fixed_small_corpus');
  assert.ok(hasReason(result, 'hostile_observations_discarded'));
  assert.ok(hasReason(result, 'cold_start_n_lt_min_samples'));
});

/* -------------------------------------------------------------------------- */
/* 3. Bounded, data-anchored window                                            */
/* -------------------------------------------------------------------------- */

section('3. Bounded window and timestamp anchoring');

check('2000 observations are capped to the last 1000 (p98 = 1980)', () => {
  const result = resolveHighActivityThreshold({ observations: ascending(2000) });
  assert.equal(result.n, 1000);
  assert.equal(result.threshold, 1980);
  assert.equal(result.mode, 'adaptive_p98');
  assert.ok(hasReason(result, 'window_capped_at_1000'));
  assert.ok(hasReason(result, 'window_anchored_to_last_observations'));
});

check('windowSize=50 considers only the last 50 observations (p98 = 99)', () => {
  const result = resolveHighActivityThreshold({
    observations: ascending(100),
    windowSize: 50,
    minSamples: 50,
  });
  assert.equal(result.n, 50);
  assert.equal(result.threshold, 99);
  assert.ok(hasReason(result, 'window_truncated_to_requested_size'));
});

check('windowSize is clamped to MAX_ROLLING_WINDOW and hostile values fall back', () => {
  const huge = resolveHighActivityThreshold({ observations: ascending(2000), windowSize: 5000 });
  assert.equal(huge.n, 1000);
  for (const windowSize of [0, -1, Number.NaN, Infinity, '50']) {
    const result = resolveHighActivityThreshold({
      observations: ascending(2000),
      windowSize: windowSize as never,
    });
    assert.equal(result.n, 1000, `windowSize=${String(windowSize)}`);
  }
});

check('windowing never mutates the caller observations array', () => {
  const observations = ascending(2000);
  const snapshot = observations.slice();
  resolveHighActivityThreshold({ observations });
  resolveHighActivityThreshold({ observations, windowSize: 7 });
  assert.deepEqual(observations, snapshot);
});

check('supplied timestamps anchor the window to the newest data, not array position', () => {
  // By time the last 2 values are [4, 1000]; by position they would be [3, 4].
  const base = {
    observations: [1000, 2, 3, 4],
    timestamps: [4, 1, 2, 3],
    windowSize: 2,
    minSamples: 2,
    floor: 0,
  };
  const byTime = resolveHighActivityThreshold(base);
  const byPosition = resolveHighActivityThreshold({
    observations: base.observations,
    windowSize: 2,
    minSamples: 2,
    floor: 0,
  });
  assert.equal(byTime.n, 2);
  assert.equal(byTime.threshold, 1000);
  assert.ok(hasReason(byTime, 'window_anchored_by_supplied_timestamps'));
  assert.equal(byPosition.threshold, 4);
});

check('unusable / mismatched timestamps fall back to the positional tail', () => {
  const mismatched = resolveHighActivityThreshold({
    observations: [1, 2, 3],
    timestamps: [1, 2],
  });
  assert.ok(hasReason(mismatched, 'timestamps_ignored_length_mismatch'));
  assert.ok(hasReason(mismatched, 'window_anchored_to_last_observations'));

  const hostile = resolveHighActivityThreshold({
    observations: [1, 2, 3],
    timestamps: [1, Number.NaN, 3],
  });
  assert.ok(hasReason(hostile, 'timestamps_unusable_window_anchored_to_tail'));
});

/* -------------------------------------------------------------------------- */
/* 4. Hostile input — always total, always fail closed                         */
/* -------------------------------------------------------------------------- */

section('4. Hostile input fails closed without throwing');

check('null / undefined / primitive / array / function inputs never throw', () => {
  for (const hostile of [null, undefined, 42, 'garbage', true, [], () => undefined] as never[]) {
    let result: ResolvedHighActivityThreshold | undefined;
    assert.doesNotThrow(() => {
      result = resolveHighActivityThreshold(hostile);
    }, `threw for ${String(hostile)}`);
    assert.equal(result?.mode, 'fixed_small_corpus');
    assert.equal(result?.threshold, 16);
    assert.equal(result?.n, 0);
  }
});

check('throwing getters on the input object are contained', () => {
  const hostile = {
    get observations(): unknown {
      throw new Error('observations getter exploded');
    },
    get floor(): unknown {
      throw new Error('floor getter exploded');
    },
    get minSamples(): unknown {
      throw new Error('minSamples getter exploded');
    },
  };
  let result: ResolvedHighActivityThreshold | undefined;
  assert.doesNotThrow(() => {
    result = resolveHighActivityThreshold(hostile as never);
  });
  assert.equal(result?.threshold, 16);
  assert.ok(hasReason(result as ResolvedHighActivityThreshold, 'hostile_input_failed_closed'));
});

check('non-array observations, hostile floor and hostile minSamples use defaults', () => {
  const result = resolveHighActivityThreshold({
    observations: 'not-an-array' as never,
    floor: Number.NaN,
    minSamples: -5,
  });
  assert.equal(result.n, 0);
  assert.equal(result.floor, 16);
  assert.equal(result.threshold, 16);
  assert.equal(resolveHighActivityThreshold({ observations: ascending(100), floor: -1 }).floor, 16);
  assert.equal(
    resolveHighActivityThreshold({ observations: ascending(100), minSamples: 0 }).mode,
    'adaptive_p98'
  );
});

check('a throwing Proxy inside observations is discarded without throwing', () => {
  const bomb = new Proxy({}, {
    get() {
      throw new Error('hostile element');
    },
  });
  const observations = [1, bomb, 3, 4] as unknown as number[];
  let result: ResolvedHighActivityThreshold | undefined;
  assert.doesNotThrow(() => {
    result = resolveHighActivityThreshold({ observations });
  });
  assert.equal(result?.n, 3);
  assert.ok(hasReason(result as ResolvedHighActivityThreshold, 'hostile_observations_discarded'));
});

check('negative observations are discarded, zeros are valid observations', () => {
  const result = resolveHighActivityThreshold({ observations: [-5, 0, 0, 0, 3] });
  assert.equal(result.n, 4);
  assert.ok(hasReason(result, 'hostile_observations_discarded'));
});

/* -------------------------------------------------------------------------- */
/* 5. Purity, determinism and no clock / timer dependence                      */
/* -------------------------------------------------------------------------- */

section('5. Purity, determinism, zero clock/timer dependence');

check('result has exactly the five documented fields, none time-like', () => {
  const result = resolveHighActivityThreshold({ observations: ascending(100) });
  assert.deepEqual(Object.keys(result).sort(), ['floor', 'mode', 'n', 'reasons', 'threshold']);
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes('timestamp'));
  assert.ok(!serialized.includes('expires'));
  assert.ok(!serialized.includes('current'));
});

check('identical input yields deeply identical output (no hidden state)', () => {
  const input = { observations: ascending(150) };
  const a = resolveHighActivityThreshold(input);
  const b = resolveHighActivityThreshold(input);
  assert.deepEqual(a, b);
});

check('interleaving other calls cannot drift a repeated result', () => {
  const input = { observations: ascending(100) };
  const baseline = resolveHighActivityThreshold(input);
  resolveHighActivityThreshold({ observations: [1, 2, 3] });
  resolveHighActivityThreshold({ observations: ascending(2000), floor: 999 });
  nearestRankPercentile(ascending(49), 0.98);
  assert.deepEqual(resolveHighActivityThreshold(input), baseline);
});

check('no clock, randomness, timer or scheduler is consulted', () => {
  const saved = {
    now: Date.now,
    random: Math.random,
    setTimeout: globalThis.setTimeout,
    setInterval: globalThis.setInterval,
    setImmediate: globalThis.setImmediate,
    queueMicrotask: globalThis.queueMicrotask,
  };
  const boom = (): never => {
    throw new Error('clock/timer/random access detected');
  };
  let result: ResolvedHighActivityThreshold | undefined;
  let percentile: number | null = 1;
  try {
    Date.now = boom;
    Math.random = boom;
    const globals = globalThis as Record<string, unknown>;
    globals['setTimeout'] = boom;
    globals['setInterval'] = boom;
    globals['setImmediate'] = boom;
    globals['queueMicrotask'] = boom;

    result = resolveHighActivityThreshold({ observations: ascending(2000) });
    percentile = nearestRankPercentile(ascending(100), 0.98);
  } finally {
    Date.now = saved.now;
    Math.random = saved.random;
    const globals = globalThis as Record<string, unknown>;
    globals['setTimeout'] = saved.setTimeout;
    globals['setInterval'] = saved.setInterval;
    globals['setImmediate'] = saved.setImmediate;
    globals['queueMicrotask'] = saved.queueMicrotask;
  }
  assert.equal(result?.mode, 'adaptive_p98');
  assert.equal(result?.threshold, 1980);
  assert.equal(percentile, 98);
});

check('reason tokens are stable lowercase audit strings', () => {
  const results = [
    resolveHighActivityThreshold({}),
    resolveHighActivityThreshold({ observations: ascending(49) }),
    resolveHighActivityThreshold({ observations: ascending(99) }),
    resolveHighActivityThreshold({ observations: ascending(100) }),
    resolveHighActivityThreshold({ observations: ascending(2000) }),
    resolveHighActivityThreshold(null),
  ];
  for (const result of results) {
    assert.ok(result.reasons.length > 0);
    for (const reason of result.reasons) {
      assert.match(reason, /^[a-z0-9_]+$/, reason);
    }
  }
});

check('fuzzed hostile inputs always return a finite, non-negative threshold', () => {
  const corpus: unknown[] = [
    null,
    undefined,
    0,
    'x',
    {},
    [],
    [null, undefined, NaN, Infinity, 'x', -1, 0, 5],
    { observations: [Number.NaN, Infinity, '3', null, 7] },
    { observations: ascending(101), floor: Number.NEGATIVE_INFINITY, minSamples: NaN },
    { observations: [1, 2, 3], timestamps: [NaN, 1, 2] },
    { observations: [1, 2, 3], windowSize: NaN },
  ];
  for (const input of corpus) {
    const result = resolveHighActivityThreshold(input as never);
    assert.ok(Number.isFinite(result.threshold), JSON.stringify(result));
    assert.ok(result.threshold >= 0, JSON.stringify(result));
    assert.ok(result.n >= 0 && Number.isInteger(result.n));
    assert.ok(result.mode === 'fixed_small_corpus' || result.mode === 'adaptive_p98');
  }
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}
