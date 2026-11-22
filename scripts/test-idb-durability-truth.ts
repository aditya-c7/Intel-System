import assert from 'node:assert/strict';
import {
  resolveIdbDurabilityTruth,
  STRONG_RAM_RATIO_MAX,
  IDB_PRIVATE_RATIO_MAX,
  IDB_NORMAL_RATIO_MIN,
} from '../src/lib/idbDurabilityTruth';

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed++;
    console.log(`FAIL  ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

check('constants preserve the original deadband and add the strong-RAM boundary', () => {
  assert.equal(STRONG_RAM_RATIO_MAX, 1.4);
  assert.equal(IDB_PRIVATE_RATIO_MAX, 1.12);
  assert.equal(IDB_NORMAL_RATIO_MIN, 1.6);
});

// Live-captured samples from 2026-11-22 (headless Chromium 156).
const LIVE_INCOGNITO = [
  { ratio: 0.531, highVariance: false },
  { ratio: 0.88, highVariance: true },
  { ratio: 1.067, highVariance: true },
  { ratio: 1.183, highVariance: true },
];
const LIVE_NORMAL = [
  { ratio: 2.701, highVariance: true },
  { ratio: 6.087, highVariance: true },
  { ratio: 6.631, highVariance: true },
  { ratio: 7.464, highVariance: true },
];

check('live incognito samples are all classified as off-the-record', () => {
  for (const sample of LIVE_INCOGNITO) {
    const result = resolveIdbDurabilityTruth(sample);
    assert.equal(result.incognito, true, `ratio ${sample.ratio} must be incognito`);
    assert.equal(result.confidence, 'high');
    assert.equal(result.rule, 'strong_ram_signature');
  }
});

check('live normal samples are all disk-backed high-confidence normals', () => {
  for (const sample of LIVE_NORMAL) {
    const result = resolveIdbDurabilityTruth(sample);
    assert.equal(result.incognito, false);
    assert.equal(result.confidence, 'high');
    assert.equal(result.rule, 'disk_backed');
  }
});

check('strong RAM signature stands alone without OPFS corroboration', () => {
  const result = resolveIdbDurabilityTruth({ ratio: 0.531, highVariance: false });
  assert.equal(result.incognito, true);
  assert.equal(result.confidence, 'high');
});

check('strong RAM signature is accepted even when the trimmed spread is wide', () => {
  const result = resolveIdbDurabilityTruth({ ratio: 0.88, highVariance: true });
  assert.equal(result.incognito, true);
  assert.equal(result.rule, 'strong_ram_signature');
});

check('1.40-1.60 deadband fails open, never incognito', () => {
  for (const ratio of [1.41, 1.5, 1.6]) {
    const result = resolveIdbDurabilityTruth({ ratio, highVariance: true });
    assert.equal(result.incognito, false, `ratio ${ratio} must fail open`);
    assert.equal(result.confidence, 'low');
    assert.equal(result.rule, 'deadband');
  }
});

check('low ratios remain strong private with or without OPFS corroboration', () => {
  for (const ratio of [1.0, 1.2]) {
    const naked = resolveIdbDurabilityTruth({ ratio, highVariance: false });
    assert.equal(naked.incognito, true);
    assert.equal(naked.rule, 'strong_ram_signature');
    const corroborated = resolveIdbDurabilityTruth({
      ratio,
      highVariance: false,
      opfsCorroboration: true,
    });
    assert.equal(corroborated.incognito, true);
  }
});

check('persistent-storage grant veto cannot be overridden by a strong ratio', () => {
  const result = resolveIdbDurabilityTruth({ ratio: 0.4, persistedGrant: true });
  assert.equal(result.incognito, false);
  assert.equal(result.rule, 'vetoed');
});

check('isolated storage context veto cannot be overridden by a strong ratio', () => {
  const result = resolveIdbDurabilityTruth({ ratio: 0.4, isolatedContext: true });
  assert.equal(result.incognito, false);
  assert.equal(result.rule, 'vetoed');
});

check('inconclusive / malformed ratios never become incognito', () => {
  for (const ratio of [null, undefined, NaN, Infinity, -1, 0, '0.5' as unknown as number]) {
    const result = resolveIdbDurabilityTruth({ ratio });
    assert.equal(result.incognito, false);
    assert.equal(result.confidence, 'low');
  }
});

check('hostile getters never throw', () => {
  const hostile = new Proxy({}, {
    get() {
      throw new Error('nope');
    },
  });
  assert.doesNotThrow(() => resolveIdbDurabilityTruth(hostile));
});

check('null / primitive input degrades safely', () => {
  assert.doesNotThrow(() => resolveIdbDurabilityTruth(null as unknown as object));
  assert.doesNotThrow(() => resolveIdbDurabilityTruth(42 as unknown as object));
});

console.log(`\nRESULT: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
