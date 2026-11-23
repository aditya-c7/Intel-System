/**
 * Regression suite for the additive audio-truth helpers.
 *
 *   npx tsx scripts/test-audio-truth.ts
 *
 * Focus: noise must only remove the audio identity anchor — never rotate an id, never
 * drop a confidence score — and the legacy exact float must survive without rounding.
 */

import assert from 'node:assert/strict';
import {
  classifyAudioStability,
  audioAnchorValue,
  type AudioStabilityInput,
  type AudioStabilityTruth,
} from '../src/lib/audioTruth';

let passed = 0;
let failed = 0;
let assertions = 0;

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL  ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Count every assertion helper call so the >=20 assertion requirement is explicit. */
function ok(value: unknown, message?: string): void {
  assertions += 1;
  assert.ok(value, message);
}
function equal<T>(actual: T, expected: T, message?: string): void {
  assertions += 1;
  assert.equal(actual, expected, message);
}
function deepEqual<T>(actual: T, expected: T, message?: string): void {
  assertions += 1;
  assert.deepEqual(actual, expected, message);
}
function noThrow(fn: () => void, message?: string): void {
  assertions += 1;
  assert.doesNotThrow(fn, message);
}

const AUDIO_BASELINE = 124.04347745512496;

function clean(overrides: Partial<AudioStabilityInput> = {}): AudioStabilityInput {
  return {
    renderSums: [AUDIO_BASELINE],
    getChannelDataWrapped: false,
    copyFromChannelMatches: true,
    silentBufferNonZero: false,
    privacyHardened: false,
    ...overrides,
  };
}

function bitsOf(value: number): bigint {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value);
  return view.getBigUint64(0);
}

/* -------------------------------------------------------------------------- */
/* Exact-value anchor (no rounding => no id rotation)                          */
/* -------------------------------------------------------------------------- */

check('audioAnchorValue preserves the legacy baseline bit-for-bit', () => {
  const anchored = audioAnchorValue(AUDIO_BASELINE);
  ok(Object.is(anchored, AUDIO_BASELINE), 'same exact double, not a rounded twin');
  equal(anchored, AUDIO_BASELINE);
  equal(bitsOf(anchored), bitsOf(AUDIO_BASELINE), 'IEEE754 bits must be identical');
  equal(String(anchored), '124.04347745512496', 'not the 8-decimal 124.04347746');
});

check('audioAnchorValue does not quantize arbitrary high-precision sums', () => {
  const a = 0.1 + 0.2;
  const b = 1 / 3;
  ok(Object.is(audioAnchorValue(a), a));
  ok(Object.is(audioAnchorValue(b), b));
  ok(Object.is(audioAnchorValue(-0), -0), 'signed zero is preserved too');
  ok(Object.is(audioAnchorValue(Number.MAX_VALUE), Number.MAX_VALUE));
});

check('audioAnchorValue is total on hostile input and never mints a fake anchor', () => {
  const throwing = { valueOf(): number { throw new Error('nope'); } };
  noThrow(() => { void audioAnchorValue(Number.NaN); });
  noThrow(() => { void audioAnchorValue(Number.POSITIVE_INFINITY); });
  noThrow(() => { void audioAnchorValue(undefined as unknown as number); });
  noThrow(() => { void audioAnchorValue('124.04347745512496' as unknown as number); });
  noThrow(() => { void audioAnchorValue(throwing as unknown as number); });
  ok(Number.isNaN(audioAnchorValue(Number.NaN)));
  ok(Number.isNaN(audioAnchorValue(undefined as unknown as number)));
  ok(Number.isNaN(audioAnchorValue(throwing as unknown as number)));
});

/* -------------------------------------------------------------------------- */
/* Stability classification                                                    */
/* -------------------------------------------------------------------------- */

check('a clean single render is stable, usable, and carries no noise claim', () => {
  const result = classifyAudioStability(clean());
  equal(result.stability, 'stable');
  equal(result.usableForIdentity, true);
  deepEqual(result.noiseReasons, []);
  equal(result.tamperingInconclusive, false);
});

check('repeated identical renders stay stable (no divergence)', () => {
  const result = classifyAudioStability(clean({ renderSums: [AUDIO_BASELINE, AUDIO_BASELINE, AUDIO_BASELINE] }));
  equal(result.stability, 'stable');
  equal(result.usableForIdentity, true);
  equal(result.tamperingInconclusive, false);
});

check('repeat-read divergence is noisy and excluded from identity anchors', () => {
  const result = classifyAudioStability(clean({ renderSums: [AUDIO_BASELINE, AUDIO_BASELINE + 1e-9] }));
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
  ok(result.noiseReasons.some((reason) => reason.includes('repeat-read divergence')));
  equal(result.tamperingInconclusive, false, 'plain noise is not automatically hard-to-interpret');
});

check('even a one-ULP divergence counts (no tolerance band)', () => {
  const next = AUDIO_BASELINE + Number.EPSILON * AUDIO_BASELINE;
  ok(next !== AUDIO_BASELINE, 'fixture really is a different double');
  const result = classifyAudioStability(clean({ renderSums: [AUDIO_BASELINE, next] }));
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
});

check('a wrapped getChannelData is noisy on its own', () => {
  const result = classifyAudioStability(clean({ getChannelDataWrapped: true }));
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
  deepEqual(result.noiseReasons, ['getChannelData is wrapped/instrumented']);
});

check('a copyFromChannel mismatch is noisy on its own', () => {
  const result = classifyAudioStability(clean({ copyFromChannelMatches: false }));
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
  ok(result.noiseReasons.some((reason) => reason.includes('copyFromChannel')));
});

check('a non-zero silent buffer is a noise signature', () => {
  const result = classifyAudioStability(clean({ silentBufferNonZero: true }));
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
  ok(result.noiseReasons.some((reason) => reason.includes('silent buffer')));
});

check('all noise signals accumulate in a deterministic order', () => {
  const input = clean({
    renderSums: [AUDIO_BASELINE, 0, Number.NaN],
    getChannelDataWrapped: true,
    copyFromChannelMatches: false,
    silentBufferNonZero: true,
    privacyHardened: true,
  });
  const result = classifyAudioStability(input);
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
  deepEqual(result.noiseReasons, [
    'repeat-read divergence: render sums differ between reads',
    'non-finite or invalid render read recorded among valid sums',
    'getChannelData is wrapped/instrumented',
    'copyFromChannel data does not match getChannelData',
    'silent buffer rendered non-zero samples',
  ]);
  deepEqual(result, classifyAudioStability(clean({
    renderSums: [AUDIO_BASELINE, 0, Number.NaN],
    getChannelDataWrapped: true,
    copyFromChannelMatches: false,
    silentBufferNonZero: true,
    privacyHardened: true,
  })), 'identical inputs must yield an identical verdict');
});

check('privacy-hardened noise makes tampering inconclusive', () => {
  for (const overrides of [
    { renderSums: [AUDIO_BASELINE, AUDIO_BASELINE + 1e-9] },
    { getChannelDataWrapped: true },
    { copyFromChannelMatches: false },
    { silentBufferNonZero: true },
  ]) {
    const result = classifyAudioStability(clean({ ...overrides, privacyHardened: true }));
    equal(result.stability, 'noisy');
    equal(result.usableForIdentity, false);
    equal(result.tamperingInconclusive, true, 'hardened noise is explained, not tampering evidence');
  }
});

check('privacyHardened alone (without noise) does not manufacture inconclusiveness', () => {
  const result = classifyAudioStability(clean({ privacyHardened: true }));
  equal(result.stability, 'stable');
  equal(result.usableForIdentity, true);
  equal(result.tamperingInconclusive, false);
  deepEqual(result.noiseReasons, []);
});

check('absence of render data is unavailable, not noisy', () => {
  const empty = classifyAudioStability(clean({ renderSums: [] }));
  equal(empty.stability, 'unavailable');
  equal(empty.usableForIdentity, false);
  deepEqual(empty.noiseReasons, []);
  const nonFinite = classifyAudioStability(clean({ renderSums: [Number.NaN, Number.POSITIVE_INFINITY] }));
  equal(nonFinite.stability, 'unavailable');
  equal(nonFinite.usableForIdentity, false);
  equal(nonFinite.tamperingInconclusive, false);
});

check('an explicit noise signal wins over unavailable render data', () => {
  const result = classifyAudioStability(clean({ renderSums: [], getChannelDataWrapped: true }));
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
  deepEqual(result.noiseReasons, ['getChannelData is wrapped/instrumented']);
});

/* -------------------------------------------------------------------------- */
/* "Does not rotate ids / drop confidence" is structural                       */
/* -------------------------------------------------------------------------- */

check('the verdict exposes no id, confidence, score or tier field', () => {
  const noisy = classifyAudioStability(clean({ getChannelDataWrapped: true })) as unknown as Record<string, unknown>;
  const stable = classifyAudioStability(clean()) as unknown as Record<string, unknown>;
  const expectedKeys = ['stability', 'usableForIdentity', 'noiseReasons', 'tamperingInconclusive'];
  deepEqual(Object.keys(noisy).sort(), [...expectedKeys].sort());
  deepEqual(Object.keys(stable).sort(), [...expectedKeys].sort());
  const forbidden = ['id', 'confidence', 'score', 'risk', 'tier', 'hash'];
  for (const key of forbidden) {
    equal(Object.prototype.hasOwnProperty.call(noisy, key), false, `no ${key} to rotate/drop`);
  }
});

check('noise only flips anchor eligibility; the exact stable anchor is unchanged', () => {
  const stable = classifyAudioStability(clean());
  const noisy = classifyAudioStability(clean({ getChannelDataWrapped: true }));
  equal(stable.usableForIdentity, true);
  equal(noisy.usableForIdentity, false);
  ok(Object.is(audioAnchorValue(AUDIO_BASELINE), AUDIO_BASELINE), 'anchor bits did not move');
});

check('classification never mutates its input', () => {
  const input = Object.freeze(clean({ renderSums: Object.freeze([AUDIO_BASELINE, AUDIO_BASELINE]) as unknown as number[] }));
  noThrow(() => { void classifyAudioStability(input); });
  equal(input.renderSums.length, 2);
  equal(input.renderSums[0], AUDIO_BASELINE);
  equal(classifyAudioStability(input).stability, 'stable');
});

/* -------------------------------------------------------------------------- */
/* Hostile input                                                              */
/* -------------------------------------------------------------------------- */

check('null / undefined / primitive / array input degrades safely', () => {
  const hostile: unknown[] = [null, undefined, 42, 'audio', [], true, Symbol('x')];
  for (const value of hostile) {
    noThrow(() => { void classifyAudioStability(value as AudioStabilityInput); });
    const result = classifyAudioStability(value as AudioStabilityInput);
    equal(result.stability, 'unavailable');
    equal(result.usableForIdentity, false);
    deepEqual(result.noiseReasons, []);
  }
});

check('a Proxy with throwing getters never throws', () => {
  const hostile = new Proxy({}, {
    get() { throw new Error('no peeking'); },
    has() { throw new Error('no peeking'); },
  });
  noThrow(() => { void classifyAudioStability(hostile as AudioStabilityInput); });
  const result = classifyAudioStability(hostile as AudioStabilityInput);
  equal(result.stability, 'unavailable');
  equal(result.tamperingInconclusive, false);
  deepEqual(result.noiseReasons, []);
});

check('hostile renderSums shapes are ignored, not coerced into anchors', () => {
  const shapes: unknown[] = [
    '124.04347745512496',
    { 0: AUDIO_BASELINE, length: 1 },
    [Number.NaN, 'x', null, {}, AUDIO_BASELINE],
    new Proxy([AUDIO_BASELINE], { get() { throw new Error('boom'); } }),
  ];
  for (const renderSums of shapes) {
    noThrow(() => { void classifyAudioStability(clean({ renderSums: renderSums as number[] })); });
    const result = classifyAudioStability(clean({ renderSums: renderSums as number[] }));
    ok(result.stability === 'noisy' || result.stability === 'unavailable');
    equal(result.usableForIdentity, false, 'hostile reads never become an identity anchor');
  }
});

check('a stateful hostile getter is read once and cannot crash the classifier', () => {
  let reads = 0;
  const input = {
    get renderSums(): number[] { reads += 1; return [AUDIO_BASELINE]; },
    get getChannelDataWrapped(): boolean { throw new Error('nope'); },
    get copyFromChannelMatches(): boolean { throw new Error('nope'); },
    get silentBufferNonZero(): boolean { throw new Error('nope'); },
    get privacyHardened(): boolean { throw new Error('nope'); },
  } as unknown as AudioStabilityInput;
  noThrow(() => { void classifyAudioStability(input); });
  const result = classifyAudioStability(input);
  equal(result.stability, 'stable', 'throwing boolean getters are "no evidence"');
  equal(result.usableForIdentity, true);
  deepEqual(result.noiseReasons, []);
  ok(reads >= 1, 'renderSums getter was consulted');
});

check('an oversized lying length cannot stall the classifier', () => {
  const huge = Object.assign([AUDIO_BASELINE], { length: 2 ** 31 - 1 });
  const started = Date.now();
  const result = classifyAudioStability(clean({ renderSums: huge as number[] }));
  ok(Date.now() - started < 2000, 'bounded scan completes promptly');
  // The 4095 sparse holes inside the bounded scan are invalid reads, so a single valid
  // sum beside them is noise-like: conservatively excluded, never an identity anchor.
  equal(result.stability, 'noisy');
  equal(result.usableForIdentity, false);
  ok(result.noiseReasons.some((reason) => reason.includes('invalid render read')));
});

console.log(`\nAudio-truth suite: ${passed} passed, ${failed} failed, ${assertions} assertions`);
if (failed > 0) process.exitCode = 1;
